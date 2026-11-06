//! Checked page budget for an embedded rootserver ELF and its boot mappings.

const PAGE_SIZE: u64 = 4096;
const MIB: u64 = 1024 * 1024;
const MIN_USER_REGION_BYTES: u64 = 16 * MIB;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadSpan {
    pub vaddr: u64,
    pub mem_size: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageBudgetError {
    Overflow,
    TableCapacity { needed: u64, capacity: u64 },
}

fn pages(span: LoadSpan) -> Result<(u64, u64), PageBudgetError> {
    if span.mem_size == 0 {
        let page = span.vaddr / PAGE_SIZE;
        return Ok((page, page));
    }
    let end = span.vaddr.checked_add(span.mem_size).ok_or(PageBudgetError::Overflow)?;
    let rounded_end = end.checked_add(PAGE_SIZE - 1).ok_or(PageBudgetError::Overflow)?;
    let end_page = rounded_end / PAGE_SIZE;
    Ok((span.vaddr / PAGE_SIZE, end_page))
}

/// Count distinct PT_LOAD pages plus mapped stack/aux pages before allocating any boot page.
/// Each page is checked against earlier segments so overlapping headers do not inflate the
/// publication table. The capacity check bounds work even for a malformed huge mem_size.
pub fn budget<I: Iterator<Item = LoadSpan> + Clone>(
    spans: I,
    stack_pages: u64,
    aux_pages: u64,
    table_capacity: u64,
) -> Result<u64, PageBudgetError> {
    let aux = stack_pages.checked_add(aux_pages).ok_or(PageBudgetError::Overflow)?;
    if aux > table_capacity {
        return Err(PageBudgetError::TableCapacity { needed: aux, capacity: table_capacity });
    }
    let mut image_pages = 0u64;
    for (index, span) in spans.clone().enumerate() {
        let (first, end) = pages(span)?;
        for page in first..end {
            let mut seen = false;
            for prior in spans.clone().take(index) {
                let (prior_first, prior_end) = pages(prior)?;
                if page >= prior_first && page < prior_end {
                    seen = true;
                    break;
                }
            }
            if !seen {
                image_pages = image_pages.checked_add(1).ok_or(PageBudgetError::Overflow)?;
                let needed = image_pages.checked_add(aux).ok_or(PageBudgetError::Overflow)?;
                if needed > table_capacity {
                    return Err(PageBudgetError::TableCapacity {
                        needed,
                        capacity: table_capacity,
                    });
                }
            }
        }
    }
    image_pages.checked_add(aux).ok_or(PageBudgetError::Overflow)
}

/// Keep the carve clear of the low rootserver placement while scaling with the live image.
/// Extra physical pages account for architecture page tables that are not image-frame entries.
pub fn reserve_bytes(mapped_pages: u64, extra_physical_pages: u64)
    -> Result<u64, PageBudgetError> {
    let pages = mapped_pages.checked_add(extra_physical_pages)
        .ok_or(PageBudgetError::Overflow)?;
    let bytes = pages.checked_mul(PAGE_SIZE).ok_or(PageBudgetError::Overflow)?;
    let needed = bytes.max(MIN_USER_REGION_BYTES);
    needed.checked_add(MIB - 1).map(|rounded| rounded & !(MIB - 1))
        .ok_or(PageBudgetError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::{budget, reserve_bytes, LoadSpan, PageBudgetError};

    #[test]
    fn current_executive_image_exceeds_the_old_fixed_page_limits() {
        let image = [LoadSpan { vaddr: 0x1000, mem_size: 3973 * 4096 }];
        assert_eq!(budget(image.iter().copied(), 128, 3, 8192).unwrap(), 4104);
        assert_eq!(
            budget(image.iter().copied(), 128, 3, 4096),
            Err(PageBudgetError::TableCapacity { needed: 4097, capacity: 4096 }),
        );
    }

    #[test]
    fn unaligned_and_overlapping_segments_count_each_page_once() {
        let image = [
            LoadSpan { vaddr: 0x1001, mem_size: 8192 },
            LoadSpan { vaddr: 0x2000, mem_size: 4096 },
            LoadSpan { vaddr: 0x5000, mem_size: 0 },
        ];
        assert_eq!(budget(image.iter().copied(), 2, 3, 16).unwrap(), 8);
    }

    #[test]
    fn arithmetic_overflow_and_capacity_refuse_before_allocation() {
        let overflow = [LoadSpan { vaddr: u64::MAX - 1, mem_size: 8 }];
        assert_eq!(budget(overflow.iter().copied(), 0, 0, 8192), Err(PageBudgetError::Overflow));
        let rounding_overflow = [LoadSpan { vaddr: u64::MAX - 1, mem_size: 1 }];
        assert_eq!(budget(rounding_overflow.iter().copied(), 0, 0, 8192), Err(PageBudgetError::Overflow));
        let small = [LoadSpan { vaddr: 0, mem_size: 4096 }];
        assert_eq!(budget(small.iter().copied(), u64::MAX, 3, 8192), Err(PageBudgetError::Overflow));
    }

    #[test]
    fn physical_reserve_rounds_up_from_live_pages_and_checks_overflow() {
        assert_eq!(reserve_bytes(4104, 0).unwrap(), 17 * 1024 * 1024);
        assert_eq!(reserve_bytes(1, 0).unwrap(), 16 * 1024 * 1024);
        assert_eq!(reserve_bytes(u64::MAX, 1), Err(PageBudgetError::Overflow));
    }
}

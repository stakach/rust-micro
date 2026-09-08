//! Checked user mappings and bootstrap page-table construction.

use core::arch::asm;
use super::paging::{kernel_virt_to_phys, read_cr3, PTE_PRESENT, PTE_RW, PTE_USER};

#[cfg(feature = "spec")]
#[path = "usermode_ping_spec.rs"]
mod ping_spec;
#[cfg(feature = "spec")]
pub use ping_spec::launch_smp_ping_thread;
#[cfg(all(feature = "spec", target_arch = "x86_64"))]
pub(crate) use ping_spec::{PING_REGISTER_SENTINEL, PING_SYSCALL_PC};

/// Seed the real current-root hierarchy for legacy invocation fixtures. Public Frame::Map
/// never allocates intermediate tables; only kernel bootstrap and fixture setup may do that.
#[cfg(feature = "spec")]
pub unsafe fn map_user_4k_public(vaddr: u64, paddr: u64, writable: bool, execute_never: bool) {
    let pml4 = super::paging::phys_to_lin(read_cr3() & 0x000F_FFFF_FFFF_F000) as *mut u64;
    map_user_4k_in(pml4, vaddr, paddr, writable, execute_never);
}

/// Phase 28g — clear the 4 KiB PTE for `vaddr` in the live PML4
/// and `invlpg` it on the calling CPU. The caller is responsible
/// for fanning a TLB-shootdown IPI to other CPUs that may have
/// the mapping cached.
///
/// Walks the page tables; if any intermediate level is missing or
/// uses a 1G/2M page, leaves the structure alone (the cap-state
/// invariant says we only Unmap pages that Frame::Map installed
/// at 4 KiB granularity, but we're defensive).
#[cfg(feature = "spec")]
pub unsafe fn unmap_user_4k_public(vaddr: u64, expected_paddr: u64) -> bool {
    let pml4_paddr = read_cr3() & 0x000F_FFFF_FFFF_F000;
    unmap_user_4k_in_pml4(pml4_paddr, vaddr, expected_paddr)
}

/// Phase 43 — unmap a 4 KiB page from a SPECIFIC vspace (identified
/// by its PML4 paddr). Used by Frame::Unmap so the kernel walks the
/// vspace the cap was mapped in, not whatever happens to be current.
pub unsafe fn unmap_user_4k_in_pml4(pml4_paddr: u64, vaddr: u64, expected_paddr: u64) -> bool {
    use super::paging::{PTE_PRESENT, PTE_PS};
    let pml4 = super::paging::phys_to_lin(pml4_paddr & 0x000F_FFFF_FFFF_F000) as *mut u64;
    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let pt_idx = ((vaddr >> 12) & 0x1FF) as usize;

    let pml4e = core::ptr::read_volatile(pml4.add(pml4_idx));
    if pml4e & PTE_PRESENT == 0 || pml4e & PTE_PS != 0 {
        return false;
    }
    let pdpt = super::paging::phys_to_lin(pml4e & 0x000F_FFFF_FFFF_F000) as *mut u64;
    let pdpte = core::ptr::read_volatile(pdpt.add(pdpt_idx));
    if pdpte & PTE_PRESENT == 0 || pdpte & PTE_PS != 0 {
        return false;
    }
    let pd = super::paging::phys_to_lin(pdpte & 0x000F_FFFF_FFFF_F000) as *mut u64;
    let pde = core::ptr::read_volatile(pd.add(pd_idx));
    if pde & PTE_PRESENT == 0 || pde & PTE_PS != 0 {
        return false;
    }
    let pt = super::paging::phys_to_lin(pde & 0x000F_FFFF_FFFF_F000) as *mut u64;
    let pte = core::ptr::read_volatile(pt.add(pt_idx));
    // At the 4 KiB leaf, bit 7 is PAT rather than the large-page flag.
    if pte & PTE_PRESENT == 0
        || pte & 0x000F_FFFF_FFFF_F000 != expected_paddr & 0x000F_FFFF_FFFF_F000
    {
        return false;
    }

    core::ptr::write_volatile(pt.add(pt_idx), 0);
    asm!("invlpg [{a}]", a = in(reg) vaddr, options(nostack, preserves_flags));
    true
}

/// Phase 24 — install a 4 KiB mapping into an explicit PML4
/// (used at thread-spawn time before we've switched CR3 to it).
pub unsafe fn map_user_4k_into_pml4(
    pml4_paddr: u64,
    vaddr: u64,
    paddr: u64,
    writable: bool,
    execute_never: bool,
) {
    let pml4 = super::paging::phys_to_lin(pml4_paddr & 0x000F_FFFF_FFFF_F000) as *mut u64;
    map_user_4k_in(pml4, vaddr, paddr, writable, execute_never);
}

unsafe fn map_user_4k_in(
    pml4: *mut u64,
    vaddr: u64,
    paddr: u64,
    writable: bool,
    execute_never: bool,
) {
    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let pt_idx = ((vaddr >> 12) & 0x1FF) as usize;

    let mid_flags = PTE_PRESENT | PTE_RW | PTE_USER;
    let leaf_flags = PTE_PRESENT
        | PTE_USER
        | if writable { PTE_RW } else { 0 }
        | if execute_never {
            super::paging::PTE_NX
        } else {
            0
        };

    let pdpt = ensure_user_table(pml4.add(pml4_idx), mid_flags);
    let pd = ensure_user_table(pdpt.add(pdpt_idx), mid_flags);
    let pt = ensure_user_table(pd.add(pd_idx), mid_flags);

    core::ptr::write_volatile(pt.add(pt_idx), (paddr & !0xFFF) | leaf_flags);
    asm!("invlpg [{a}]", a = in(reg) vaddr, options(nostack, preserves_flags));
}

unsafe fn ensure_user_table(entry_ptr: *mut u64, flags: u64) -> *mut u64 {
    use super::paging::{PTE_PRESENT, PTE_PS};
    let entry = core::ptr::read_volatile(entry_ptr);
    if entry & PTE_PRESENT != 0 {
        if entry & PTE_PS != 0 {
            // 2 MiB large page (PD slot with PS=1). Split it into a
            // PT of 512 4 KiB entries so the rootserver can mutate
            // sub-pages without disturbing the rest of the 2 MiB
            // region — early boot maps the lower memory at PML4[0]
            // with 2 MiB pages, and rootservers laying out
            // in PML4[0] (e.g. sel4test-driver at 0x400000) need
            // 4 KiB granularity in those regions.
            let large_paddr = entry & 0x000F_FFFF_FFE0_0000;
            // Carry the entry's low flag bits, dropping PS. PAT
            // moves between bit positions for 2 MiB vs 4 KiB
            // entries, but the early identity entries don't set
            // PAT — masking PS is sufficient here.
            let leaf_flags = (entry & 0xFFF) & !PTE_PS;
            let pt_v = super::paging::alloc_user_table_va();
            for i in 0..512 {
                let leaf = (large_paddr + (i as u64) * 0x1000) | leaf_flags;
                core::ptr::write_volatile(pt_v.add(i), leaf);
            }
            let pt_p = kernel_virt_to_phys(pt_v as u64);
            // Replace the PD entry with a pointer at the new PT
            // (PS=0). The requested mid-flags (PRESENT|RW|USER)
            // overwrite the original — note that user-mode access
            // also requires US=1 in the leaf PT entries, so the
            // 511 leaves still mapping the early identity range remain
            // kernel-only (their leaf_flags inherited PS=0/US=0).
            // Only the leaf the rootserver later overwrites with
            // its own US=1 entry becomes user-accessible.
            let new_pd = (pt_p & 0x000F_FFFF_FFFF_F000) | flags;
            core::ptr::write_volatile(entry_ptr, new_pd);
            // Return the kernel-virtual address of the new PT we
            // just allocated — pt_v is already kernel-virt.
            return pt_v;
        }
        let updated = entry | flags;
        if updated != entry {
            core::ptr::write_volatile(entry_ptr, updated);
        }
        return super::paging::phys_to_lin(entry & 0x000F_FFFF_FFFF_F000) as *mut u64;
    }
    let table_v = super::paging::alloc_user_table_va();
    let table_p = kernel_virt_to_phys(table_v as u64);
    core::ptr::write_volatile(entry_ptr, (table_p & !0xFFF) | flags);
    table_v
}

/// Phase 26 — install an intermediate paging structure into the
/// invoker's vspace (i.e. the live CR3 PML4). `level` selects the
/// parent table the entry is written into:
///   * `level=3` → PML4 entry at index `vaddr >> 39`. Used to map a
///     `Cap::Pdpt` into a vspace.
///   * `level=2` → PDPT entry at index `vaddr >> 30`. Used to map a
///     `Cap::PageDirectory`. Walks PML4 to find the PDPT.
///   * `level=1` → PD entry at index `vaddr >> 21`. Used to map a
///     `Cap::PageTable`. Walks PML4 → PDPT to find the PD.
///
/// Returns false if a parent entry is missing (caller should map
/// the higher-level structure first) or if the target entry is
/// already present (caller should Unmap first).
/// SAFETY: `pml4_paddr` must be a valid PML4 paddr and the
/// rootserver pool memory must be reachable through the kernel's
/// linear map.
pub unsafe fn install_user_table_in_paddr(
    pml4_paddr: u64,
    level: u32,
    vaddr: u64,
    table_paddr: u64,
    attributes: u64,
) -> Result<(), u32> {
    // Use the kernel linear map for the physical PML4 page.
    let pml4 = super::paging::phys_to_lin(pml4_paddr & 0x000F_FFFF_FFFF_F000) as *mut u64;
    install_user_table_in(pml4, level, vaddr, table_paddr, attributes)
}

pub fn current_pml4_paddr() -> u64 {
    read_cr3() & 0x000F_FFFF_FFFF_F000
}

/// Remove an intermediate paging structure only when the parent entry still
/// names the capability's physical page. A stale paging cap must not detach a
/// replacement table that now covers the same virtual range.
unsafe fn user_table_entry_in_paddr(pml4_paddr: u64, level: u32, vaddr: u64) -> Option<*mut u64> {
    use super::paging::{PTE_PRESENT, PTE_PS};
    let pml4 = super::paging::phys_to_lin(pml4_paddr & 0x000F_FFFF_FFFF_F000) as *mut u64;
    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;

    let entry = match level {
        3 => pml4.add(pml4_idx),
        2 => {
            let pml4e = core::ptr::read_volatile(pml4.add(pml4_idx));
            if pml4e & PTE_PRESENT == 0 || pml4e & PTE_PS != 0 {
                return None;
            }
            let pdpt = super::paging::phys_to_lin(pml4e & 0x000F_FFFF_FFFF_F000) as *mut u64;
            pdpt.add(pdpt_idx)
        }
        1 => {
            let pml4e = core::ptr::read_volatile(pml4.add(pml4_idx));
            if pml4e & PTE_PRESENT == 0 || pml4e & PTE_PS != 0 {
                return None;
            }
            let pdpt = super::paging::phys_to_lin(pml4e & 0x000F_FFFF_FFFF_F000) as *mut u64;
            let pdpte = core::ptr::read_volatile(pdpt.add(pdpt_idx));
            if pdpte & PTE_PRESENT == 0 || pdpte & PTE_PS != 0 {
                return None;
            }
            let pd = super::paging::phys_to_lin(pdpte & 0x000F_FFFF_FFFF_F000) as *mut u64;
            pd.add(pd_idx)
        }
        _ => return None,
    };
    Some(entry)
}

pub unsafe fn user_table_matches_in_paddr(
    pml4_paddr: u64,
    level: u32,
    vaddr: u64,
    expected_paddr: u64,
) -> bool {
    let Some(entry) = user_table_entry_in_paddr(pml4_paddr, level, vaddr) else {
        return false;
    };
    let current = core::ptr::read_volatile(entry);
    current & super::paging::PTE_PRESENT != 0
        && current & super::paging::PTE_PS == 0
        && current & 0x000F_FFFF_FFFF_F000 == expected_paddr & 0x000F_FFFF_FFFF_F000
}

pub unsafe fn unmap_user_table_in_paddr(
    pml4_paddr: u64,
    level: u32,
    vaddr: u64,
    expected_paddr: u64,
) -> bool {
    if !user_table_matches_in_paddr(pml4_paddr, level, vaddr, expected_paddr) {
        return false;
    }
    let entry = user_table_entry_in_paddr(pml4_paddr, level, vaddr).unwrap();
    core::ptr::write_volatile(entry, 0);
    true
}


/// Install or replace a same-size user leaf after invocation authority checks. Intermediate
/// tables must already exist. Errors 1/2/3 identify a missing parent; 4 means replacing a
/// lower-level subtree would be required. Replacing an existing same-size leaf is permitted.
pub unsafe fn map_user_frame_in_pml4(
    pml4_paddr: u64,
    vaddr: u64,
    frame_paddr: u64,
    size: crate::cap::FrameSize,
    rights: crate::cap::FrameRights,
    attributes: super::vspace::FrameMappingAttributes,
) -> Result<(), u32> {
    use super::paging::PTE_PS;
    use crate::cap::FrameSize;
    let bits = match size {
        FrameSize::Small => 12,
        FrameSize::Large => 21,
        FrameSize::Huge => 30,
    };
    let entry = super::vspace::frame_mapping_entry(frame_paddr, bits, rights, attributes)
        .expect("frame size has an x86 leaf encoding");
    let pml4 = super::paging::phys_to_lin(pml4_paddr & 0x000F_FFFF_FFFF_F000) as *mut u64;
    let indices = super::vspace::decompose_vaddr(vaddr);
    let pml4e = core::ptr::read_volatile(pml4.add(indices.pml4 as usize));
    if pml4e & PTE_PRESENT == 0 || pml4e & PTE_PS != 0 {
        return Err(1);
    }
    let pdpt = super::paging::phys_to_lin(pml4e & 0x000F_FFFF_FFFF_F000) as *mut u64;
    let pdpte_slot = pdpt.add(indices.pdpt as usize);
    let pdpte = core::ptr::read_volatile(pdpte_slot);
    let leaf = if size == FrameSize::Huge {
        if pdpte & PTE_PRESENT != 0 && pdpte & PTE_PS == 0 {
            return Err(4);
        }
        pdpte_slot
    } else {
        if pdpte & PTE_PRESENT == 0 || pdpte & PTE_PS != 0 {
            return Err(2);
        }
        let pd = super::paging::phys_to_lin(pdpte & 0x000F_FFFF_FFFF_F000) as *mut u64;
        let pde_slot = pd.add(indices.pd as usize);
        let pde = core::ptr::read_volatile(pde_slot);
        if size == FrameSize::Large {
            if pde & PTE_PRESENT != 0 && pde & PTE_PS == 0 {
                return Err(4);
            }
            pde_slot
        } else {
            if pde & PTE_PRESENT == 0 || pde & PTE_PS != 0 {
                return Err(3);
            }
            let pt = super::paging::phys_to_lin(pde & 0x000F_FFFF_FFFF_F000) as *mut u64;
            pt.add(indices.pt as usize)
        }
    };
    core::ptr::write_volatile(leaf, entry);
    Ok(())
}

/// Unmap a 2 MiB Large frame from a specific vspace. Bails if the
/// PD entry isn't actually a 2 MiB leaf.
pub unsafe fn unmap_user_2m_in_pml4(pml4_paddr: u64, vaddr: u64, expected_paddr: u64) -> bool {
    use super::paging::{PTE_PRESENT, PTE_PS};
    let pml4 = super::paging::phys_to_lin(pml4_paddr & 0x000F_FFFF_FFFF_F000) as *mut u64;
    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;

    let pml4e = core::ptr::read_volatile(pml4.add(pml4_idx));
    if pml4e & PTE_PRESENT == 0 || pml4e & PTE_PS != 0 {
        return false;
    }
    let pdpt = super::paging::phys_to_lin(pml4e & 0x000F_FFFF_FFFF_F000) as *mut u64;
    let pdpte = core::ptr::read_volatile(pdpt.add(pdpt_idx));
    if pdpte & PTE_PRESENT == 0 || pdpte & PTE_PS != 0 {
        return false;
    }
    let pd = super::paging::phys_to_lin(pdpte & 0x000F_FFFF_FFFF_F000) as *mut u64;
    let pde = core::ptr::read_volatile(pd.add(pd_idx));
    if pde & PTE_PRESENT == 0 || pde & PTE_PS == 0 {
        // Not a 2 MiB leaf — nothing to do.
        return false;
    }
    if pde & 0x000F_FFFF_FFE0_0000 != expected_paddr & 0x000F_FFFF_FFE0_0000 {
        return false;
    }
    core::ptr::write_volatile(pd.add(pd_idx), 0);
    asm!("invlpg [{a}]", a = in(reg) vaddr, options(nostack, preserves_flags));
    true
}

/// Unmap a 1 GiB Huge frame from a specific vspace.
pub unsafe fn unmap_user_1g_in_pml4(pml4_paddr: u64, vaddr: u64, expected_paddr: u64) -> bool {
    use super::paging::{PTE_PRESENT, PTE_PS};
    let pml4 = super::paging::phys_to_lin(pml4_paddr & 0x000F_FFFF_FFFF_F000) as *mut u64;
    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pml4e = core::ptr::read_volatile(pml4.add(pml4_idx));
    if pml4e & PTE_PRESENT == 0 || pml4e & PTE_PS != 0 {
        return false;
    }
    let pdpt = super::paging::phys_to_lin(pml4e & 0x000F_FFFF_FFFF_F000) as *mut u64;
    let pdpte = core::ptr::read_volatile(pdpt.add(pdpt_idx));
    if pdpte & PTE_PRESENT == 0 || pdpte & PTE_PS == 0 {
        // Not a 1 GiB leaf — nothing to do.
        return false;
    }
    if pdpte & 0x000F_FFFF_C000_0000 != expected_paddr & 0x000F_FFFF_C000_0000 {
        return false;
    }
    core::ptr::write_volatile(pdpt.add(pdpt_idx), 0);
    asm!("invlpg [{a}]", a = in(reg) vaddr, options(nostack, preserves_flags));
    true
}

/// Install a paging-structure entry. Returns Ok(()) on success.
/// On Err, the value is the seL4_MappingFailedLookupLevel value
/// (21=PT, 30=PD, 39=PDPT) — i.e. the bit-position of the *missing*
/// parent entry, so callers can populate the FailedLookup mr2.
/// Returns 0 on "slot already present" (caller surfaces as
/// DeleteFirst).
unsafe fn install_user_table_in(
    pml4: *mut u64,
    level: u32,
    vaddr: u64,
    table_paddr: u64,
    attributes: u64,
) -> Result<(), u32> {
    use super::paging::PTE_PS;
    // Paging structures honor PWT and PCD; PAT is a leaf attribute, not a table flag.
    let flags = PTE_PRESENT | PTE_RW | PTE_USER | ((attributes & 3) << 3);
    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;

    let entry_ptr: *mut u64 = match level {
        3 => pml4.add(pml4_idx),
        2 => {
            let e = core::ptr::read_volatile(pml4.add(pml4_idx));
            if e & PTE_PRESENT == 0 || e & PTE_PS != 0 {
                return Err(39); // need PDPT (= PML4 missing)
            }
            (super::paging::phys_to_lin(e & 0x000F_FFFF_FFFF_F000) as *mut u64).add(pdpt_idx)
        }
        1 => {
            let pml4e = core::ptr::read_volatile(pml4.add(pml4_idx));
            if pml4e & PTE_PRESENT == 0 || pml4e & PTE_PS != 0 {
                return Err(39); // need PDPT (PML4 entry missing)
            }
            let pdpt = super::paging::phys_to_lin(pml4e & 0x000F_FFFF_FFFF_F000) as *mut u64;
            let pdpte = core::ptr::read_volatile(pdpt.add(pdpt_idx));
            if pdpte & PTE_PRESENT == 0 || pdpte & PTE_PS != 0 {
                return Err(30); // need PD (PDPT entry missing)
            }
            (super::paging::phys_to_lin(pdpte & 0x000F_FFFF_FFFF_F000) as *mut u64).add(pd_idx)
        }
        _ => return Err(0),
    };

    let cur = core::ptr::read_volatile(entry_ptr);
    if cur & PTE_PRESENT != 0 {
        return Err(0); // already present — caller maps to DeleteFirst
    }
    core::ptr::write_volatile(entry_ptr, (table_paddr & !0xFFF) | flags);
    Ok(())
}

//! Validated device scopes for one ACPI DMAR hardware unit.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmarUnit {
    pub base: u64,
    pub include_all: bool,
    pub scopes_paddr: u64,
    pub scopes_len: usize,
}

impl DmarUnit {
    pub fn scopes_valid(self) -> bool {
        let scopes = unsafe {
            core::slice::from_raw_parts(self.scopes_paddr as *const u8, self.scopes_len)
        };
        visit_endpoint_scopes(scopes, |_| {}).is_some()
    }

    /// Copy exact PCI endpoint authority into kernel-owned storage before
    /// user vspaces drop the loader's low-memory identity mapping.
    pub fn populate_allowed_rids(self, allowed: &mut [u64; 1024]) -> bool {
        let scopes = unsafe {
            core::slice::from_raw_parts(self.scopes_paddr as *const u8, self.scopes_len)
        };
        allowed.fill(0);
        visit_endpoint_scopes(scopes, |rid| {
            allowed[(rid as usize) >> 6] |= 1u64 << (rid & 63);
        }).is_some()
    }
}

/// Return `None` for a malformed scope list, `Some(true)` only when an
/// endpoint scope names this exact PCI requester ID. Bridge scopes are valid
/// firmware descriptions but do not authorize downstream requester IDs until
/// the PCI bridge topology is resolved by a dedicated owner.
pub fn endpoint_scope_covers_rid(scopes: &[u8], rid: u16) -> Option<bool> {
    let mut matched = false;
    visit_endpoint_scopes(scopes, |scoped_rid| matched |= scoped_rid == rid)?;
    Some(matched)
}

fn visit_endpoint_scopes(scopes: &[u8], mut endpoint: impl FnMut(u16)) -> Option<()> {
    let mut offset = 0usize;
    while offset < scopes.len() {
        if scopes.len() - offset < 6 {
            return None;
        }
        let scope_type = scopes[offset];
        let len = scopes[offset + 1] as usize;
        if len < 8 || len > scopes.len() - offset || (len - 6) % 2 != 0 {
            return None;
        }
        let path_count = (len - 6) / 2;
        let start_bus = scopes[offset + 5];
        // A one-path endpoint names an exact bus/device/function. Multi-hop
        // endpoints and bridges require a topology walk, so are not matched.
        if scope_type == 1 && path_count == 1 {
            let device = scopes[offset + 6];
            let function = scopes[offset + 7];
            if device > 31 || function > 7 {
                return None;
            }
            let scoped_rid = ((start_bus as u16) << 8)
                | ((device as u16) << 3)
                | function as u16;
            endpoint(scoped_rid);
        }
        offset += len;
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const IOAPIC: [u8; 8] = [3, 8, 0, 0, 0, 0, 31, 0];
    const AHCI: [u8; 8] = [1, 8, 0, 0, 0, 0, 2, 0];

    #[test]
    fn qemu_endpoint_scope_matches_only_exact_bus_device_function() {
        let mut scopes = [0u8; 16];
        scopes[..8].copy_from_slice(&IOAPIC);
        scopes[8..].copy_from_slice(&AHCI);
        assert_eq!(endpoint_scope_covers_rid(&scopes, 0x10), Some(true));
        assert_eq!(endpoint_scope_covers_rid(&scopes, 0x11), Some(false));
        assert_eq!(endpoint_scope_covers_rid(&scopes, 0x110), Some(false));
        assert_eq!(endpoint_scope_covers_rid(&scopes, 0xf8), Some(false));
        let unit = DmarUnit {
            base: 0xfed9_0000,
            include_all: false,
            scopes_paddr: scopes.as_ptr() as u64,
            scopes_len: scopes.len(),
        };
        assert!(unit.scopes_valid());
        let mut allowed = [0u64; 1024];
        assert!(unit.populate_allowed_rids(&mut allowed));
        assert_ne!(allowed[0] & (1 << 0x10), 0);
        assert_eq!(allowed[0] & (1 << 0x11), 0);
        assert_eq!(allowed[4] & (1 << 0x10), 0);
    }

    #[test]
    fn malformed_or_missing_endpoint_scope_never_admits_requester() {
        assert_eq!(endpoint_scope_covers_rid(&IOAPIC, 0x10), Some(false));
        assert_eq!(endpoint_scope_covers_rid(&[], 0x10), Some(false));
        assert_eq!(endpoint_scope_covers_rid(&[1, 7, 0, 0, 0, 0, 2], 0x10), None);
        assert_eq!(endpoint_scope_covers_rid(&[1, 10, 0, 0, 0, 0, 2, 0], 0x10), None);
    }

    #[test]
    fn bridge_scope_does_not_guess_downstream_bdf() {
        let bridge = [2, 8, 0, 0, 0, 0, 2, 0];
        assert_eq!(endpoint_scope_covers_rid(&bridge, 0x10), Some(false));
    }
}

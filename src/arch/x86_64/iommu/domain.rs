//! Software ownership of hardware VT-d domain identifiers.
//!
//! The kernel binds one live requester to each domain because two independent
//! translation roots cannot use the same IOTLB tag.

use super::retirement::VtdError;

pub const MAX_DOMAINS: usize = u16::MAX as usize + 1;

/// CAP.ND encodes domain ID widths from 4 to 16 bits in steps of two.
/// The all-ones encoding is reserved.
pub fn domain_count(cap: u64) -> Option<usize> {
    let nd = (cap & 0x7) as usize;
    (nd < 7).then(|| 1 << (4 + 2 * nd))
}

fn index(owners: &[u16], domain: u16, requester: u16) -> Result<usize, VtdError> {
    let index = usize::from(domain);
    // This implementation reserves domain zero and does not admit requester zero.
    if domain == 0 || requester == 0 || index >= owners.len() {
        return Err(VtdError::InvalidDomain);
    }
    Ok(index)
}

/// Allow a free domain or a subsequent map by its current requester.
pub fn check_domain(owners: &[u16], domain: u16, requester: u16) -> Result<(), VtdError> {
    let owner = owners[index(owners, domain, requester)?];
    if owner != 0 && owner != requester {
        return Err(VtdError::OwnershipConflict);
    }
    Ok(())
}

/// Record ownership before the first context entry for the domain can become present.
pub fn reserve_domain(owners: &mut [u16], domain: u16, requester: u16) -> Result<(), VtdError> {
    let index = index(owners, domain, requester)?;
    if owners[index] != 0 {
        return Err(VtdError::OwnershipConflict);
    }
    owners[index] = requester;
    Ok(())
}

/// Release only after the exact context's retirement effect has acknowledged.
pub fn retire_owned_domain(
    owners: &mut [u16],
    domain: u16,
    requester: u16,
    retire: impl FnOnce() -> Result<(), VtdError>,
) -> Result<(), VtdError> {
    let index = index(owners, domain, requester)?;
    if owners[index] != requester {
        return Err(VtdError::OwnershipConflict);
    }
    retire()?;
    owners[index] = 0;
    Ok(())
}

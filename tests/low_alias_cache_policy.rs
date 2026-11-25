//! A low loader identity alias must be classified before admitting a cache-typed
//! mapping of the same physical device page. The native walker supplies the
//! physical leaf and its *effective* type after PAT/MTRR decoding; this pure
//! policy decides whether the requested mapping can coexist with that leaf.

#[path = "../src/boot/direct_map_policy.rs"]
mod direct_map_policy;

use direct_map_policy::{
    cache_alias_admission, CacheAliasError, EffectiveCacheType, PhysicalRange,
};

#[test]
fn low_loader_wb_alias_refuses_uncached_device_mapping() {
    let loader_leaf = PhysicalRange { start: 0, end: 0x20_0000 };
    let device_page = PhysicalRange { start: 0xA_0000, end: 0xA_1000 };

    assert_eq!(
        cache_alias_admission(
            loader_leaf,
            EffectiveCacheType::WriteBack,
            device_page,
            EffectiveCacheType::Uncached,
        ),
        Err(CacheAliasError::ConflictingType),
    );
    assert_eq!(
        cache_alias_admission(
            loader_leaf,
            EffectiveCacheType::Unknown,
            device_page,
            EffectiveCacheType::Uncached,
        ),
        Err(CacheAliasError::UnprovenType),
    );
}

#[test]
fn compatible_or_disjoint_aliases_preserve_admission() {
    let loader_leaf = PhysicalRange { start: 0, end: 0x20_0000 };
    let device_page = PhysicalRange { start: 0xA_0000, end: 0xA_1000 };
    let remote_page = PhysicalRange { start: 0x40_0000, end: 0x40_1000 };

    assert_eq!(
        cache_alias_admission(
            loader_leaf,
            EffectiveCacheType::Uncached,
            device_page,
            EffectiveCacheType::Uncached,
        ),
        Ok(()),
    );
    assert_eq!(
        cache_alias_admission(
            loader_leaf,
            EffectiveCacheType::WriteBack,
            remote_page,
            EffectiveCacheType::Uncached,
        ),
        Ok(()),
    );
    assert_eq!(
        cache_alias_admission(
            loader_leaf,
            EffectiveCacheType::WriteBack,
            remote_page,
            EffectiveCacheType::Unknown,
        ),
        Err(CacheAliasError::UnprovenType),
        "an unproven requested cache type cannot be admitted without an alias",
    );
}

#[test]
fn invalid_or_wrapped_ranges_are_refused_before_alias_classification() {
    let device_page = PhysicalRange { start: 0xA_0000, end: 0xA_1000 };
    for invalid in [
        PhysicalRange { start: 0xA_0000, end: 0xA_0000 },
        PhysicalRange { start: 0xA_0001, end: 0xA_1000 },
        // A caller that wraps start + length must not turn it into a
        // disjoint range that is silently admitted.
        PhysicalRange { start: u64::MAX - 0xFFF, end: 0 },
    ] {
        assert_eq!(
            cache_alias_admission(
                invalid,
                EffectiveCacheType::WriteBack,
                device_page,
                EffectiveCacheType::Uncached,
            ),
            Err(CacheAliasError::InvalidRange),
        );
    }
}

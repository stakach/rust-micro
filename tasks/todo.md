# Intel VT-d IOMMU — sel4test IOPT family

Goal: pass IOPT0001, 0002, 0004, 0008, 0009, 0011.

## Plan / checklist
- [ ] build_support/bf.rs: enable CONFIG_IOMMU in default_config so IoSpaceCap / IoPageTableCap bitfields generate
- [ ] src/cap.rs: tags IO_SPACE=15, IO_PAGE_TABLE=17; FrameMapType enum; Cap::IoSpace + Cap::IoPageTable; from_words/to_words; Frame map_type field
- [ ] src/object_type.rs: X86_IO_PAGE_TABLE=13, size 12 bits
- [ ] src/untyped.rs: make_object_cap arm for IoPageTable (zeroed 4K page, paddr ptr)
- [ ] src/arch/x86_64/iommu.rs: replace probe with vtd_init; root table + lazy context tables; entry encode/decode; lookup_vtd_context_slot; lookup_iopt_slot; IOMMU page pool
- [ ] src/boot.rs: carve IOMMU page pool from RAM in reserve_user_page_region
- [ ] src/main.rs: call vtd_init after reserve_user_page_region
- [ ] src/rootserver.rs: write master io_space cap into slot 8 (when DRHU present); set bi.numIOPTLevels
- [ ] src/invocation.rs: mint io_space badge; dispatch IoPageTable/IoSpace caps; decode_x86_iopt (Map/Unmap); decode_x86_iomap (X86PageMapIO); branch X86PageUnmap on IoSpace map_type
- [ ] Build, set test regex ^(IOPT), run, iterate

## Key decisions
- numIOPTLevels = 4 (test needs pts[3]); context aw = 2.
- Caps store PHYSICAL addrs; access tables via phys_to_lin. IOMMU tables in low RAM (<4GiB, linear-map covered).
- Hand-encode vtd rte/cte/pte as u64 ops (self-consistent, spec-faithful).
- context_index = RID & 0xff; root_index = (RID>>8)&0xff.
- Lazy context-table alloc on IOPageTableMap; MapIO/Unmap use allocate=false.

## REVIEW — DONE. All 6 IOPT tests pass (IOPT0001/0002/0004/0008/0009/0011), 8/8 incl framework.
Kernel internal specs still pass (incl new io_space/io_page_table round-trip).

Files changed:
- build_support/bf.rs: CONFIG_IOMMU=true in default_config (generates IoSpaceCap/IoPageTableCap).
- src/cap.rs: tags 15/17; FrameMapType enum; Frame.map_type field; Cap::IoSpace + Cap::IoPageTable; from/to_words; round-trip spec.
- src/object_type.rs: X86_IO_PAGE_TABLE=13, size 12.
- src/untyped.rs: retype arm for IoPageTable; Frame literal map_type.
- src/arch/x86_64/iommu.rs: full rewrite — vtd_init, IOMMU page pool, rte/cte/pte encode, lookup_vtd_context_slot, lookup_iopt_slot.
- src/boot.rs: IOMMU pool sliced off top of the 16MiB user-pages carve (avoids low-RAM collision with rootserver placement).
- src/main.rs: vtd_init after reserve_user_page_region.
- src/rootserver.rs: master io_space cap in slot 8 (when DRHU>0); bi.numIOPTLevels; Frame literal map_type.
- src/invocation.rs: dispatch IoPageTable/IoSpace; X86PageMapIO route; decode_x86_iopt + decode_x86_iomap + delete_io_page_table + unmap_io_page; io_space mint badge; X86PageUnmap IO branch; finalise-on-delete for IoPageTable + IO-frames (maybe_free_object + cnode_delete frame path).

Two non-obvious bugs found + fixed:
1. IOMMU pool carved at paddr 0 collided with place_rootserver (vtd_init zeroed rootserver TCB). Fix: bundle pool into the 16MiB user-pages carve so it lands at 0x1900000.
2. IOPT0008 needs a fresh depth-4 tree, but leaked VT-d mappings (same badge across all tests → same PCI context) corrupted it. Fix: finalise-on-delete clears VT-d entries at test teardown.

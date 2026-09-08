use super::*;

pub(crate) fn run() {
    raw_validation();
    local_and_global_enables();
    installation_preserves_stepping();
    unsafe { disabled_hardware_state_and_status(); }
    crate::arch::log("  raw debug context validates hardware state and preserves stepping policy\n");
}

fn raw_validation() {
    let blank = validate_raw_context([0; 6]).unwrap();
    assert_eq!(blank.dr, [0, 0, 0, 0, DR6_INIT, DR7_INIT]);
    for bit in [11, 12, 13, 14, 15, 32, 63] {
        let mut raw = [0; 6];
        raw[5] = 1 << bit;
        assert!(validate_raw_context(raw).is_err());
    }
    for bit in [12, 32, 63] {
        let mut raw = [0; 6];
        raw[4] = 1 << bit;
        assert!(validate_raw_context(raw).is_err());
    }
    let mut raw = [0; 6];
    raw[4] = DR6_STATUS_BITS;
    assert_eq!(validate_raw_context(raw).unwrap().dr[4], DR6_INIT | DR6_STATUS_BITS);
    for bp in 0..4 {
        for address in [1 << 47, 0xffff_7fff_ffff_ffff] {
            let mut raw = [0; 6];
            raw[bp] = address;
            assert!(validate_raw_context(raw).is_err(), "disabled MOV DR must remain safe");
        }
        let mut raw = [0; 6];
        raw[bp] = 0xffff_8000_0000_0001;
        raw[5] = 3 << len_shift(bp);
        assert_eq!(validate_raw_context(raw).unwrap().dr[bp], raw[bp]);
        raw[5] |= 1 << (2 * bp);
        assert!(validate_raw_context(raw).is_err(), "enabled comparator cannot name kernel memory");
        raw[bp] = 0x1000;
        assert!(validate_raw_context(raw).is_err(), "instruction LEN must be zero");
        raw[5] = 2 << type_shift(bp);
        assert!(validate_raw_context(raw).is_err(), "I/O comparator contract is unavailable");
        for (len, size) in [(0, 1), (1, 2), (2, 8), (3, 4)] {
            for ty in [1, 3] {
                raw[5] = (1 << (2 * bp)) | (ty << type_shift(bp)) | (len << len_shift(bp));
                raw[bp] = super::super::vspace::USER_VADDR_END - size;
                assert!(validate_raw_context(raw).is_ok());
                if size != 1 {
                    raw[bp] += 1;
                    assert!(validate_raw_context(raw).is_err());
                    raw[5] &= !enable_pair(bp);
                    assert!(validate_raw_context(raw).is_ok(), "disabled stale alignment is retained");
                }
            }
        }
    }
}

fn local_and_global_enables() {
    for bp in 0..4 {
        for enables in [1, 2, 3] {
            let mut raw = [0; 6];
            raw[bp] = 0x1000;
            raw[5] = (enables << (2 * bp)) | 0x300;
            let context = validate_raw_context(raw).unwrap();
            let mut state = DebugState::new();
            install_raw_context(&mut state, &context);
            assert_eq!(state.used_breakpoints_bf, 1 << bp);
            assert_eq!(get_breakpoint(&state, bp).4, 1);
            assert_eq!(state.dr[5] & 0x300, 0x300, "LE/GE are not NT-masked");
            unset_breakpoint(&mut state, bp);
            assert_eq!(state.dr[5] & enable_pair(bp), 0);
            assert_eq!(get_breakpoint(&state, bp).4, 0);
            assert!(!state.any_breakpoint_used());
        }
    }
}

fn installation_preserves_stepping() {
    let mut state = DebugState::new();
    configure_single_stepping(&mut state, 27);
    let context = validate_raw_context([0x1000, 1, 2, 3, DR6_SINGLE_STEP, 1]).unwrap();
    install_raw_context(&mut state, &context);
    assert_eq!(state.n_instructions, 27);
    assert!(state.single_step_enabled);
    assert_eq!(state.dr, context.dr);
    let before = state;
    let mut invalid = context.dr;
    invalid[5] |= 1 << 13;
    if let Ok(context) = validate_raw_context(invalid) {
        install_raw_context(&mut state, &context);
        panic!("invalid GD accepted");
    }
    assert_eq!(state.dr, before.dr);
    assert_eq!(state.used_breakpoints_bf, before.used_breakpoints_bf);
    assert_eq!(state.n_instructions, before.n_instructions);
    assert_eq!(state.single_step_enabled, before.single_step_enabled);
}

unsafe fn live_registers() -> [u64; 6] {
    let mut dr = [0; 6];
    core::arch::asm!("mov {}, dr0", out(reg) dr[0], options(nomem, nostack));
    core::arch::asm!("mov {}, dr1", out(reg) dr[1], options(nomem, nostack));
    core::arch::asm!("mov {}, dr2", out(reg) dr[2], options(nomem, nostack));
    core::arch::asm!("mov {}, dr3", out(reg) dr[3], options(nomem, nostack));
    dr[4] = read_dr6();
    core::arch::asm!("mov {}, dr7", out(reg) dr[5], options(nomem, nostack));
    dr
}

unsafe fn disabled_hardware_state_and_status() {
    let _guard = crate::spec::KernelGuard::acquire();
    let saved = DebugState { dr: live_registers(), ..DebugState::new() };
    let disabled = DebugState {
        dr: [0x1001, 0x2002, 0x3003, 0x4004, DR6_INIT | DR6_SINGLE_STEP, DR7_INIT | ALL_ENABLE_BITS],
        ..DebugState::new()
    };
    // This path must never activate the supplied enable bits, even transiently.
    load_all_disabled(&disabled);
    let actual = live_registers();
    let mut thread = crate::tcb::Tcb::default();
    configure_single_stepping(&mut thread.debug, 2);
    crate::arch::x86_64::exceptions::defer_quiesced_debug(
        &mut thread, crate::smp::UserEntryKind::Debug { status: actual[4] },
    );
    load_breakpoint_state(&saved);
    assert_eq!(&actual[..4], &disabled.dr[..4]);
    assert_eq!(actual[5] & ALL_ENABLE_BITS, 0);
    assert_eq!(actual[4] & DR6_STATUS_BITS, DR6_SINGLE_STEP);
    assert_eq!(thread.debug.dr[4], actual[4], "cache preserves the actual hardware status word");
    assert_eq!(thread.debug.n_instructions, 1);
    assert!(thread.deferred_debug.is_none());
}

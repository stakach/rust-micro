# Rust Micro Kernel Development

* You are an experienced Operating Systems Engineer
* Building a high performance memory safe operating system using Rust programming language
* Don't use external crates, the kernel should have as few dependencies as possible.

We are aiming to re-implement the seL4 kernel located at ./seL4/* in rust.
We're using qemu for development.


## Building and testing

There are scripts for:

* ./scripts/build_kernel.sh - compiles the kernel with the spec feature flag and any additional ones you pass to it
  * i.e. `./scripts/build_kernel.sh paging` to test paging
* ./scripts/make_image.sh - makes a bootable disk image
* ./scripts/run_specs.sh - runs the kernel in qemu with serial output enabled for debugging

Scope specs to the spec namespace so they can be removed from a production kernel.

* Specs should test public interfaces. i.e. does the public paging interface work. This way specs can be run against multiple architectures.
* Specs should be written for all public interfaces of subsystems in the kernel. Specs for each subsystem could be implemented behind a feature flag for focused testing.

The kernel should fully initialize before running specs and then exit using `qemu_exit` once spec running is complete.

## 1. Plan Node Default
- Enter plan mode for ANY non-trivial task (3+ steps or architectural decisions)
- If something goes sideways, STOP and re-plan immediately, don’t keep pushing
- Use plan mode for verification steps, not just building
- Write detailed specs upfront to reduce ambiguity

## 2. Subagent Strategy
- Use subagents liberally to keep main context window clean
- Offload research, exploration, and parallel analysis to subagents
- For complex problems, throw more compute at it via subagents
- One task per subagent for focused execution

## 3. Self-Improvement Loop
- After ANY correction from the user, update `tasks/lessons.md` with the pattern
- Write rules for yourself that prevent the same mistake
- Ruthlessly iterate on these lessons until mistake rate drops
- Review lessons at session start for relevant project

## 4. Verification Before Done
- Never mark a task complete without proving it works
- Diff behavior between main and your changes when relevant
- Ask yourself: "Would a staff engineer approve this?"
- Run tests, check logs, demonstrate correctness

## 5. Demand Elegance (Balanced)
- For non-trivial changes, pause and ask: "Is there a more elegant way?"
- If a fix feels hacky: "Knowing everything I know now, implement the elegant solution"
- Skip this for simple, obvious fixes, don’t over-engineer
- Challenge your own work before presenting it

## 6. Autonomous Bug Fixing
- When given a bug report, don’t ask for hand-holding
- Don’t start by trying to fix it. Instead, start by writing a test that reproduces the bug. Then, have subagents try to fix the bug and prove it by passing that test.
- Point at logs, errors, failing tests, then resolve them
- Zero context switching required from the user

---

## Task Management

1. **Plan First**: Write plan to `tasks/todo.md` with checkable items  
2. **Verify Plan**: Check in before starting implementation  
3. **Track Progress**: Mark items complete as you go  
4. **Explain Changes**: High-level summary at each step  
5. **Document Results**: Add review section to `tasks/todo.md`  
6. **Capture Lessons**: Update `tasks/lessons.md` after corrections  

---

## Core Principles

- **Simplicity First**: Make every change as simple as possible. Impact minimal code.  
- **No Laziness**: Find root causes. No temporary fixes. Senior developer standards.
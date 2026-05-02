//! seL4 IPC-buffer layout constants.
//!
//! Mirrors libsel4's `seL4_IPCBuffer` struct layout in u64 word
//! offsets so the kernel can index directly into a user-mode IPC
//! buffer page (accessed by paddr through the BOOTBOOT identity
//! map; see `tcb.ipc_buffer_paddr`).
//!
//! Layout:
//! ```text
//!   [0]      tag (seL4_MessageInfo)
//!   [1..121] msg[120]
//!   [121]    userData
//!   [122..125] caps_or_badges[3]
//!   [125]    receiveCNode
//!   [126]    receiveIndex
//!   [127]    receiveDepth
//! ```

#![allow(dead_code)]

/// Word offset of the tag (`seL4_MessageInfo`) inside the buffer.
pub const TAG_OFFSET: usize = 0;
/// Word offset of `msg[0]`.
pub const MSG_OFFSET: usize = 1;
/// Word offset of `userData`.
pub const USER_DATA_OFFSET: usize = 121;
/// Word offset of `caps_or_badges[0]`.
pub const CAPS_OR_BADGES_OFFSET: usize = 122;
/// Word offset of `receiveCNode`.
pub const RECEIVE_CNODE_OFFSET: usize = 125;
/// Word offset of `receiveIndex`.
pub const RECEIVE_INDEX_OFFSET: usize = 126;
/// Word offset of `receiveDepth`.
pub const RECEIVE_DEPTH_OFFSET: usize = 127;

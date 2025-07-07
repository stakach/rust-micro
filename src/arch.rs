#[cfg(all(target_arch = "x86_64"))]
mod x86_64;
#[cfg(all(target_arch = "aarch64"))]
mod aarch64;

#[cfg(all(target_arch = "x86_64", feature = "spec"))]
pub use x86_64::qemu::qemu_exit;

#[cfg(all(target_arch = "aarch64", feature = "spec"))]
pub use aarch64::qemu::qemu_exit;

#[cfg(all(target_arch = "x86_64"))]
pub use x86_64::{serial::init_serial, serial::log};

#[cfg(all(target_arch = "aarch64"))]
pub use aarch64::{serial::init_serial, serial::log};

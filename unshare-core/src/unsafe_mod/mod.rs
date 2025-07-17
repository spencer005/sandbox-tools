#![deny(missing_docs)]
//! unshare-unsafe
//!
//! This module provides the low-level, `unsafe` bindings to functionality
//! that relies on unsafe syscalls and FFI operations.

pub mod process;
pub mod seccomp;
pub mod selinux;

pub use process::{InitForkResult, fork_with_init, run_forked};
pub use seccomp::{SeccompProgram, seccomp_program_new, seccomp_programs_apply};

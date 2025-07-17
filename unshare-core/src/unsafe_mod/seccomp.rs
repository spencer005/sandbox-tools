//! # Low-Level Seccomp Operations
//!
//! This module provides safe wrappers for loading and applying seccomp-bpf filters.
//! It encapsulates the `unsafe` FFI calls and interactions with the kernel,
//! exposing a safe Rust API that uses proper Rust types instead of
//! C-style primitives.

use anyhow::{Context, Result, anyhow};
use std::{fs::File, io::Read, os::unix::io::OwnedFd};

/// A high-level, safe representation of a seccomp BPF program.
///
/// This struct owns the filter data and can be safely passed between threads.
#[derive(Debug, Default, Clone)]
pub struct SeccompProgram {
    filters: Vec<libc::sock_filter>,
}

/// Reads a seccomp BPF program from an owned file descriptor and returns a safe `SeccompProgram` struct.
///
/// This function takes ownership of the file descriptor and ensures it is closed.
/// The seccomp program is validated to ensure it does not exceed `MAX_SECCOMP_PROGRAM_SIZE`
/// and that its size is a multiple of `sock_filter`.
///
/// # Arguments
///
/// * `fd`: An `OwnedFd` from which to read the BPF program.
pub fn seccomp_program_new(fd: OwnedFd) -> Result<SeccompProgram> {
    let file = File::from(fd);

    const MAX_SECCOMP_PROGRAM_SIZE: u64 = 65536;

    // Read the file into a buffer, but limit the read to prevent memory exhaustion.
    let mut bytes = Vec::new();
    file.take(MAX_SECCOMP_PROGRAM_SIZE + 1)
        .read_to_end(&mut bytes)
        .context("Can't read seccomp filter")?;

    // Now, perform all checks on the in-memory buffer.
    if bytes.len() as u64 > MAX_SECCOMP_PROGRAM_SIZE {
        return Err(anyhow!("seccomp program too large"));
    }
    if !bytes
        .len()
        .is_multiple_of(std::mem::size_of::<libc::sock_filter>())
    {
        return Err(anyhow!(
            "seccomp program size is not a multiple of filter size"
        ));
    }

    let num_filters = bytes.len() / std::mem::size_of::<libc::sock_filter>();
    let mut filter_vec = Vec::with_capacity(num_filters);

    for chunk in bytes.chunks_exact(std::mem::size_of::<libc::sock_filter>()) {
        let code = u16::from_ne_bytes([chunk[0], chunk[1]]);
        let jt = chunk[2];
        let jf = chunk[3];
        let k = u32::from_ne_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
        filter_vec.push(libc::sock_filter { code, jt, jf, k });
    }

    Ok(SeccompProgram {
        filters: filter_vec,
    })
}

/// Applies a slice of loaded seccomp programs to the current process.
///
/// # Arguments
///
/// * `programs`: A slice of `SeccompProgram` to be loaded into the kernel.
///
/// # Safety
///
/// This function requires calling the `prctl` syscall
/// directly using libc::prctl, which can lead to undefined behavior if misused.
/// On failure, `nix::Error` is used to provide detailed error information from `errno`.
pub fn seccomp_programs_apply(programs: &[SeccompProgram]) -> Result<()> {
    const PR_SET_SECCOMP: i32 = 22;
    const SECCOMP_MODE_FILTER: i32 = 2;

    for program in programs {
        let mut sock_fprog = libc::sock_fprog {
            len: program
                .filters
                .len()
                .try_into()
                .context("seccomp filter is too long")?,
            // The kernel expects a mutable pointer, but it will not be written to.
            filter: program.filters.as_ptr() as *mut _,
        };

        // Minimal unsafe block - only the actual syscall
        let result = unsafe {
            libc::prctl(
                PR_SET_SECCOMP,
                SECCOMP_MODE_FILTER,
                &mut sock_fprog as *mut _ as libc::c_ulong,
                0,
                0,
            )
        };

        if result != 0 {
            let errno = nix::Error::last();
            if matches!(errno, nix::Error::EINVAL) {
                return Err(anyhow!(
                    "Unable to set up system call filtering as requested: prctl(PR_SET_SECCOMP) reported EINVAL. (Hint: this requires a kernel configured with CONFIG_SECCOMP and CONFIG_SECCOMP_FILTER.)"
                ));
            }
            return Err(anyhow!("prctl(PR_SET_SECCOMP) failed")).with_context(|| errno);
        }
    }
    Ok(())
}

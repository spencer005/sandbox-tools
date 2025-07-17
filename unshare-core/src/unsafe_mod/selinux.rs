//! # Safe SELinux Operations
//!
//! This module provides safe Rust wrappers for `libselinux` functions.
//! It encapsulates the `unsafe` FFI calls and handles error checking, presenting
//! a clean and safe API to the rest of the crate. This avoids exposing raw
//! C types and unsafe functions to the rest of the application.

use anyhow::{Context, Result, anyhow};
use std::ffi::CString;

/// This inner module contains the raw, unsafe FFI bindings to `libselinux`.
mod ffi {
    use std::os::raw::{c_char, c_int};

    // Link to `libselinux`. The `build.rs` script for this crate will use
    // `pkg-config` to ensure the library is found and linked correctly.
    #[link(name = "selinux")]
    unsafe extern "C" {
        /// Corresponds to the `is_selinux_enabled(3)` C function.
        /// Returns > 0 if enabled, 0 if disabled, and < 0 on error.
        pub fn is_selinux_enabled() -> c_int;

        /// Corresponds to the `setexeccon(3)` C function.
        /// Sets the security context for the next `execve` call.
        /// Returns 0 on success and -1 on error.
        pub fn setexeccon(context: *const c_char) -> c_int;
    }
}

/// Checks if SELinux is enabled on the system in a safe way.
///
/// This function wraps the `unsafe` `is_selinux_enabled` FFI call, checks
/// its return value, and translates it into a Rust `Result<bool>`.
///
/// # Returns
/// - `Ok(true)` if SELinux is enabled.
/// - `Ok(false)` if SELinux is disabled.
/// - `Err` if the system call fails.
pub fn is_selinux_enabled() -> Result<bool> {
    // This call is `unsafe` because it's an FFI call.
    let res = unsafe { ffi::is_selinux_enabled() };

    if res < 0 {
        // A negative return value indicates an error.
        Err(anyhow!(std::io::Error::last_os_error()).context("is_selinux_enabled() failed"))
    } else {
        // A return value > 0 means enabled, 0 means disabled.
        Ok(res > 0)
    }
}

/// Safely sets the security context for the next `execve` call.
///
/// This function is a no-op if SELinux is not enabled. If a label is provided,
/// it is converted to a C-compatible string and passed to the `setexeccon`
/// FFI function.
///
/// # Arguments
/// * `label`: An `Option<&str>` containing the security context label. If `None`,
///   the function does nothing.
pub fn set_exec_context(label: Option<&str>) -> Result<()> {
    // First, check if SELinux is even enabled. If not, we don't need to do anything.
    if !is_selinux_enabled()? {
        return Ok(());
    }

    if let Some(label_str) = label {
        // Convert the Rust &str to a null-terminated C string, which is what
        // the C function expects. This can fail if the string contains null bytes.
        let c_label = CString::new(label_str)
            .context("SELinux exec_label contained an internal null byte")?;

        // This call is `unsafe` because it's an FFI call with a raw pointer.
        let res = unsafe { ffi::setexeccon(c_label.as_ptr()) };
        if res < 0 {
            return Err(anyhow!(std::io::Error::last_os_error()))
                .context(format!("setexeccon for label '{label_str}' failed"));
        }
    }

    Ok(())
}

/// mount options and an optional SELinux label, and combines them.
pub fn label_mount(opt: Option<&str>, mount_label: Option<&str>) -> Result<Option<String>> {
    // Start with the base options.
    let mut options = opt.map(|s| s.to_string());

    // If SELinux is enabled and a label is provided, add the context.
    if let (true, Some(label)) = (is_selinux_enabled()?, mount_label) {
        let context = format!("context=\"{label}\"");
        if let Some(existing_opts) = options.as_mut() {
            existing_opts.push(',');
            existing_opts.push_str(&context);
        } else {
            options = Some(context);
        }
    }

    Ok(options)
}

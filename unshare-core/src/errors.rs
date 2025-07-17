//! Error types for various things that can go wrong when interacting with the Linux kernel and system.

use std::path::PathBuf;
use thiserror::Error;

/// A general error type for a `nix` or `libc`-based syscall that fails.
///
/// This is a common pattern where the underlying error is an `errno` value.
/// It's useful for simple syscalls where extensive context is not needed.
#[derive(Error, Debug)]
#[error("syscall failed: {context}")]
pub struct SyscallError {
    /// A description of the context in which the syscall failed.
    pub context: String,
    /// The underlying error that caused the syscall to fail.
    #[source]
    pub source: nix::Error,
}

/// Errors that can occur during mount-related operations.
#[derive(Error, Debug)]
pub enum MountError {
    /// Error when trying to mount a filesystem.
    #[error("mount syscall failed for source: {source:?}, dest: {dest:?}")]
    MountFailed {
        /// The source path being mounted, if applicable.
        source: Option<PathBuf>,
        /// The destination path where the source is being mounted.
        dest: PathBuf,
        /// The underlying error that caused the mount to fail.
        #[source]
        source_err: nix::Error,
    },

    /// Error when trying to unmount a filesystem.
    #[error("umount syscall failed for dest: {dest:?}")]
    UmountFailed {
        /// The destination path that was attempted to be unmounted.
        dest: PathBuf,
        /// The underlying error that caused the umount to fail.
        #[source]
        source_err: nix::Error,
    },

    /// Error when trying to pivot the root filesystem.
    #[error("pivot_root failed on new_root: {new_root:?}, put_old: {put_old:?}")]
    PivotRootFailed {
        /// The new root directory to pivot to.
        new_root: PathBuf,
        /// The old root directory that will be put in place of the new root.
        put_old: PathBuf,
        /// The underlying error that caused the pivot_root to fail.
        #[source]
        source_err: nix::Error,
    },

    /// Error when trying to read the mount table from `/proc/self/mountinfo`.
    #[error("failed to read /proc/self/mountinfo")]
    ReadMountInfo(#[source] std::io::Error),
    /// Error when parsing a line from the mount table.
    #[error("failed to parse /proc/self/mountinfo: {line}")]
    ParseMountInfo {
        /// The line from the mount table that failed to parse.
        line: String,
    },
    /// Error when trying to find the root mount in the mount table.
    #[error("root mount not found in mount table")]
    RootMountNotFound,
}

/// Errors that can occur during namespace setup.
#[derive(Error, Debug)]
pub enum NamespaceError {
    /// The flags that were attempted to be used with `unshare`.
    #[error("unshare({flags:?}) failed")]
    UnshareFailed {
        /// The flags that were attempted to be used with `unshare`.
        /// e.g., "CLONE_NEWNS", "CLONE_NEWPID"
        flags: String,
        /// The underlying error that caused the unshare to fail.
        #[source]
        source_err: nix::Error,
    },

    /// The type of namespace that was attempted to be set.
    #[error("setns({ns_type}) failed on fd: {fd}")]
    SetnsFailed {
        /// The type of namespace that was attempted to be set.
        /// e.g., "CLONE_NEWNS", "CLONE_NEWPID"
        ns_type: String,
        /// The file descriptor that was attempted to be set.
        fd: std::os::unix::io::RawFd,
        /// The underlying error that caused the setns to fail.
        #[source]
        source_err: nix::Error,
    },
}

/// Errors related to seccomp filter application.
#[derive(Error, Debug)]
pub enum SeccompError {
    /// Failed to apply the seccomp filter using `prctl(PR_SET_SECCOMP)`.
    #[error("prctl(PR_SET_SECCOMP) failed to apply filter")]
    ApplyFailed(#[source] nix::Error),
    /// The seccomp BPF program provided is invalid (e.g., wrong size or alignment).
    #[error("seccomp BPF program is invalid (e.g., wrong size or alignment)")]
    InvalidProgram,
    /// Failed to read the seccomp BPF program from a file descriptor.
    #[error("could not read seccomp BPF program from file descriptor")]
    ReadFailed(#[source] std::io::Error),
}

/// Errors related to interacting with `/proc` filesystem entries.
#[derive(Error, Debug)]
pub enum ProcfsError {
    /// Failed to write to a `/proc` filesystem entry.
    #[error("failed to write to {path:?}")]
    WriteFailed {
        /// The path to the `/proc` entry that was attempted to be written to.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source_err: std::io::Error,
    },
    /// Failed to read from a `/proc` filesystem entry.
    #[error("failed to read from {path:?}")]
    ReadFailed {
        /// The path to the `/proc` entry that was attempted to be read from.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source_err: std::io::Error,
    },
    /// Failed to parse the content of a `/proc` filesystem entry.
    #[error("failed to parse content of {path:?}: '{content}'")]
    ParseFailed {
        /// The path to the `/proc` entry whose content could not be parsed.
        path: PathBuf,
        /// The content that failed to parse.
        content: String,
    },
}

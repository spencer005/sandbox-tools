//! # Low-Level User and Group Operations
//!
//! This module provides safe wrappers for low-level operations related to
//! Linux users and groups. It interacts directly with the system to query
//! information like real user IDs and system-wide overflow IDs, and to
//! configure user namespaces by writing to the `/proc` filesystem.

use crate::errors::ProcfsError;
use anyhow::{Context, Result};
use nix::sys::prctl;
use nix::unistd::{self, Gid, Pid, Uid};
use std::fs;
use std::path::PathBuf;

/// A container for various user and group IDs relevant to the sandbox.
#[derive(Debug, Clone, Copy)]
pub struct UserIds {
    /// The real user ID of the process that is creating the sandbox.
    /// Must be set before the fork.
    pub real_uid: Uid,
    /// The real group ID of the process that is creating the sandbox
    /// Must be set before the fork.
    pub real_gid: Gid,
    /// The system's configured overflow UID.
    pub overflow_uid: Uid,
    /// The system's configured overflow GID.
    pub overflow_gid: Gid,
}

impl UserIds {
    /// Gathers all necessary user and group IDs from the system.
    pub fn new() -> Result<Self> {
        let real_uid = unistd::getuid();
        let real_gid = unistd::getgid();
        let (overflow_uid, overflow_gid) =
            read_overflow_ids().context("Failed to read overflow IDs")?;
        Ok(Self {
            real_uid,
            real_gid,
            overflow_uid,
            overflow_gid,
        })
    }
}

/// Configuration for UID/GID mapping operations
#[derive(Debug, Clone)]
pub struct UidGidMapConfig {
    /// The User ID (UID) of the current process in the parent (host) user namespace.
    pub parent_uid: Uid,
    /// The User ID (UID) that the `parent_uid` will be mapped to inside the new
    /// user namespace. For unprivileged user namespaces, this is often `Uid::from_raw(0)`
    /// to map the current user to root inside the sandbox.
    pub sandbox_uid: Uid,
    /// The Group ID (GID) of the current process in the parent (host) user namespace.
    pub parent_gid: Gid,
    /// The Group ID (GID) that the `parent_gid` will be mapped to inside the new
    /// user namespace. For unprivileged user namespaces, this is often `Gid::from_raw(0)`
    /// to map the current user's primary group to root group inside the sandbox.
    pub sandbox_gid: Gid,
    /// The system-wide overflow UID configured via `/proc/sys/kernel/overflowuid`.
    /// This UID is used when a process in a user namespace attempts to use a UID
    /// that has no mapping to the parent namespace.
    pub overflow_uid: Uid,
    /// The system-wide overflow GID configured via `/proc/sys/kernel/overflowgid`.
    /// This GID is used when a process in a user namespace attempts to use a GID
    /// that has no mapping to the parent namespace.
    pub overflow_gid: Gid,
    /// If `true`, the `setgroups` file in `/proc/[pid]/setgroups` will be set to "deny".
    /// This prevents processes inside the user namespace from being able to gain new
    /// group memberships, which is a security hardening measure for unprivileged
    /// user namespaces.
    pub deny_groups: bool,
    /// If `true`, it implies that the intention is to map the parent's `parent_uid`
    /// and `parent_gid` to `Uid::from_raw(0)` and `Gid::from_raw(0)` respectively
    /// inside the sandbox, effectively granting root privileges within the namespace.
    /// (Note: The actual mapping values are determined by `sandbox_uid` and `sandbox_gid`).
    pub map_root: bool,
}

impl UidGidMapConfig {
    /// Writes the UID and GID mappings to the appropriate `/proc` files.
    ///
    /// This function configures how user and group IDs are translated between the parent
    /// and child user namespaces by writing to `/proc/[pid]/uid_map` and `/proc/[pid]/gid_map`.
    ///
    /// # User Namespace ID Mapping
    ///
    /// When a new user namespace is created, the kernel needs to know how to translate
    /// UIDs and GIDs between the "inside" (child namespace) and "outside" (parent namespace).
    /// Without this mapping, processes in the child namespace would have no valid UIDs/GIDs.
    ///
    /// The kernel interface expects lines in the format:
    /// ```text
    /// ID-inside-ns ID-outside-ns length
    /// ```
    ///
    /// Where:
    /// - `ID-inside-ns`: The UID/GID as seen inside the child namespace
    /// - `ID-outside-ns`: The corresponding UID/GID in the parent namespace
    /// - `length`: Number of consecutive IDs to map (usually 1)
    ///
    /// For example, `"1000 1000 1"` means "UID 1000 inside the namespace maps to UID 1000 outside"
    ///
    /// # Unprivileged User Namespace Mapping
    ///
    /// When an unprivileged user creates a new user namespace, the kernel allows the
    /// creator's UID and GID to be mapped to any other UID/GID inside the namespace.
    /// This is typically used to map the real user to the `root` user (UID 0) inside
    /// the sandbox, granting full privileges within the sandboxed environment without
    /// requiring any privileges on the host system. This function handles writing the
    /// single-line mapping required for this operation.
    pub fn write_map(&self, pid: Option<Pid>) -> Result<(), ProcfsError> {
        let proc_dir = if let Some(p) = pid {
            PathBuf::from("/proc").join(p.to_string())
        } else {
            PathBuf::from("/proc/self")
        };

        if self.deny_groups {
            let setgroups_path = proc_dir.join("setgroups");
            match fs::write(&setgroups_path, "deny\n") {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(ProcfsError::WriteFailed {
                        path: setgroups_path,
                        source_err: e,
                    });
                }
            }
        }

        // Write uid_map. For an unprivileged user, this can only contain a single
        // line mapping the real UID to a sandbox UID.
        let uid_map_str = format!(
            "{} {} 1\n",
            self.sandbox_uid.as_raw(),
            self.parent_uid.as_raw()
        );
        let uid_map_path = proc_dir.join("uid_map");
        fs::write(&uid_map_path, uid_map_str).map_err(|e| ProcfsError::WriteFailed {
            path: uid_map_path,
            source_err: e,
        })?;

        // Write gid_map. For an unprivileged user, this can only contain a single
        // line mapping the real GID to a sandbox GID.
        let gid_map_str = format!(
            "{} {} 1\n",
            self.sandbox_gid.as_raw(),
            self.parent_gid.as_raw()
        );
        let gid_map_path = proc_dir.join("gid_map");
        fs::write(&gid_map_path, gid_map_str).map_err(|e| ProcfsError::WriteFailed {
            path: gid_map_path,
            source_err: e,
        })?;

        Ok(())
    }
}

/// Reads and parses the system's overflow UID and GID.
pub fn read_overflow_ids() -> Result<(Uid, Gid), ProcfsError> {
    let uid = read_overflow_id("/proc/sys/kernel/overflowuid")?;
    let gid = read_overflow_id("/proc/sys/kernel/overflowgid")?;
    Ok((Uid::from_raw(uid), Gid::from_raw(gid)))
}

fn read_overflow_id(path: &str) -> Result<u32, ProcfsError> {
    let path_buf = PathBuf::from(path);
    let content = fs::read_to_string(&path_buf).map_err(|e| ProcfsError::ReadFailed {
        path: path_buf.clone(),
        source_err: e,
    })?;

    content
        .trim()
        .parse()
        .map_err(|_| ProcfsError::ParseFailed {
            path: path_buf,
            content,
        })
}

/// Switches the process to the real user's UID/GID.
pub fn switch_to_user(
    no_new_privs: bool,
    unshare_user: bool,
    real_uid: Uid,
    real_gid: Gid,
) -> Result<(), anyhow::Error> {
    if no_new_privs {
        prctl::set_no_new_privs().context("PR_SET_NO_NEW_PRIVS failed")?;
    }

    if !real_uid.is_root() && !unshare_user {
        unistd::setresgid(real_gid, real_gid, real_gid).context("Can't setresgid")?;
        unistd::setresuid(real_uid, real_uid, real_uid).context("Can't setresuid")?;
    }

    Ok(())
}

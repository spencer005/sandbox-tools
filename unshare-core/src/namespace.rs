//! # Namespace Configuration Types
//!
//! This module provides safe types for configuring Linux namespaces

#[cfg(feature = "cli")]
use clap::Args;

/// Configuration options for Linux namespace creation.
///
/// This struct specifies which Linux namespaces should be unshared (created anew)
/// when setting up the sandbox. Each field corresponds to a specific namespace type:
///
/// - **User namespace** (`unshare_user`): Isolates user and group IDs
/// - **PID namespace** (`unshare_pid`): Isolates process IDs
/// - **Network namespace** (`unshare_net`): Isolates network interfaces and routing
/// - **IPC namespace** (`unshare_ipc`): Isolates System V IPC objects and POSIX message queues
/// - **UTS namespace** (`unshare_uts`): Isolates hostname and NIS domain name
/// - **Cgroup namespace** (`unshare_cgroup`): Isolates cgroup filesystem views
///
/// By default, no namespaces are unshared, meaning the process will inherit
/// the namespaces of its parent.
#[cfg_attr(feature = "cli", derive(Args))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NamespaceOptions {
    /// Create a new user namespace for UID/GID isolation
    #[cfg_attr(feature = "cli", arg(long))]
    pub unshare_user: bool,
    /// Create a new PID namespace for process isolation
    #[cfg_attr(feature = "cli", arg(long))]
    pub unshare_pid: bool,
    /// Create a new network namespace for network isolation
    #[cfg_attr(feature = "cli", arg(long))]
    pub unshare_net: bool,
    /// Create a new IPC namespace for inter-process communication isolation
    #[cfg_attr(feature = "cli", arg(long))]
    pub unshare_ipc: bool,
    /// Create a new UTS namespace for hostname isolation
    #[cfg_attr(feature = "cli", arg(long))]
    pub unshare_uts: bool,
    /// Create a new cgroup namespace for cgroup view isolation
    #[cfg_attr(feature = "cli", arg(long))]
    pub unshare_cgroup: bool,
}

impl NamespaceOptions {
    /// Create namespace options with all namespaces enabled.
    pub fn all() -> Self {
        Self {
            unshare_user: true,
            unshare_pid: true,
            unshare_net: true,
            unshare_ipc: true,
            unshare_uts: true,
            unshare_cgroup: true,
        }
    }

    /// Create namespace options with no namespaces enabled.
    pub fn none() -> Self {
        Self::default()
    }
}

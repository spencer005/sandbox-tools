//! unshare-core - Core Sandboxing Library
//! This crate provides the core functionality for creating and managing
//! namespaces, mounts, and process execution in a sandboxed environment.

mod fs;
pub mod unsafe_mod;

pub mod mount;

pub mod child;
pub mod parent;

pub mod env;
pub mod errors;
pub mod namespace;
pub mod users;
pub mod utils;

pub use env::EnvOptions;
pub use mount::{MountOp, bind_mount};
pub use namespace::NamespaceOptions;
pub use unsafe_mod::process::ChildExitStatus;
pub use utils::{handle_die_with_parent, propagate_exit_status, unblock_sigchild};

use crate::unsafe_mod::{SeccompProgram, run_forked};
use crate::{child::child_process, parent::parent_process, users::UserIds};
use anyhow::{Context, Result, anyhow};
use nix::{
    errno::Errno,
    sched::CloneFlags,
    unistd::{self, Gid, Uid},
};
use std::path::PathBuf;

#[cfg(feature = "cli")]
use clap::{Args, ValueEnum, builder::TypedValueParser};

/// Pasta networking modes
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "cli", derive(ValueEnum))]
pub enum PastaMode {
    /// Transparent mode - feels like host network, copies host networking config
    Transparent,
    /// Loopback-only mode - minimal networking, just loopback and basic connectivity
    #[default]
    LoopbackOnly,
}

/// A comprehensive struct holding all validated and processed command-line options
/// required to configure and run the sandbox.
#[cfg_attr(feature = "cli", derive(Args))]
#[derive(Debug, Clone)]
pub struct SandboxOptions {
    // General options
    /// If `true`, the sandbox process will log its level prefix.
    #[cfg_attr(feature = "cli", arg(long))]
    pub level_prefix: bool,
    /// If `true`, the sandboxed process will run as PID 1 in its new PID namespace.
    #[cfg_attr(feature = "cli", arg(long))]
    pub as_pid_1: bool,
    /// If `true`, the sandboxed process will die if its parent dies.
    #[cfg_attr(feature = "cli", arg(long))]
    pub die_with_parent: bool,
    /// If `true`, the sandboxed process will start a new session.
    #[cfg_attr(feature = "cli", arg(long))]
    pub new_session: bool,
    /// If `true`, the `PR_SET_NO_NEW_PRIVS` bit will be set on the sandboxed process.
    #[cfg_attr(feature = "cli", arg(long))]
    pub no_new_privs: bool,

    /// Options for controlling the environment variables of the sandboxed process.
    #[cfg_attr(feature = "cli", command(flatten))]
    pub env: EnvOptions,

    // Namespace creation options
    /// Options for configuring the various Linux namespaces.
    #[cfg_attr(feature = "cli", command(flatten))]
    pub namespaces: NamespaceOptions,

    // User namespace configuration
    /// The UID to map the calling user to inside the user namespace.
    /// The UID to map the calling user to inside the user namespace.
    #[cfg_attr(feature = "cli", arg(long = "uid", value_name = "UID", value_parser = clap::value_parser!(u32).map(Uid::from_raw)))]
    pub sandbox_uid: Option<Uid>,
    /// The GID to map the calling user's primary group to inside the user namespace.
    #[cfg_attr(feature = "cli", arg(long = "gid", value_name = "GID", value_parser = clap::value_parser!(u32).map(Gid::from_raw)))]
    pub sandbox_gid: Option<Gid>,

    // String/path options
    /// The value to set for `argv[0]` inside the sandbox.
    #[cfg_attr(feature = "cli", arg(long, value_name = "STRING"))]
    pub argv0: Option<String>,
    /// The directory to change into within the sandbox.
    #[cfg_attr(feature = "cli", arg(long, value_name = "DIR"))]
    pub chdir: Option<PathBuf>,
    /// The SELinux execution label to apply.
    #[cfg_attr(feature = "cli", arg(long, value_name = "LABEL"))]
    pub exec_label: Option<String>,
    /// The SELinux file label to apply.
    #[cfg_attr(feature = "cli", arg(long, value_name = "LABEL"))]
    pub file_label: Option<String>,

    // Mount-related flags derived from options
    /// If `true`, a `/dev/pts` mount is required.
    #[cfg_attr(feature = "cli", arg(long, default_value_t = false, hide = true))]
    pub needs_devpts: bool,

    // Networking options
    /// The pasta networking mode to use.
    #[cfg_attr(feature = "cli", arg(long, value_enum, default_value_t = PastaMode::LoopbackOnly))]
    pub pasta_mode: PastaMode,

    /// The path to the host's TTY device, if stdout is a TTY.
    #[cfg_attr(feature = "cli", arg(long, hide = true))]
    pub host_tty_dev_path: Option<String>,

    /// A comma-separated list of capabilities to add to the bounding set.
    #[cfg_attr(feature = "cli", arg(long = "cap-add", value_name = "CAP", action = clap::ArgAction::Append, value_delimiter = ','))]
    pub cap_add: Vec<String>,
    /// A comma-separated list of capabilities to drop from the bounding set.
    #[cfg_attr(feature = "cli", arg(long = "cap-drop", value_name = "CAP", action = clap::ArgAction::Append, value_delimiter = ','))]
    pub cap_drop: Vec<String>,
}

impl Default for SandboxOptions {
    fn default() -> Self {
        Self {
            level_prefix: false,
            as_pid_1: false,
            die_with_parent: false,
            new_session: false,
            no_new_privs: true,
            env: EnvOptions::default(),
            namespaces: NamespaceOptions::default(),
            sandbox_uid: None,
            sandbox_gid: None,
            argv0: None,
            chdir: None,
            exec_label: None,
            file_label: None,
            needs_devpts: false,
            pasta_mode: PastaMode::default(),
            host_tty_dev_path: None,
            cap_add: Vec::new(),
            cap_drop: Vec::new(),
        }
    }
}

/// Runs the sandboxed command with the given options, mount operations, and seccomp programs.
///
/// This function handles the full lifecycle of the sandbox:
/// 1. Pre-clone setup (determining clone flags, preparing `/proc/self/fd/` for child communication).
/// 2. Forking the process into parent and child.
/// 3. In the parent process: managing the child's UID/GID map and waiting for its exit.
/// 4. In the child process: initializing namespaces, setting up mounts, applying seccomp,
///    and executing the target command.
///
/// # Arguments
/// * `sandbox_options` - A `SandboxOptions` struct containing all configuration for the sandbox.
/// * `command_strings` - A slice of strings representing the command and its arguments to execute inside the sandbox.
/// * `mount_ops` - A vector of `MountOp` specifying the filesystem mounts to perform.
/// * `seccomp_programs` - A vector of `SeccompProgram` to apply to the sandboxed process.
///
/// # Returns
/// A `Result` containing the exit code of the sandboxed process on success,
/// or an `anyhow::Error` if any part of the sandbox setup or execution fails.
pub fn run(
    mut sandbox_options: SandboxOptions,
    command_strings: &[String],
    mount_ops: Vec<MountOp>,
    seccomp_programs: Vec<SeccompProgram>,
) -> Result<i32> {
    // Gather all necessary user and group IDs from the system.
    let user_ids = UserIds::new()?;

    // Determine host TTY device path if it wasn't specified.
    if sandbox_options.host_tty_dev_path.is_none() && unistd::isatty(std::io::stdout())? {
        let tty_path =
            unistd::ttyname(std::io::stdout()).context("Failed to get tty name for stdout")?;
        sandbox_options.host_tty_dev_path = Some(tty_path.to_string_lossy().into_owned());
    }

    // Build clone flags for unprivileged namespace creation
    let mut clone_flags = CloneFlags::CLONE_NEWNS;
    if sandbox_options.namespaces.unshare_user {
        clone_flags.insert(CloneFlags::CLONE_NEWUSER);
    }
    if sandbox_options.namespaces.unshare_pid {
        clone_flags.insert(CloneFlags::CLONE_NEWPID);
    }
    if sandbox_options.namespaces.unshare_net {
        clone_flags.insert(CloneFlags::CLONE_NEWNET);
    }
    if sandbox_options.namespaces.unshare_ipc {
        clone_flags.insert(CloneFlags::CLONE_NEWIPC);
    }
    if sandbox_options.namespaces.unshare_uts {
        clone_flags.insert(CloneFlags::CLONE_NEWUTS);
    }
    if sandbox_options.namespaces.unshare_cgroup
        && nix::sys::stat::stat("/proc/self/ns/cgroup").is_ok()
    {
        clone_flags.insert(CloneFlags::CLONE_NEWCGROUP);
    }
    // --- End of pre-clone setup ---

    // The child closure must be 'static, so we need to give it owned data.
    let child_options = sandbox_options.clone();
    let child_user_ids = user_ids;
    let child_command_strings = command_strings.to_vec();

    let mut child_data = Some((mount_ops, seccomp_programs));
    let child_fn = move || -> Result<i32> {
        let (mount_ops, seccomp_programs) = child_data
            .take()
            .expect("child_fn should only be called once");
        child_process(
            &child_options,
            &child_user_ids,
            &child_command_strings,
            mount_ops,
            seccomp_programs,
        )
        .context("Child process setup failed")
    };

    let parent_fn =
        |child_pid| parent_process(&sandbox_options, child_pid).context("parent process failed");

    run_forked(clone_flags, parent_fn, child_fn).map_err(|err| {
        // Try to downcast the error source to a nix::Error (Errno) to provide
        // specific error messages for common namespace creation problems.
        if let Some(nix_err) = err.source().and_then(|s| s.downcast_ref::<nix::Error>()) {
            if sandbox_options.namespaces.unshare_user {
                if *nix_err == Errno::EINVAL {
                    return anyhow!("Creating new namespace failed, likely because the kernel does not support user namespaces. Enable with 'sysctl kernel.unprivileged_userns_clone=1'.");
                } else if *nix_err == Errno::EPERM {
                    return anyhow!("No permissions to creating new namespace, likely because the kernel does not allow non-privileged user namespaces. On e.g. debian this can be enabled with 'sysctl kernel.unprivileged_userns_clone=1'.");
                }
            }
            if *nix_err == Errno::ENOSPC {
                return anyhow!("Creating new namespace failed: nesting depth or /proc/sys/user/max_*_namespaces exceeded (ENOSPC)");
            }
        }
        err.context("Creating new namespace failed")
    })
}

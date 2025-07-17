//! A module for adapting and validating command-line interface arguments
//! into structured configuration options.

use crate::parser::Cli;
use anyhow::{anyhow, Context, Result};
use nix::unistd::{Gid, Uid};
use std::{fs::File, os::unix::io::OwnedFd};
use unshare_core::{MountOp, SandboxOptions};

/// represents the fully parsed and validated configuration
type Config = (SandboxOptions, Vec<String>, Vec<MountOp>, Vec<OwnedFd>);

/// Translates the parsed `Cli` arguments into safe, structured option sets,
/// performing all necessary validation and processing. This function is the
/// primary entry point for converting user input into a configuration that
/// can be safely passed through the application, eliminating the need for
/// `unsafe` access to global state.
pub fn adapt_and_validate(cli: Cli, real_uid: Uid, real_gid: Gid) -> Result<Config> {
    let mut mount_ops = Vec::new();
    let mut sandbox_options = cli.sandbox;

    // --- Namespace Options ---
    if cli.unshare_all {
        sandbox_options.namespaces.unshare_user = true;
        sandbox_options.namespaces.unshare_pid = true;
        sandbox_options.namespaces.unshare_net = true;
        sandbox_options.namespaces.unshare_uts = true;
        sandbox_options.namespaces.unshare_cgroup = true;
    }
    if cli.share_net {
        sandbox_options.namespaces.unshare_net = false;
    }

    // --- Mount Operations ---
    let mut needs_devpts = false;

    for c in cli.bind.chunks(2) {
        mount_ops.push(MountOp::BindMount {
            source: c[0].clone().into(),
            dest: c[1].clone().into(),
            readonly: false,
            devices: false,
            allow_not_exist: false,
        });
    }
    for c in cli.bind_try.chunks(2) {
        mount_ops.push(MountOp::BindMount {
            source: c[0].clone().into(),
            dest: c[1].clone().into(),
            readonly: false,
            devices: false,
            allow_not_exist: true,
        });
    }
    for c in cli.ro_bind.chunks(2) {
        mount_ops.push(MountOp::BindMount {
            source: c[0].clone().into(),
            dest: c[1].clone().into(),
            readonly: true,
            devices: false,
            allow_not_exist: false,
        });
    }
    for c in cli.ro_bind_try.chunks(2) {
        mount_ops.push(MountOp::BindMount {
            source: c[0].clone().into(),
            dest: c[1].clone().into(),
            readonly: true,
            devices: false,
            allow_not_exist: true,
        });
    }
    for c in cli.dev_bind.chunks(2) {
        mount_ops.push(MountOp::BindMount {
            source: c[0].clone().into(),
            dest: c[1].clone().into(),
            readonly: false,
            devices: true,
            allow_not_exist: false,
        });
    }
    for c in cli.dev_bind_try.chunks(2) {
        mount_ops.push(MountOp::BindMount {
            source: c[0].clone().into(),
            dest: c[1].clone().into(),
            readonly: false,
            devices: true,
            allow_not_exist: true,
        });
    }

    for p in cli.remount_ro {
        mount_ops.push(MountOp::RemountRoNoRecursive { dest: p });
    }

    if let Some(p) = cli.proc {
        mount_ops.push(MountOp::MountProc { dest: p });
    }
    if let Some(p) = cli.dev {
        mount_ops.push(MountOp::MountDev { dest: p });
        needs_devpts = true;
    }
    if let Some(p) = cli.mqueue {
        mount_ops.push(MountOp::MountMqueue { dest: p });
    }
    if let Some(p) = cli.tmpfs {
        mount_ops.push(MountOp::MountTmpfs { dest: p });
    }

    for d in cli.dir {
        mount_ops.push(MountOp::MakeDir { dest: d });
    }
    for s in cli.symlink.chunks(2) {
        mount_ops.push(MountOp::MakeSymlink {
            source_text: s[0].clone(),
            dest: s[1].clone().into(),
        });
    }
    for c in cli.chmod.chunks(2) {
        let perms = u32::from_str_radix(&c[0], 8).context("Invalid octal mode for --chmod")?;
        mount_ops.push(MountOp::Chmod {
            path: c[1].clone().into(),
            perms,
        });
    }

    sandbox_options.needs_devpts = needs_devpts;

    // --- Seccomp ---
    let mut seccomp_fds = Vec::new();
    if let Some(seccomp_file) = cli.seccomp {
        let file = File::open(&seccomp_file)
            .with_context(|| format!("Failed to open seccomp file: {}", seccomp_file.display()))?;
        seccomp_fds.push(OwnedFd::from(file));
    }

    // --- Command ---
    let command_strings = cli.command;

    if sandbox_options.sandbox_uid.is_none() {
        sandbox_options.sandbox_uid = Some(real_uid);
    }
    if sandbox_options.sandbox_gid.is_none() {
        sandbox_options.sandbox_gid = Some(real_gid);
    }

    // --- Final Validation ---
    if sandbox_options.as_pid_1 && !sandbox_options.namespaces.unshare_pid {
        return Err(anyhow!("--as-pid-1 requires --unshare-pid"));
    }

    Ok((sandbox_options, command_strings, mount_ops, seccomp_fds))
}

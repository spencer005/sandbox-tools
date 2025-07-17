//! This module provides the `run_clap` function to execute the rwrap CLI application.

use crate::{adapt_and_validate, Cli};
use clap::Parser;

use anyhow::{Context, Result};
use nix::unistd;
use unshare_core::unsafe_mod::seccomp_program_new;

/// Runs the rwrap CLI application with the provided arguments.
pub fn run_clap(args: Vec<String>) -> Result<i32> {
    let _program_name = args.first().cloned().unwrap_or_else(|| "rwrap".to_string());
    let cli = Cli::parse_from(args);

    let real_uid = unistd::getuid();
    let real_gid = unistd::getgid();

    let (sandbox_options, command_strings, mount_ops, seccomp_fds) =
        adapt_and_validate(cli, real_uid, real_gid)?;

    let seccomp_programs = seccomp_fds
        .into_iter()
        .map(seccomp_program_new)
        .collect::<Result<Vec<_>>>()
        .context("Failed to load seccomp programs")?;

    unshare_core::run(
        sandbox_options,
        &command_strings,
        mount_ops,
        seccomp_programs,
    )
}

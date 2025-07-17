//! Command-line argument parser using `clap` derive macros.

use clap::Parser;
use std::path::PathBuf;
use unshare_core::SandboxOptions;

/// A tool to create sandboxed environments for unprivileged users.
#[derive(Parser, Debug)]
#[command(
    name = "rwrap",
    version,
    about,
    long_about = "rwrap is a tool to create sandboxed environments. It works by creating a new, separate filesystem and process namespace for the application to run in."
)]
pub struct Cli {
    /// All general sandbox options, which can be configured via flags.
    #[command(flatten)]
    pub sandbox: SandboxOptions,

    // --- Special Namespace Options ---
    /// Unshare all possible namespaces
    #[arg(
        long,
        help = "Unshare all namespaces: user, ipc, pid, net, uts, cgroup"
    )]
    pub unshare_all: bool,

    /// Retain the network namespace (can be used with --unshare-all)
    #[arg(long)]
    pub share_net: bool,

    // --- Mounting Options ---
    /// Bind mount SRC on DEST
    #[arg(long, value_names = &["SRC", "DEST"], num_args = 2, action = clap::ArgAction::Append)]
    pub bind: Vec<String>,

    /// Bind mount SRC on DEST, but ignore if SRC doesn't exist
    #[arg(long, value_names = &["SRC", "DEST"], num_args = 2, action = clap::ArgAction::Append)]
    pub bind_try: Vec<String>,

    /// Bind mount the device SRC on DEST
    #[arg(long, value_names = &["SRC", "DEST"], num_args = 2, action = clap::ArgAction::Append)]
    pub dev_bind: Vec<String>,

    /// Bind mount the device SRC on DEST, but ignore if SRC doesn't exist
    #[arg(long, value_names = &["SRC", "DEST"], num_args = 2, action = clap::ArgAction::Append)]
    pub dev_bind_try: Vec<String>,

    /// Read-only bind mount SRC on DEST
    #[arg(long, value_names = &["SRC", "DEST"], num_args = 2, action = clap::ArgAction::Append)]
    pub ro_bind: Vec<String>,

    /// Read-only bind mount SRC on DEST, but ignore if SRC doesn't exist
    #[arg(long, value_names = &["SRC", "DEST"], num_args = 2, action = clap::ArgAction::Append)]
    pub ro_bind_try: Vec<String>,

    /// Remount DEST as read-only, without recursive option
    #[arg(long, value_name = "DEST", action = clap::ArgAction::Append)]
    pub remount_ro: Vec<PathBuf>,

    /// Mount new procfs on DEST
    #[arg(long, value_name = "DEST")]
    pub proc: Option<PathBuf>,

    /// Mount new devtmpfs on DEST
    #[arg(long, value_name = "DEST")]
    pub dev: Option<PathBuf>,

    /// Mount new tmpfs on DEST
    #[arg(long, value_name = "DEST")]
    pub tmpfs: Option<PathBuf>,

    /// Mount new mqueue on DEST
    #[arg(long, value_name = "DEST")]
    pub mqueue: Option<PathBuf>,

    /// Create a directory at DEST
    #[arg(long, value_name = "DEST", action = clap::ArgAction::Append)]
    pub dir: Vec<PathBuf>,

    /// Create a symlink at DEST with target SRC
    #[arg(long, value_names = &["SRC", "DEST"], num_args = 2, action = clap::ArgAction::Append)]
    pub symlink: Vec<String>,

    /// Set the mode of a file or directory
    #[arg(long, value_names = &["OCTAL-MODE", "PATH"], num_args = 2, action = clap::ArgAction::Append)]
    pub chmod: Vec<String>,

    // --- Seccomp ---
    /// Apply seccomp filter from file
    #[arg(long, value_name = "FILE")]
    pub seccomp: Option<PathBuf>,

    /// The command to run inside the sandbox
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

//! # Environment Variable Configuration
//!
//! This module defines the configuration options for managing environment
//! variables within the sandbox. It uses conditional compilation (`cfg_attr`)
//! to add `clap` attributes only when the `cli` feature is enabled,
//! allowing the same struct to be used in both the core library and the
//! command-line interface without creating a hard dependency on `clap`.

// This will allow the struct to derive `clap::Args` when the `cli` feature is set.
#[cfg(feature = "cli")]
use clap::Args;

/// Defines how environment variables should be handled in the sandboxed process.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
// Conditionally add the `clap::Args` derive macro.
#[cfg_attr(feature = "cli", derive(Args))]
pub struct EnvOptions {
    /// Clear the environment
    #[cfg_attr(feature = "cli", arg(long))]
    pub clearenv: bool,

    /// Set an environment variable
    #[cfg_attr(feature = "cli", arg(long, value_names = &["VAR", "VALUE"], num_args = 2, action = clap::ArgAction::Append))]
    pub setenv: Vec<String>,

    /// Unset an environment variable
    #[cfg_attr(feature = "cli", arg(long, value_name = "VAR", action = clap::ArgAction::Append))]
    pub unsetenv: Vec<String>,
}

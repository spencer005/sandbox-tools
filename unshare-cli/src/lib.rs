#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! # Unshare CLI
//!
//! This crate provides the main CLI application for the sandboxing functionality
//! provided by the `unshare-core` crate. It is responsible for parsing command-line
//! arguments and orchestrating the sandbox setup by calling into `unshare-core`.
//!
//! ## Architecture
//!
//! - **CLI Logic**: This crate handles command-line parsing and validation.
//! - **Core Sandboxing**: All heavy lifting is delegated to the `unshare-core` crate.

pub mod adapter;
pub mod parser;
pub mod runner;

pub use adapter::adapt_and_validate;
pub use parser::Cli;

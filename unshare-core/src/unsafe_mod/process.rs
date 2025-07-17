//! # Low-Level Process Operations
//!
//! This module provides safe wrappers for fundamental process management
//! syscalls like `clone` and `fork`. It is responsible for the actual
//! creation of new processes and handles unsafe operations safely.

use crate::fs::open_fds;
use anyhow::{Context, Result as AnyhowResult};
use libc::{SIGCHLD, STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO};
use nix::sched::CloneFlags;
use nix::unistd::{self, Pid};
use std::fs::File;
use std::os::unix::io::AsRawFd;

/// The result of monitoring a child process.
#[derive(Debug, PartialEq, Eq)]
pub enum ChildExitStatus {
    /// The child exited normally with the given code.
    Exited(i32),
    /// The child was terminated by a signal, resulting in the given code.
    Signaled(i32),
    /// The child was stopped. The exit code will be 1.
    Stopped,
    /// An event was received on the event_fd, with the given exit code.
    Event(i32),
}

/// Represents the result of a `fork_with_init` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitForkResult {
    /// The parent process completed its init duties and is ready to exit.
    /// Contains the exit code from the child process.
    ParentExited(i32),
    /// The call returned in the newly created child process.
    Child,
}

const CLONE_STACK_SIZE: usize = 1024 * 1024;

/// Creates a new child process with a specified set of `CLONE_*` flags.
///
/// This function is a wrapper around the `nix::sched::clone` call, which
/// itself is a wrapper for the raw `clone(2)` syscall. It allocates a new
/// stack for the child process and executes a callback in the child.
///
/// # Arguments
///
/// * `flags`: A `nix::sched::CloneFlags` struct specifying which namespaces
///   to create.
/// * `cb`: A boxed closure that the child process will execute. The
///   child process will exit with the return value of this callback.
///
/// # Safety
///
/// The `clone` syscall is unsafe. The caller must ensure that the callback `cb`
/// is safe to be executed in a child process after `clone`. For instance, it
/// should not perform any memory allocations that are not async-signal-safe.
/// The child process is also created with a fixed-size stack of
/// `CLONE_STACK_SIZE` bytes. The caller must ensure that the callback does not
/// overflow this stack.
pub unsafe fn clone(
    flags: CloneFlags,
    cb: Box<dyn FnMut() -> isize + Send + 'static>,
) -> Result<Pid, nix::Error> {
    let mut stack = vec![0u8; CLONE_STACK_SIZE];
    let pid = unsafe { nix::sched::clone(cb, &mut stack, flags, Some(SIGCHLD))? };
    Ok(pid)
}

/// Safely forks a process for PID namespace init process management.
///
/// This function encapsulates the unsafe fork operation along with the necessary
/// file descriptor cleanup and init process management. It implements the
/// critical pattern used in sandboxing where the parent process becomes a
/// lightweight init system to properly reap zombie processes.
pub fn fork_with_init<F>(event_file: Option<File>, do_init_fn: F) -> AnyhowResult<InitForkResult>
where
    F: FnOnce(Option<File>, Pid) -> AnyhowResult<i32>,
{
    unsafe {
        match unistd::fork() {
            Ok(unistd::ForkResult::Parent { child: pid }) => {
                // The parent of the final command becomes an init-like process
                let mut dont_close = vec![STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO];
                if let Some(file) = &event_file {
                    dont_close.push(file.as_raw_fd());
                }

                // Close all other open file descriptors.
                if let Ok(fds) = open_fds() {
                    for fd in fds.flatten() {
                        if !dont_close.contains(&fd) {
                            // Errors are ignored, as we want to try closing all fds.
                            let _ = unistd::close(fd);
                        }
                    }
                }

                // This process now becomes the reaper for the sandboxed command
                let exit_code = do_init_fn(event_file, pid)?;
                Ok(InitForkResult::ParentExited(exit_code))
            }
            Ok(unistd::ForkResult::Child) => {
                // Continue in child - no file descriptor cleanup needed here
                // as the child will continue with normal execution
                Ok(InitForkResult::Child)
            }
            Err(e) => Err(e).context("Can't fork for pid 1"),
        }
    }
}

/// A safe wrapper around the `clone` syscall that separates parent and child logic.
///
/// This function encapsulates the `unsafe` `clone` operation. It creates a new
/// process and executes a `child_fn` in it. The `parent_fn` is executed in
/// the original process. This avoids the need for the caller to handle the
/// raw return value of `clone`.
///
/// # Arguments
///
/// * `flags`: `CloneFlags` to specify the namespaces for the new process.
/// * `parent_fn`: A closure that takes the child's `Pid` and runs in the parent.
/// * `child_fn`: A closure that runs in the newly created child process. It must
///   be `'static` as it will be executed in a new thread of execution.
///
/// # Returns
///
/// An `anyhow::Result` wrapping the exit code from the parent's execution path.
/// Errors from `clone` or the parent's logic are propagated. Errors from the
/// child are handled internally by printing a message and exiting.
pub fn run_forked<P, C>(flags: CloneFlags, parent_fn: P, mut child_fn: C) -> AnyhowResult<i32>
where
    P: FnOnce(Pid) -> AnyhowResult<i32>,
    C: FnMut() -> AnyhowResult<i32> + Send + 'static,
{
    let child_closure: Box<dyn FnMut() -> isize + Send + 'static> =
        Box::new(move || match child_fn() {
            Ok(exit_code) => exit_code as isize,
            Err(err) => {
                eprintln!("unshare child process failed: {err:?}");
                1
            }
        });

    // The `clone` function is `unsafe`. We are wrapping it here to provide a
    // safer abstraction. The primary safety concerns are ensuring the child
    // has a valid stack and that the child's code is safe to run, but we
    // can only guarantee that the child code is safe to run up to the point
    // that it spawns the user provided program.
    let child_pid =
        unsafe { clone(flags, child_closure) }.with_context(|| "call to clone(2) failed")?;

    // In the parent, execute the parent function. If it fails, we try to
    // clean up by killing the child process.
    parent_fn(child_pid).inspect_err(|_| {
        // Attempt to kill the child process to prevent it from being orphaned.
        // We ignore the result as there isn't much we can do if it fails.
        let _ = nix::sys::signal::kill(child_pid, nix::sys::signal::Signal::SIGKILL);
    })
}

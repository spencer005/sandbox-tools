//! # Parent Process Implementation
//!
//! This module contains all the logic for the parent process in the sandbox.
//! The parent is responsible for monitoring the child process, setting up networking,
//! and handling various synchronization and cleanup tasks.

use crate::{ChildExitStatus, PastaMode, SandboxOptions, handle_die_with_parent};
use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::{SigSet, Signal};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use std::os::unix::io::AsFd;
use std::process::Command;

/// Monitors a child process for exit events and other file descriptor events.
/// This function is a low-level utility that also closes all open file descriptors
/// except for a specified list, making it suitable for use in the parent process
/// after forking.
pub fn monitor_child(child_pid: Pid) -> Result<ChildExitStatus> {
    let mut sigset = SigSet::empty();
    sigset.add(Signal::SIGCHLD);
    sigset.thread_block().context("Can't block SIGCHLD")?;

    let signal_fd = SignalFd::with_flags(&sigset, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK)
        .context("Can't create signalfd")?;

    let mut poll_fds = vec![PollFd::new(signal_fd.as_fd(), PollFlags::POLLIN)];

    loop {
        poll(&mut poll_fds, PollTimeout::NONE).context("poll failed")?;

        // After poll, we try to read from the signal FD.
        // If we get a signal, we loop on waitpid() to reap all children.
        if let Some(_siginfo) = signal_fd.read_signal()? {
            loop {
                match waitpid(child_pid, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::Exited(pid, status)) if pid == child_pid => {
                        return Ok(ChildExitStatus::Exited(status));
                    }
                    Ok(WaitStatus::Signaled(pid, signal, _)) if pid == child_pid => {
                        let exitc = 128 + signal as i32;
                        return Ok(ChildExitStatus::Signaled(exitc));
                    }
                    Ok(WaitStatus::Stopped(pid, _)) if pid == child_pid => {
                        return Ok(ChildExitStatus::Stopped);
                    }
                    Ok(WaitStatus::StillAlive) => break, // No more children to reap.
                    Ok(_) => {}                          // Reaped a different child.
                    Err(Errno::ECHILD) => break,         // No children left.
                    Err(e) => return Err(anyhow::Error::from(e).context("waitpid failed")),
                }
            }
        }
    }
}

/// Main entry point for parent process execution.
///
/// This function contains all the logic for the parent process after the `clone()` call.
/// It handles privilege management, networking setup, and child monitoring.
pub fn parent_process(sandbox_options: &SandboxOptions, child_pid: Pid) -> Result<i32> {
    // In unprivileged mode, the child process handles its own UID/GID mapping
    // No synchronization needed - child can proceed immediately

    // Privilege dropping is not needed in unprivileged mode - security comes from namespaces

    // Optionally bind the lifecycle of this process to its parent
    if sandbox_options.die_with_parent {
        handle_die_with_parent().context("PR_SET_PDEATHSIG failed")?;
    }

    // Setup pasta networking if network namespace is unshared
    if sandbox_options.namespaces.unshare_net {
        setup_pasta_networking(&sandbox_options.pasta_mode, child_pid)?;
    }

    // No FD-based status reporting in simplified mode

    // Monitor the child process and wait for it to exit
    let status_result = monitor_child(child_pid).context("monitor_child failed")?;

    let exit_code = match status_result {
        ChildExitStatus::Exited(status) => status,
        ChildExitStatus::Signaled(exitc) => exitc,
        ChildExitStatus::Stopped => 1,
        ChildExitStatus::Event(exitc) => exitc,
    };

    // No status reporting in simplified mode

    Ok(exit_code)
}

/// Sets up pasta networking for the child process.
///
/// This function configures network isolation using the pasta tool, which provides
/// user-space network virtualization for the sandboxed process.
fn setup_pasta_networking(pasta_mode: &PastaMode, child_pid: Pid) -> Result<()> {
    let mut pasta_args = vec!["--config-net".to_string()];

    match pasta_mode {
        PastaMode::Transparent => {
            // Transparent mode - copy host network configuration, let pasta auto-detect DNS
            pasta_args.extend([
                "--no-dhcp".to_string(),
                "--no-dhcpv6".to_string(),
                "--no-ndp".to_string(),
                "--no-ra".to_string(),
                "--no-map-gw".to_string(),
            ]);
        }
        PastaMode::LoopbackOnly => {
            // Loopback-only mode - block all external connectivity
            pasta_args.extend([
                "--no-dhcp".to_string(),
                "--no-dhcpv6".to_string(),
                "--no-ndp".to_string(),
                "--no-ra".to_string(),
                "--no-map-gw".to_string(),
                "--no-tcp".to_string(),
                "--no-udp".to_string(),
                "--no-icmp".to_string(),
            ]);
        }
    }

    // Add the target PID

    pasta_args.push(child_pid.to_string());

    let output = Command::new("pasta")
        .args(&pasta_args)
        .output()
        .context("Failed to execute pasta command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!(
            "Pasta failed with exit code {}: {}",
            output.status,
            stderr
        ));
    }

    Ok(())
}

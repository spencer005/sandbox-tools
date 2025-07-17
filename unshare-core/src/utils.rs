//! Miscellaneous utility functions
use nix::{
    Result,
    sys::{
        prctl,
        signal::{SigSet, Signal},
        wait::WaitStatus,
    },
};

/// Sets the parent death signal to SIGKILL, so that the child process will
/// be killed if the parent dies unexpectedly.
pub fn handle_die_with_parent() -> Result<()> {
    prctl::set_pdeathsig(Some(Signal::SIGKILL))
}

/// Unblocks the `SIGCHLD` signal for the current thread.
///
/// This is typically used in a child process after a `fork` to ensure that
/// `SIGCHLD` signals from its own children (if any) are delivered,
/// especially if they might have been blocked in the parent process.
pub fn unblock_sigchild() -> Result<()> {
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGCHLD);
    mask.thread_unblock()
}

/// Handle exit status
pub fn propagate_exit_status(status: WaitStatus) -> i32 {
    match status {
        WaitStatus::Exited(_, exit_code) => exit_code,
        WaitStatus::Signaled(_, signal, _) => 128 + signal as i32,
        _ => 1, // Covers stopped and other cases
    }
}

//! # Filesystem Utilities

use nix::Result as NixResult;
use nix::dir::{Dir, OwningIter};
use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use std::os::unix::io::{AsRawFd, RawFd};

/// An iterator over the open file descriptors of the current process.
///
/// This iterator safely reads from `/proc/self/fd`. It abstracts away the
/// details of directory traversal and file descriptor parsing.
///
/// The iterator yields `Result<RawFd, nix::Error>`, allowing the caller to
/// handle any I/O or parsing errors that might occur.
pub struct OpenFds {
    iter: OwningIter,
    dir_fd: RawFd,
}

/// Creates a new iterator over the process's open file descriptors.
///
/// This function opens `/proc/self/fd` and returns an `OpenFds` iterator.
/// The file descriptor for `/proc/self/fd` itself is not included in the
/// iteration, preventing the iterator from trying to close its own source.
pub fn open_fds() -> NixResult<OpenFds> {
    let dir = Dir::open(
        "/proc/self/fd",
        OFlag::O_RDONLY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;
    // We need the directory's own FD to ensure we don't close it while iterating.
    let dir_fd = dir.as_raw_fd();
    // into_iter consumes the Dir, returning an OwningIter, which avoids lifetime issues.
    let iter = dir.into_iter();
    Ok(OpenFds { iter, dir_fd })
}

impl Iterator for OpenFds {
    type Item = NixResult<RawFd>;

    fn next(&mut self) -> Option<Self::Item> {
        for entry_result in &mut self.iter {
            // If there was an error reading the directory, yield it and stop.
            let entry = match entry_result {
                Ok(e) => e,
                Err(e) => return Some(Err(e)),
            };

            // We are not interested in the `.` or `..` entries.
            let file_name = entry.file_name().to_string_lossy();
            if file_name == "." || file_name == ".." {
                continue;
            }

            // Attempt to parse the filename as a file descriptor (an integer).
            // If it's a valid FD and not the one for the `/proc/self/fd` directory
            // itself, yield it.
            if let Ok(fd) = file_name.parse::<RawFd>()
                && fd != self.dir_fd
            {
                return Some(Ok(fd));
            }
        }
        None
    }
}

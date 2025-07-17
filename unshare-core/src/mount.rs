//! # Filesystem Mounting and Operations
//!
//! This module provides a comprehensive suite of tools for managing filesystem
//! operations within the sandbox. It unifies the logic for defining mount
//! operations (`MountOp`) and executing them, including complex bind mounts.

// Library Imports
use anyhow::{Context, Result, anyhow};
use libc;
use nix::fcntl::{AtFlags, OFlag, openat};
use nix::mount::{MsFlags, mount};
use nix::sys::stat::{self as nix_stat, Mode};
use nix::unistd;
use std::ffi::OsStr;
use std::os::unix::io::BorrowedFd;
use std::path::{Path, PathBuf};

use crate::SandboxOptions;
use crate::unsafe_mod::selinux::label_mount;

type BindOption = u32;
const BIND_READONLY: u32 = 1 << 0;
const BIND_DEVICES: u32 = 1 << 2;
const BIND_RECURSIVE: u32 = 1 << 3;

const DEV_NODES: &[&str] = &["null", "zero", "full", "random", "urandom", "tty"];
const DEV_SYMLINKS: &[(&str, &str)] = &[
    ("stdin", "/proc/self/fd/0"),
    ("stdout", "/proc/self/fd/1"),
    ("stderr", "/proc/self/fd/2"),
    ("fd", "/proc/self/fd"),
];

/// Defines a single mount or filesystem operation to be performed during setup.
#[derive(Debug, Clone)]
pub enum MountOp {
    BindMount {
        source: PathBuf,
        dest: PathBuf,
        readonly: bool,
        devices: bool,
        allow_not_exist: bool,
    },
    RemountRoNoRecursive {
        dest: PathBuf,
    },
    MountProc {
        dest: PathBuf,
    },
    MountDev {
        dest: PathBuf,
    },
    MountTmpfs {
        dest: PathBuf,
    },
    MountMqueue {
        dest: PathBuf,
    },
    MakeDir {
        dest: PathBuf,
    },
    MakeSymlink {
        source_text: String,
        dest: PathBuf,
    },
    Chmod {
        path: PathBuf,
        perms: u32,
    },
}

/// Represents the options for a bind mount operation.
impl MountOp {
    /// Executes a single mount or filesystem operation.
    pub fn run(&self, sandbox_options: &SandboxOptions, newroot_fd: BorrowedFd<'_>) -> Result<()> {
        match self {
            MountOp::BindMount {
                source,
                dest,
                readonly,
                devices,
                allow_not_exist,
            } => {
                if !source.exists() {
                    if *allow_not_exist {
                        return Ok(());
                    }
                    return Err(anyhow!("Source {source:?} for bind mount does not exist."));
                }
                let final_dest = strip_root_prefix(dest);
                if source.is_dir() {
                    create_dir_all_at(newroot_fd, final_dest, Mode::from_bits(0o755).unwrap())?;
                } else {
                    ensure_parent_dir_at(newroot_fd, final_dest)?;
                    // Create the file if it doesn't exist.
                    let fd = openat(
                        newroot_fd,
                        final_dest,
                        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_CLOEXEC,
                        Mode::from_bits(0o644).unwrap(),
                    )?;
                    // We only needed to create the file, so we can close it immediately.
                    unistd::close(fd)?;
                }
                let mut bind_flags = BIND_RECURSIVE;
                if *readonly {
                    bind_flags |= BIND_READONLY;
                }
                if *devices {
                    bind_flags |= BIND_DEVICES;
                }
                bind_mount(Some(source), final_dest, bind_flags).with_context(|| {
                    format!(
                        "Can't bind mount {} on {}",
                        source.display(),
                        final_dest.display()
                    )
                })?;
            }

            MountOp::RemountRoNoRecursive { dest } => {
                let final_dest = strip_root_prefix(dest);
                // Note: BIND_RECURSIVE is not set here.
                bind_mount(None, final_dest, BIND_READONLY).with_context(|| {
                    format!("Can't remount readonly on {}", final_dest.display())
                })?;
            }

            MountOp::MountProc { dest } => {
                let final_dest = strip_root_prefix(dest);
                run_mount_proc(final_dest, newroot_fd)?;
            }

            MountOp::MountDev { dest } => {
                let final_dest = strip_root_prefix(dest);
                run_mount_dev(final_dest, sandbox_options, newroot_fd)?;
            }

            MountOp::MountTmpfs { dest } => {
                let final_dest = strip_root_prefix(dest);
                create_dir_all_at(newroot_fd, final_dest, Mode::from_bits(0o755).unwrap())?;
                let data = format!("mode=0{:o}", 0o755);
                let final_data = label_mount(Some(&data), sandbox_options.file_label.as_deref())
                    .context("Failed to process mount label")?
                    .unwrap_or(data);
                mount_fs(
                    final_dest,
                    Some(Path::new("tmpfs")),
                    Some(Path::new("tmpfs")),
                    MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
                    Some(final_data.as_str()),
                    "Can't mount tmpfs",
                )?;
            }

            MountOp::MountMqueue { dest } => {
                let final_dest = strip_root_prefix(dest);
                create_dir_all_at(newroot_fd, final_dest, Mode::from_bits(0o755).unwrap())?;
                mount_fs(
                    final_dest,
                    Some(Path::new("mqueue")),
                    Some(Path::new("mqueue")),
                    MsFlags::empty(),
                    None,
                    "Can't mount mqueue",
                )?;
            }

            MountOp::MakeDir { dest } => {
                let final_dest = strip_root_prefix(dest);
                create_dir_all_at(newroot_fd, final_dest, Mode::from_bits(0o755).unwrap())
                    .with_context(|| format!("Can't create directory {}", final_dest.display()))?;
            }

            MountOp::MakeSymlink { source_text, dest } => {
                let final_dest = strip_root_prefix(dest);
                ensure_parent_dir_at(newroot_fd, final_dest)?;
                unistd::symlinkat(OsStr::new(source_text), newroot_fd, final_dest).with_context(
                    || {
                        format!(
                            "Can't make symlink from {} to {}",
                            source_text,
                            final_dest.display()
                        )
                    },
                )?;
            }

            MountOp::Chmod { path, perms } => {
                let final_path = strip_root_prefix(path);
                let mode = Mode::from_bits(*perms as nix_stat::mode_t)
                    .context("Invalid permission bits")?;
                nix_stat::fchmodat(
                    newroot_fd,
                    final_path,
                    mode,
                    nix_stat::FchmodatFlags::FollowSymlink,
                )
                .with_context(|| format!("Can't set permissions on {}", final_path.display()))?;
            }
        }
        Ok(())
    }
}

/// Performs a bind mount operation, with support for remounting with different flags.
///
/// This function implements a two-step process:
/// 1. An initial `mount` syscall with `MS_BIND` to create the bind mount.
/// 2. A second `mount` syscall with `MS_REMOUNT` to apply additional flags
///    (e.g., `MS_RDONLY`, `MS_NODEV`). This is the standard way to change mount
///    options on an existing mount point.
///
/// This approach is more flexible than a single mount call. However, as seen
/// with `/dev/console`, the remount step can fail on special files.
pub fn bind_mount(src: Option<&Path>, dest: &Path, options: BindOption) -> Result<()> {
    let readonly = (options & BIND_READONLY) != 0;
    let devices = (options & BIND_DEVICES) != 0;
    let recursive = (options & BIND_RECURSIVE) != 0;
    let mut mount_flags = MsFlags::MS_SILENT | MsFlags::MS_BIND;
    if recursive {
        mount_flags |= MsFlags::MS_REC;
    }
    if let Some(src_path) = src {
        mount(
            Some(src_path),
            dest,
            None::<&Path>,
            mount_flags,
            None::<&str>,
        )
        .with_context(|| {
            format!(
                "Unable to mount {} on {}",
                src.map_or("none".to_string(), |p| p.display().to_string()),
                dest.display()
            )
        })?;
    }

    remount_with_flags(dest, readonly, devices, recursive)
        .with_context(|| format!("Unable to apply mount flags: remount {}", dest.display()))?;

    Ok(())
}

fn run_mount_proc(dest: &Path, newroot_fd: BorrowedFd<'_>) -> Result<()> {
    create_dir_all_at(newroot_fd, dest, Mode::from_bits(0o755).unwrap())?;
    mount_fs(
        dest,
        Some(Path::new("proc")),
        Some(Path::new("proc")),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        None,
        "Can't mount procfs",
    )?;
    // Note: We do not attempt to bind mount subdirectories of /proc (e.g., /proc/sys)
    // as read-only. The kernel often disallows this, leading to EPERM errors.
    // The new /proc mount is sufficient for isolation.
    Ok(())
}

fn run_mount_dev(
    dest: &Path,
    sandbox_options: &SandboxOptions,
    newroot_fd: BorrowedFd<'_>,
) -> Result<()> {
    create_dir_all_at(newroot_fd, dest, Mode::from_bits(0o755).unwrap())?;
    let data = "mode=0755".to_string();
    let final_data = label_mount(Some(&data), sandbox_options.file_label.as_deref())
        .context("Failed to process mount label for /dev tmpfs")?
        .unwrap_or(data);
    mount_fs(
        dest,
        Some(Path::new("tmpfs")),
        Some(Path::new("tmpfs")),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(&final_data),
        "Can't mount tmpfs for /dev",
    )?;

    for node in DEV_NODES {
        let node_dest = dest.join(node);
        let fd = openat(
            newroot_fd,
            &node_dest,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_CLOEXEC,
            Mode::from_bits(0o666).unwrap(),
        )?;
        unistd::close(fd)?;

        bind_mount(
            Some(&Path::new("/dev").join(node)),
            &node_dest,
            BIND_DEVICES | BIND_RECURSIVE,
        )
        .with_context(|| format!("Can't bind mount /dev/{} on {}", node, node_dest.display()))?;
    }

    for (name, target) in DEV_SYMLINKS {
        let link_path = dest.join(name);
        unistd::symlinkat(OsStr::new(target), newroot_fd, &link_path)
            .with_context(|| format!("Can't create symlink {}", link_path.display()))?;
    }

    let pts = dest.join("pts");
    create_dir_all_at(newroot_fd, &pts, Mode::from_bits(0o755).unwrap())?;
    create_dir_all_at(
        newroot_fd,
        &dest.join("shm"),
        Mode::from_bits(0o755).unwrap(),
    )?;

    mount(
        Some(Path::new("devpts")),
        &pts,
        Some(Path::new("devpts")),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666,mode=620"),
    )
    .with_context(|| format!("Can't mount devpts on {}", pts.display()))?;

    unistd::symlinkat("pts/ptmx", newroot_fd, &dest.join("ptmx"))
        .context("Can't make symlink at /dev/ptmx")?;

    if let Some(host_tty) = &sandbox_options.host_tty_dev_path {
        let dest_console = dest.join("console");
        let fd = openat(
            newroot_fd,
            &dest_console,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_CLOEXEC,
            Mode::from_bits(0o666).unwrap(),
        )?;
        unistd::close(fd)?;
        // Special handling for the console device. A standard `bind_mount` fails
        // on a TTY device because its remount operation (to apply flags like
        // MS_NODEV) is not permitted by the kernel (`EPERM`). We must perform
        // a simple, direct bind mount without any additional flags.
        mount(
            Some(&PathBuf::from(host_tty)),
            &dest_console,
            None::<&Path>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .with_context(|| {
            format!(
                "Can't bind mount {} on {}",
                host_tty,
                dest_console.display()
            )
        })?;
    }
    Ok(())
}

fn strip_root_prefix(path: &Path) -> &Path {
    path.strip_prefix("/").unwrap_or(path)
}

fn mount_fs(
    dest: &Path,
    source: Option<&Path>,
    fstype: Option<&Path>,
    flags: MsFlags,
    data: Option<&str>,
    context_msg: &str,
) -> Result<()> {
    mount(source, dest, fstype, flags, data)
        .with_context(|| format!("{} on {}", context_msg, dest.display()))
}

fn remount_with_flags(
    dest: &Path,
    readonly: bool,
    devices: bool,
    recursive: bool,
) -> Result<(), nix::Error> {
    let mut new_ms_flags = MsFlags::MS_NOSUID;
    if !devices {
        new_ms_flags |= MsFlags::MS_NODEV;
    }
    if readonly {
        new_ms_flags |= MsFlags::MS_RDONLY;
    }

    let mut remount_flags =
        MsFlags::MS_SILENT | MsFlags::MS_BIND | MsFlags::MS_REMOUNT | new_ms_flags;
    if recursive {
        remount_flags |= MsFlags::MS_REC;
    }

    mount(
        None::<&Path>,
        dest,
        None::<&Path>,
        remount_flags,
        None::<&str>,
    )?;
    Ok(())
}

/// A securely implemented version of `create_dir_all` that operates relative
/// to a base directory file descriptor to prevent Time-of-Check to Time-of-Use
/// (TOCTOU) vulnerabilities and symlink attacks.
fn create_dir_all_at(dirfd: BorrowedFd<'_>, path: &Path, mode: Mode) -> Result<()> {
    let mut current_path = PathBuf::new();
    for component in path.components() {
        if component.as_os_str() == "/" {
            continue;
        }
        current_path.push(component);
        // Skip creating '.'
        if current_path == Path::new(".") {
            continue;
        }
        match nix_stat::mkdirat(dirfd, &current_path, mode) {
            Ok(()) => {}
            Err(nix::Error::EEXIST) => {
                // It's ok if the directory already exists, but fail if it's a file.
                match nix_stat::fstatat(dirfd, &current_path, AtFlags::empty()) {
                    Ok(stat) if (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR => {
                        // This is a directory, so we can continue.
                    }
                    _ => {
                        return Err(anyhow!(
                            "Failed to create directory {:?}: path component is not a directory",
                            path
                        ));
                    }
                }
            }
            Err(e) => {
                return Err(anyhow!(e))
                    .with_context(|| format!("Failed to create directory {current_path:?}"));
            }
        }
    }
    Ok(())
}

/// Securely ensures that the parent directory of a given path exists, creating it
/// if necessary. All operations are relative to a base directory file descriptor.
fn ensure_parent_dir_at(dirfd: BorrowedFd<'_>, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        create_dir_all_at(dirfd, parent, Mode::from_bits(0o755).unwrap())?;
    }
    Ok(())
}

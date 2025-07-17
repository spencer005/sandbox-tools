//! # Child Process Implementation
//!
//! This module contains all the logic for the child process in the sandbox.
//! It orchestrates the complete setup sequence: namespace initialization, mount setup,
//! and final execution of the target command.

use crate::unsafe_mod::selinux::set_exec_context;
use crate::unsafe_mod::{InitForkResult, SeccompProgram, fork_with_init, seccomp_programs_apply};
use crate::{
    MountOp, SandboxOptions, handle_die_with_parent, propagate_exit_status, unblock_sigchild,
    users::{self, UserIds},
};
use anyhow::{Context, Result};
use tempfile::Builder as TempFileBuilder;

use nix::{
    dir::Dir,
    errno::Errno,
    fcntl::OFlag,
    mount::{MntFlags, MsFlags, mount, umount2},
    sys::stat::Mode,
    sys::wait::{WaitStatus, wait},
    unistd::{self, Gid, Pid, Uid},
};

use std::{
    env,
    fs::{self, DirBuilder},
    io::Write,
    os::unix::{
        fs::DirBuilderExt,
        io::{AsFd, BorrowedFd},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::Command,
};

/// Main entry point for child process execution.
///
/// This function orchestrates the complete child process setup within the new namespaces
/// and returns a Result to propagate any errors that occur.
pub fn child_process(
    sandbox_options: &SandboxOptions,
    user_ids: &UserIds,
    argv: &[String],
    mount_ops: Vec<MountOp>,
    seccomp_programs: Vec<SeccompProgram>,
) -> Result<i32> {
    // --- Start of inlined child_init_namespace logic ---
    if sandbox_options.namespaces.unshare_user {
        let mut sandbox_uid = sandbox_options.sandbox_uid;
        let mut sandbox_gid = sandbox_options.sandbox_gid;
        if sandbox_options.needs_devpts {
            sandbox_uid = Some(Uid::from_raw(0));
            sandbox_gid = Some(Gid::from_raw(0));
        }

        // We are the child, so we write to /proc/self/*
        // This must happen in the child process for unprivileged user namespaces
        let config = users::UidGidMapConfig {
            parent_uid: user_ids.real_uid,
            sandbox_uid: sandbox_uid.expect("sandbox_uid should have been set by the adapter"),
            parent_gid: user_ids.real_gid,
            sandbox_gid: sandbox_gid.expect("sandbox_gid should have been set by the adapter"),
            overflow_uid: user_ids.overflow_uid,
            overflow_gid: user_ids.overflow_gid,
            deny_groups: true, // Always deny setgroups in a new user namespace
            map_root: sandbox_options.needs_devpts,
        };
        config.write_map(None)?;
    }

    // Set NO_NEW_PRIVS, and drop privileges to the real user ID.
    // This must be done after UID mapping but before other setup.
    users::switch_to_user(
        sandbox_options.no_new_privs,
        sandbox_options.namespaces.unshare_user,
        user_ids.real_uid,
        user_ids.real_gid,
    )
    .context("Failed to switch user")?;
    // --- End of inlined child_init_namespace logic ---

    // Set up the new root filesystem and all the mounts
    let old_cwd = mount_setup(mount_ops, sandbox_options)?;

    // Finish the final setup steps and execute the user's command
    finish_setup_and_exec(sandbox_options, &old_cwd, argv, &seccomp_programs)
}

/// Sets up the new root filesystem by creating mounts and pivoting root.
///
/// This handles the core sandbox setup, including creating the new root filesystem,
/// performing mounts, and pivoting the root.
fn mount_setup(mount_ops: Vec<MountOp>, sandbox_options: &SandboxOptions) -> Result<PathBuf> {
    // Create a temporary directory that will serve as the mount point for our new root.
    // This directory is created on the host filesystem and will be leaked, but using
    // tempfile avoids collisions with a hardcoded path.
    let temp_dir = TempFileBuilder::new()
        .prefix("unshare-newroot-")
        .tempdir_in("/tmp")
        .context("Failed to create temporary directory for new root")?;
    let temp_newroot_path = temp_dir.keep();

    // This path must be relative to the CWD, which will be the tmpfs mount
    let oldroot_path_relative = Path::new("oldroot");
    // After the pivot, this is where the old root will be mounted
    let oldroot_path_absolute = Path::new("/oldroot");

    // Mark / as private, so we don't receive mounts from the real root
    mount(
        None::<&Path>,
        Path::new("/"),
        None::<&Path>,
        MsFlags::MS_PRIVATE,
        None::<&Path>,
    )
    .context("Failed to make / private")?;

    // Create a tmpfs which we will use as / in the namespace
    mount(
        Some(Path::new("tmpfs")),
        &temp_newroot_path,
        Some(Path::new("tmpfs")),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID,
        None::<&Path>,
    )
    .context("Failed to mount tmpfs on newroot")?;

    // Safely open the new root directory to get a file descriptor handle.
    // This is used as the root for all subsequent path-based operations
    // to prevent symlink-based attacks.
    let newroot_dir = Dir::open(
        &temp_newroot_path,
        OFlag::O_DIRECTORY | OFlag::O_RDONLY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .context("Failed to open newroot for setup")?;

    // Get current working directory before chdir
    let old_cwd = env::current_dir().context("Failed to get current working directory")?;

    // Chdir to the new root tmpfs mount
    env::set_current_dir(&temp_newroot_path).context("Failed to chdir to newroot")?;

    // Set up all the mounts in the new root, contained within newroot_dir
    setup_newroot(mount_ops, sandbox_options, newroot_dir.as_fd())?;

    // Create the directory for the old root inside the tmpfs
    DirBuilder::new()
        .mode(0o755)
        .create(oldroot_path_relative)
        .context("Creating oldroot failed")?;

    // Pivot root. The CWD ('.') becomes the new root, and the old root is mounted
    // on top of `oldroot_path_relative`
    unistd::pivot_root(Path::new("."), oldroot_path_relative).context("pivot_root failed")?;

    // The old root is now at the absolute path from the new root
    // The old root better be rprivate or we will send unmount events to the parent namespace
    mount(
        Some(oldroot_path_absolute),
        oldroot_path_absolute,
        None::<&Path>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&Path>,
    )
    .context("Failed to make old root rprivate")?;

    umount2(oldroot_path_absolute, MntFlags::MNT_DETACH).context("unmount old root")?;
    fs::remove_dir(oldroot_path_absolute).context("Failed to remove oldroot directory")?;

    Ok(old_cwd)
}

/// Sets up the new root filesystem by iterating through the `mount_ops`
/// and executing them directly in the user namespace.
fn setup_newroot(
    mount_ops: Vec<MountOp>,
    sandbox_options: &SandboxOptions,
    newroot_fd: BorrowedFd<'_>,
) -> Result<()> {
    for mount_op in mount_ops {
        mount_op.run(sandbox_options, newroot_fd)?;
    }
    Ok(())
}

/// Handles the final steps before executing the user's command, after
/// all namespace and mount setup is complete.
fn finish_setup_and_exec(
    options: &SandboxOptions,
    old_cwd: &Path,
    argv: &[String],
    seccomp_programs: &[SeccompProgram],
) -> Result<i32> {
    // The umask is read by setting a new umask, and then immediately restoring
    // the original value.
    let old_umask = nix::sys::stat::umask(nix::sys::stat::Mode::from_bits(0).unwrap());
    nix::sys::stat::umask(old_umask);

    // Change directory if requested
    if let Some(path) = &options.chdir {
        env::set_current_dir(path)
            .with_context(|| format!("Can't chdir to specified path {}", path.display()))?;
    } else if env::set_current_dir(old_cwd).is_err() {
        // Fallback to $HOME if chdir to original CWD fails
        if let Ok(home) = env::var("HOME") {
            let _ = env::set_current_dir(home);
        }
    }

    // Create a new terminal session if requested
    if options.new_session {
        unistd::setsid().context("setsid failed")?;
    }

    // Apply SELinux label if specified
    set_exec_context(options.exec_label.as_deref()).context("Failed to set SELinux exec label")?;

    // If not running as pid 1, we fork, and the parent becomes an init
    // process that waits for the final child. This is needed for --sync-fd,
    // locking, etc.
    if !options.as_pid_1 && options.namespaces.unshare_pid {
        let init_logic = |mut event_file: Option<std::fs::File>, initial_pid: Pid| -> Result<i32> {
            let mut initial_exit_status = 1;
            let mut initial_child_exited = false;

            handle_die_with_parent()?;

            // As PID 1, we must reap all children until none are left.
            loop {
                match wait() {
                    Ok(status @ (WaitStatus::Exited(pid, _) | WaitStatus::Signaled(pid, _, _))) => {
                        // If this is the first time we're seeing the initial child exit,
                        // record its exit status. We don't exit here, because we must
                        // continue to reap any other children.
                        if pid == initial_pid && !initial_child_exited {
                            initial_exit_status = propagate_exit_status(status);
                            initial_child_exited = true;

                            if let Some(file) = event_file.as_mut() {
                                let val: u64 =
                                    u64::from(initial_exit_status as u32).wrapping_add(1);
                                let val_bytes = val.to_ne_bytes();

                                if let Err(e) = file.write_all(&val_bytes) {
                                    eprintln!("warning: failed to write to event_fd: {e}");
                                }
                            }
                        }
                    }
                    Ok(_) => {
                        // A child was stopped, continued, etc. We don't care, just keep waiting.
                        continue;
                    }
                    Err(Errno::EINTR) => {
                        // Interrupted by signal, continue waiting
                        continue;
                    }
                    Err(Errno::ECHILD) => {
                        // No more child processes. This is the correct exit condition for an init process.
                        break;
                    }
                    Err(e) => {
                        return Err(e).context("init wait() failed");
                    }
                }
            }
            Ok(initial_exit_status)
        };

        match fork_with_init(None, init_logic)? {
            InitForkResult::ParentExited(exit_code) => {
                return Ok(exit_code);
            }
            InitForkResult::Child => {
                // Continue in child process
            }
        }
    }

    // Final signal and parent-death handling
    unblock_sigchild()?;
    if options.die_with_parent {
        handle_die_with_parent()?;
    }

    // Add or drop capabilities if requested. This should be done after becoming root
    // in the user namespace but before exec.
    if !options.cap_add.is_empty() || !options.cap_drop.is_empty() {
        capng::get_caps_process().context("Failed to get process capabilities")?;

        if !options.cap_add.is_empty() {
            let caps_to_add: Vec<&str> = options.cap_add.iter().map(AsRef::as_ref).collect();
            capng::updatev(
                capng::Action::ADD,
                capng::Type::EFFECTIVE
                    | capng::Type::PERMITTED
                    | capng::Type::INHERITABLE
                    | capng::Type::BOUNDING_SET,
                caps_to_add,
            )
            .context("Failed to add capabilities")?;
        }

        if !options.cap_drop.is_empty() {
            let caps_to_drop: Vec<&str> = options.cap_drop.iter().map(AsRef::as_ref).collect();
            capng::updatev(
                capng::Action::DROP,
                capng::Type::EFFECTIVE
                    | capng::Type::PERMITTED
                    | capng::Type::INHERITABLE
                    | capng::Type::BOUNDING_SET,
                caps_to_drop,
            )
            .context("Failed to drop capabilities")?;
        }

        capng::apply(capng::Set::BOTH).context("Failed to apply capabilities")?;
    }

    // Apply seccomp filters. This must be one of the last things we do
    seccomp_programs_apply(seccomp_programs)?;

    // Prepare arguments for exec
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);

    // --- Environment Setup ---
    if options.env.clearenv {
        command.env_clear();
    }

    for var in &options.env.unsetenv {
        command.env_remove(var);
    }

    for pair in options.env.setenv.chunks(2) {
        if pair.len() == 2 {
            command.env(&pair[0], &pair[1]);
        }
    }

    if let Some(argv0_str) = &options.argv0 {
        command.arg0(argv0_str);
    } else {
        command.arg0(&argv[0]);
    }

    // The unsafe env::set_var is removed. We now set PWD here safely for the new process.
    if let Ok(pwd) = env::current_dir() {
        command.env("PWD", pwd);
    }

    // Execute the user's command. This will replace the current process.
    let err = command.exec();

    #[allow(clippy::needless_return)]
    return Err(anyhow::anyhow!("Failed to execute command: {}", err));
}

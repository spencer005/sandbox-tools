//! Integration tests for the rwrap CLI.
//!
//! This suite focuses on verifying the seccomp functionality using a
//! block-list approach, which is a more robust testing strategy than
//! allow-listing.

use anyhow::{Context, Result};
use assert_cmd::prelude::*;
use nix::unistd;
use predicates::prelude::*;
use std::io::{self, Write};
use std::process::Command;
use tempfile::NamedTempFile;

// --- BPF Generation Helpers ---

// BPF instruction classes and modes
const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;

// Seccomp return values
const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
const SECCOMP_RET_KILL: u32 = 0x00000000;

// Syscall numbers for x86_64, from `ausyscall --dump`.
mod syscalls {
    pub const WRITE: u32 = 1;
    pub const UNAME: u32 = 63;
    pub const REBOOT: u32 = 169;
}

/// Creates a single BPF instruction as a byte vector.
fn bpf_ins(opcode: u16, jt: u8, jf: u8, k: u32) -> Vec<u8> {
    let mut instruction = Vec::with_capacity(8);
    instruction.extend_from_slice(&opcode.to_le_bytes());
    instruction.push(jt);
    instruction.push(jf);
    instruction.extend_from_slice(&k.to_le_bytes());
    instruction
}

/// Generates a seccomp filter that blocks a specific list of syscalls.
/// All other syscalls are allowed.
fn generate_bpf_block_filter(blocked_syscalls: &[u32]) -> Vec<u8> {
    let mut instructions = Vec::new();

    // 1. Load the syscall number into the accumulator.
    instructions.extend(bpf_ins(BPF_LD | BPF_W | BPF_ABS, 0, 0, 0));

    // 2. For each syscall in the block-list, add a check.
    //    If the syscall number matches, jump to the KILL instruction.
    let n = blocked_syscalls.len();
    for (i, &syscall) in blocked_syscalls.iter().enumerate() {
        // The jump-if-true offset is relative to the instruction *following* the jump.
        // If a syscall matches, we jump to the final `RET KILL` instruction.
        // The number of instructions to jump over is the number of remaining `JEQ`
        // checks plus the `RET ALLOW` instruction. After the i-th check, there are
        // `(n - 1 - i)` checks left. So, the total offset is `(n - 1 - i) + 1 = n - i`.
        let jump_if_true = (n - i) as u8;

        instructions.extend(bpf_ins(
            BPF_JMP | BPF_JEQ | BPF_K,
            jump_if_true,
            0, // if false, fall through to the next check
            syscall,
        ));
    }

    // 3. If no match was found, allow the syscall. This is the default action.
    instructions.extend(bpf_ins(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW));

    // 4. This is the target for all jumps. If a syscall is blocked, we land here.
    instructions.extend(bpf_ins(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL));

    instructions
}

/// Creates a temporary file with the given BPF filter data.
fn create_bpf_file(filter_data: &[u8]) -> Result<NamedTempFile> {
    let mut file = NamedTempFile::new()?;
    file.write_all(filter_data)?;
    file.flush()?;
    Ok(file)
}

/// Creates a base rwrap command with common sandbox setup arguments.
fn sandboxed_cmd() -> Command {
    let mut cmd = Command::cargo_bin("rwrap").expect("rwrap binary not found");
    cmd.arg("--unshare-user")
        // Bind host utilities into the sandbox for testing purposes
        .arg("--ro-bind")
        .arg("/run/current-system/sw/bin")
        .arg("/bin")
        .arg("--ro-bind")
        .arg("/nix")
        .arg("/nix")
        .arg("--ro-bind")
        .arg("/run")
        .arg("/run")
        .arg("--dir")
        .arg("/tmp");
    cmd
}

// --- Test Cases ---

#[test]
fn test_block_unrelated_syscall_succeeds() -> Result<()> {
    // Block the `reboot` syscall (169), which `echo` will not use.
    let filter = generate_bpf_block_filter(&[syscalls::REBOOT]);
    let bpf_file = create_bpf_file(&filter)?;

    sandboxed_cmd()
        .arg("--seccomp")
        .arg(bpf_file.path())
        .arg("/bin/echo")
        .arg("This should succeed")
        .assert()
        .success()
        .stdout(predicate::str::contains("This should succeed"));

    Ok(())
}

#[test]
fn test_block_used_syscall_fails() -> Result<()> {
    // Block the `write` syscall (1), which `echo` must use to print output.
    let filter = generate_bpf_block_filter(&[syscalls::WRITE]);
    let bpf_file = create_bpf_file(&filter)?;

    let output = sandboxed_cmd()
        .arg("--seccomp")
        .arg(bpf_file.path())
        .arg("/bin/echo")
        .arg("This should fail")
        .output()?; // Use .output() to capture the exit status

    // The process should be killed by seccomp for calling a blocked syscall.
    // This results in a non-zero exit code.
    assert!(
        !output.status.success(),
        "Command succeeded when it should have been killed by seccomp."
    );

    Ok(())
}

#[test]
fn test_block_uname_and_run_uname_fails() -> Result<()> {
    // Block the `uname` syscall (63).
    let filter = generate_bpf_block_filter(&[syscalls::UNAME]);
    let bpf_file = create_bpf_file(&filter)?;

    let output = sandboxed_cmd()
        .arg("--seccomp")
        .arg(bpf_file.path())
        .arg("/bin/uname") // This command's primary purpose is to use the `uname` syscall.
        .output()?;

    // The process should be killed by seccomp.
    assert!(
        !output.status.success(),
        "uname command succeeded when its syscall should have been blocked."
    );

    Ok(())
}

// --- Mount Option Tests ---

#[test]
fn test_bind_mount_read() -> Result<()> {
    let mut host_file = NamedTempFile::new()?;
    writeln!(host_file, "hello from host")?;
    let host_path = host_file.path();

    sandboxed_cmd()
        .arg("--bind")
        .arg(host_path)
        .arg("/tmp/testfile")
        .arg("--")
        .arg("/bin/cat")
        .arg("/tmp/testfile")
        .assert()
        .success()
        .stdout(predicate::str::contains("hello from host"));

    Ok(())
}

#[test]
fn test_ro_bind_mount_write_fails() -> Result<()> {
    let host_file = NamedTempFile::new()?;
    let host_path = host_file.path();

    let output = sandboxed_cmd()
        .arg("--ro-bind")
        .arg(host_path)
        .arg("/tmp/testfile")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("echo 'should fail' > /tmp/testfile")
        .output()?;

    assert!(
        !output.status.success(),
        "Command succeeded when it should have failed to write to a read-only mount."
    );

    Ok(())
}

#[test]
fn test_dir_creation() -> Result<()> {
    sandboxed_cmd()
        .arg("--dir")
        .arg("/tmp/newdir")
        .arg("--")
        .arg("/bin/test")
        .arg("-d")
        .arg("/tmp/newdir")
        .assert()
        .success();

    Ok(())
}

#[test]
fn test_symlink_creation() -> Result<()> {
    sandboxed_cmd()
        .arg("--symlink")
        .arg("some_target")
        .arg("/tmp/newlink")
        .arg("--")
        .arg("/bin/readlink")
        .arg("/tmp/newlink")
        .assert()
        .success()
        .stdout(predicate::str::contains("some_target"));

    Ok(())
}

#[test]
fn test_tmpfs_writable() -> Result<()> {
    sandboxed_cmd()
        .arg("--tmpfs")
        .arg("/tmp/mytmpfs")
        .arg("--")
        .arg("/bin/touch")
        .arg("/tmp/mytmpfs/testfile")
        .assert()
        .success();

    Ok(())
}

// --- Environment and User/Group Test Cases ---

#[test]
fn test_setenv_variable_is_set() -> Result<()> {
    sandboxed_cmd()
        .arg("--setenv")
        .arg("MY_VAR")
        .arg("my_value")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("test \"$MY_VAR\" = \"my_value\"")
        .assert()
        .success();

    Ok(())
}

#[test]
fn test_unsetenv_variable_is_not_set() -> Result<()> {
    sandboxed_cmd()
        .env("SHOULD_BE_UNSET", "some_value")
        .arg("--unsetenv")
        .arg("SHOULD_BE_UNSET")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("test -z \"$SHOULD_BE_UNSET\"")
        .assert()
        .success();

    Ok(())
}

#[test]
fn test_clearenv_removes_variables() -> Result<()> {
    sandboxed_cmd()
        .env("SHOULD_BE_CLEARED", "some_value")
        .arg("--clearenv")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("test -z \"$SHOULD_BE_CLEARED\"")
        .assert()
        .success();

    Ok(())
}

#[test]
fn test_uid_changes_user() -> Result<()> {
    sandboxed_cmd()
        .arg("--uid")
        .arg("1000")
        .arg("--")
        .arg("/bin/id")
        .arg("-u")
        .assert()
        .success()
        .stdout(predicate::str::contains("1000"));

    Ok(())
}

#[test]
fn test_gid_changes_group() -> Result<()> {
    sandboxed_cmd()
        .arg("--gid")
        .arg("1000")
        .arg("--")
        .arg("/bin/id")
        .arg("-g")
        .assert()
        .success()
        .stdout(predicate::str::contains("1000"));

    Ok(())
}

#[test]
fn test_dev_mount() -> Result<()> {
    sandboxed_cmd()
        .arg("--dev")
        .arg("/dev")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("test -e /dev/zero && test -e /dev/tty && test -e /dev/null")
        .assert()
        .success();
    Ok(())
}

#[test]
fn test_as_pid_1_runs_as_init() -> Result<()> {
    sandboxed_cmd()
        .arg("--unshare-pid")
        .arg("--as-pid-1")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("test $$ -eq 1")
        .assert()
        .success();
    Ok(())
}

#[test]
fn test_remount_ro_makes_fs_readonly() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let file_path = temp_dir.path().join("testfile");
    std::fs::write(&file_path, "content")?;

    let output = sandboxed_cmd()
        .arg("--bind")
        .arg(temp_dir.path())
        .arg("/tmp/mydir")
        .arg("--remount-ro")
        .arg("/tmp/mydir")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("echo 'should fail' > /tmp/mydir/testfile")
        .output()?;

    assert!(!output.status.success());
    Ok(())
}

#[test]
fn test_proc_mount_succeeds() -> Result<()> {
    sandboxed_cmd()
        .arg("--unshare-pid")
        .arg("--proc")
        .arg("/proc")
        .arg("--")
        .arg("/bin/test")
        .arg("-f")
        .arg("/proc/self/stat")
        .assert()
        .success();
    Ok(())
}

#[test]
fn test_dev_console_mount_succeeds() -> Result<()> {
    // This test will only pass if stdout is a TTY, as rwrap requires it to create /dev/console
    if !atty::is(atty::Stream::Stdout) {
        eprintln!("Skipping test_dev_console_mount because stdout is not a TTY.");
        return Ok(());
    }

    // In the test environment, automatic TTY detection might fail.
    // We explicitly find the TTY path and pass it to rwrap.
    let tty_path = unistd::ttyname(io::stdout())
        .context("Failed to get tty name for stdout")?
        .to_string_lossy()
        .into_owned();

    sandboxed_cmd()
        .arg("--dev")
        .arg("/dev")
        .arg("--host-tty-dev-path")
        .arg(tty_path)
        .arg("--")
        .arg("/bin/test")
        .arg("-e")
        .arg("/dev/console")
        .assert()
        .success();
    Ok(())
}

#[test]
fn test_cap_drop_removes_capabilities() -> Result<()> {
    // This test verifies that capabilities can be dropped using `--cap-drop`.
    // It checks both repeated arguments and comma-separated values.
    // We will drop CAP_SYS_ADMIN (21) and CAP_SYS_CHROOT (18).
    // The expected bounding set is based on the observed value from the test
    // environment to ensure stability.
    let expected_capbnd = "CapBnd:\t000001ffffdbffff";

    // Test with repeated arguments
    sandboxed_cmd()
        .arg("--unshare-pid")
        .arg("--proc")
        .arg("/proc")
        .arg("--uid")
        .arg("0") // become root
        .arg("--cap-drop")
        .arg("SYS_ADMIN")
        .arg("--cap-drop")
        .arg("SYS_CHROOT")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("grep CapBnd /proc/self/status")
        .assert()
        .success()
        .stdout(predicate::str::contains(expected_capbnd));

    // Test with comma-separated values
    sandboxed_cmd()
        .arg("--unshare-pid")
        .arg("--proc")
        .arg("/proc")
        .arg("--uid")
        .arg("0") // become root
        .arg("--cap-drop")
        .arg("SYS_ADMIN,SYS_CHROOT")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("grep CapBnd /proc/self/status")
        .assert()
        .success()
        .stdout(predicate::str::contains(expected_capbnd));

    Ok(())
}

# Sandbox Tools

A Rust implementation of unprivileged user namespaces and related tools for creating secure, isolated environments.

*   `unshare-core`: Provides the core, safe abstractions for working with Linux namespaces.
*   `unshare-unsafe`: Contains the low-level, `unsafe` bindings to the necessary `libc` functions.
*   `unshare-cli`: A command-line utility `rwrap` for creating new namespaces and running commands within them, inspired by bubblewrap but intentionally simpler.

### Installation & Building

1.  Clone the repository:
    ```sh
    git clone https://github.com/spencer005/sandbox-tools.git
    cd sandbox-tools
    nix develop
    cargo build --release
    ./target/release/rwrap --help
    ```

## Usage

The `rwrap` tool allows you to run a command in a new set of namespaces. For example:

```sh
./target/release/rwrap --ro-bind /nix/store /nix/store --ro-bind /run /run --ro-bind /bin/sh /bin/sh --bind ~/fakehomedir /home/$USER --unshare-all /bin/sh
```

This command will create a new user namespace, mount the specified directories as read-only, and run a shell in that isolated environment.

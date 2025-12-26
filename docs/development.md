# Development Guide

This guide covers everything you need to know to build, test, and package **dirLocker**.

## Prerequisites

Before starting, ensure you have the following installed:

- **Go**: Version 1.24 or higher.
- **Rust**: Version 1.70 or higher (via rustup).
- **GCC/MinGW**: Required for CGO compilation.
- **Make**: A standard Make tool (available via Git Bash or MinGW on Windows).

### Windows Specifics

- **go-winres**: For icon embedding (automatically installed by Makefile).
- **Rsrc**: Recommended to have `git bash` or equivalent for running Make commands.

### Linux Specifics

- **Dependencies**: Requires `libsecret-1-dev` and `dbus` headers for the `keyring` crate.
  - Ubuntu/Debian: `sudo apt-get install libsecret-1-dev libdbus-1-dev fuse3 libfuse3-dev`
  - Fedora: `sudo dnf install libsecret-devel dbus-devel fuse3 fuse3-devel`

## Build System

We use a unified `Makefile` for all platforms.

### Standard Build

Compiles all components (Rust core, CLI, GUI):

```bash
make build
# or just 'make'
```

### Component Builds

Build specific parts of the application:

```bash
make build-core   # Helper: builds Rust library
make build-cli    # Builds bin/dirlocker-cli
make build-gui    # Builds bin/dirlocker-gui
```

## Testing

Run the full test suite (Go + Rust):

```bash
make test
```

- **Rust Tests**: Runs `cargo test` inside `vault-core`.

### Windows Specific Testing

When running tests on Windows, ensure your environment is correctly configured:

1.  **Mounting Drivers**: The `TestMountIntegration` requires either **Dokany** or **WinFSP** to be installed. If neither is found, the test will skip securely.
    - _Note_: The test runner verifies the drivers are present before attempting to mount.
2.  **Cross-Compilation Variables**: **DO NOT** set `GOOS=linux` when running tests on Windows.
    - Running `go test` with `GOOS=linux` on Windows will attempt to build and execute Linux binaries, resulting in `%1 is not a valid Win32 application` errors.
    - Ensure `GOOS` is unset (empty) or set to `windows` in your terminal session before testing.
    - _PowerShell_: `$env:GOOS=""`

### CI/CD Environment Notes

When running tests in a CI environment (especially Linux):

1.  **Shared Libraries**: Go tests linking against the Rust core need `LD_LIBRARY_PATH` set to the build output directory (e.g., `vault-core/target/release`).
    - _Example:_ `export LD_LIBRARY_PATH=$PWD/vault-core/target/release:$LD_LIBRARY_PATH`
2.  **PATH Handling**: Avoid overwriting `PATH` in `env` blocks as it might remove system tools like `gcc`. Append/Prepend in the `run` script instead.
    - _Correct:_ `export PATH=$PWD/bin:$PATH`
3.  **DBus**: Use `dbus-run-session` for headless environments to support secret service integration.

## Packaging & Distribution

We support native packaging for major platforms.

### Windows

The standard build (`make build-gui`) automatically handles:

1.  Icon embedding via `go-winres`.
2.  Metadata generation (version info, description).
3.  `.exe` creation.

### Linux

Create a portable Linux distribution structure:

```bash
make package-linux
```

Output at `bin/linux/`:

- `share/applications/`: `.desktop` file.
- `share/icons/`: Application icon.
- `dirlocker-gui`: Executable.

### macOS

Create an App Bundle for macOS:

```bash
make package-mac
```

Output at `bin/dirLocker.app`:

- Standard macOS directory structure.
- `Info.plist` creation.
- Icon handling.

## Directory Structure

- `cmd/`: Application entry points (`cli`, `gui`).
- `pkg/`: Core Go packages (`vault`, `mount`, `iconmanager`).
- `internal/`: Private package implementations.
- `vault-core/`: Rust cryptographic library.
- `scripts/`: Helper scripts (e.g., icon resizing).

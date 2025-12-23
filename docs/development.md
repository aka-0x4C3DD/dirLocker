# Development Guide

This guide covers everything you need to know to build, test, and package **dirLocker**.

## Prerequisites

Before starting, ensure you have the following installed:

*   **Go**: Version 1.24 or higher.
*   **Rust**: Version 1.70 or higher (via rustup).
*   **GCC/MinGW**: Required for CGO compilation.
*   **Make**: A standard Make tool (available via Git Bash or MinGW on Windows).

### Windows Specifics
*   **go-winres**: For icon embedding (automatically installed by Makefile).
*   **Rsrc**: Recommended to have `git bash` or equivalent for running Make commands.

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
*   **Go Tests**: Runs with `CGO_ENABLED=1` to ensure FFI bindings are tested.
*   **Rust Tests**: Runs `cargo test` inside `vault-core`.

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
*   `share/applications/`: `.desktop` file.
*   `share/icons/`: Application icon.
*   `dirlocker-gui`: Executable.

### macOS
Create an App Bundle for macOS:
```bash
make package-mac
```
Output at `bin/dirLocker.app`:
*   Standard macOS directory structure.
*   `Info.plist` creation.
*   Icon handling.

## Directory Structure
*   `cmd/`: Application entry points (`cli`, `gui`).
*   `pkg/`: Core Go packages (`vault`, `mount`, `iconmanager`).
*   `internal/`: Private package implementations.
*   `vault-core/`: Rust cryptographic library.
*   `scripts/`: Helper scripts (e.g., icon resizing).

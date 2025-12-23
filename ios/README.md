# dirLocker iOS

This directory contains the iOS client for dirLocker.

## Prerequisites
- Xcode 15+
- Rust 1.70+ (with `aarch64-apple-ios` and `x86_64-apple-ios` targets)

## Setup
1. Build the Rust core for iOS:
   ```bash
   cd ../vault-core
   cargo build --release --target aarch64-apple-ios
   ```
2. Open `DirLocker.xcodeproj` in Xcode.
3. Ensure the bridging header points to the generated `vault_core.h`.

## Structure
- `DirLocker/`: Main app source
- `FileProvider/`: File Provider extension for Files app integration

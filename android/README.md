# dirLocker Android

This directory contains the Android client for dirLocker.

## Prerequisites
- Android Studio Hedgehog+
- Rust 1.70+ (with `aarch64-linux-android` target)
- NDK 25+

## Setup
1. Build the Rust core for Android:
   ```bash
   cd ../vault-core
   cargo build --release --target aarch64-linux-android
   ```
2. Open this directory in Android Studio.
3. Sync Gradle project.

## Structure
- `app/`: Main application module
- `vault-core-bindings/`: JNI bindings for Rust core

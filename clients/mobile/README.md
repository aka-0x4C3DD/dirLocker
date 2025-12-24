# Mobile Client Setup

## Prerequisites
- Flutter SDK installed and in your PATH.
- Android Studio / Xcode for mobile emulation.

## Initialization
Since the Flutter CLI was not available during the automated setup, please run the following command in this directory:

```bash
flutter create --org com.dirlocker.mobile --platforms android,ios,linux .
```

## Rust Bridge Setup
After initializing the project, run the `flutter_rust_bridge_codegen` to generate the bindings:

```bash
# Install codegen if needed
cargo install flutter_rust_bridge_codegen

# Generate bindings
flutter_rust_bridge_codegen --rust-input ../../vault-core/src/mobile_api.rs --dart-output ./lib/bridge_generated.dart --c-output ./ios/Runner/bridge_generated.h
```

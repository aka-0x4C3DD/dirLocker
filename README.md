<div align="center">

# 🔒 dirLocker
### secure • cross-platform • invisible

[![CI Status](https://img.shields.io/github/actions/workflow/status/aka-0x4C3DD/dirLocker/ci.yml?style=flat-square&logo=github)](https://github.com/aka-0x4C3DD/dirLocker/actions)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat-square&logo=go)](go.mod)
[![Rust Version](https://img.shields.io/badge/Rust-1.70+-000000?style=flat-square&logo=rust)](vault-core/Cargo.toml)
[![Platform](https://img.shields.io/badge/platform-win%20%7C%20linux%20%7C%20macos-lightgrey?style=flat-square)](README.md)

[Getting Started](#-quick-start) • [Features](#-features) • [Dev Guide](docs/development.md) • [Architecture](docs/architecture.md) • [Contributing](#-contributing)

</div>

---

## 💫 About
**dirLocker** is a state-of-the-art encrypted file vault application designed for paranoia-level security and seamless usability. It combines a high-performance Rust cryptographic core with a flexible Go application layer to deliver military-grade encryption, plausible deniability, and cross-platform native interfaces.

Whether you need to secure personal documents, hide sensitive data, or share secrets securely, dirLocker provides a fortress for your digital assets.

## ✨ Features

| Feature | Description |
| :--- | :--- |
| **🔐 Strong Encryption** | AES-256-GCM and XChaCha20-Poly1305 (Pure Rust Core) |
| **👻 Plausible Deniability** | Advanced file hiding capabilities make vaults invisible to the OS |
| **📂 Virtual Drive** | Mount vaults as native drives using FUSE, Dokany, or WinFSP |
| **🤝 Secure Sharing** | Share access securely via X25519 authenticated key exchange |
| **🔑 Recovery System** | Cryptographic recovery keys ensure you never lose access |
| **🖥️ Cross-Platform** | Native CLI and GUI experiences for Windows, Linux, and macOS |

## 🚀 Quick Start

### Prerequisites
*   **Rust**: 1.70+
*   **Go**: 1.24+
*   **GCC**: Required for CGO

### 🛠️ Building

**Windows (PowerShell)**
```powershell
# 1. Build Rust Core
cd vault-core
cargo build --release --target x86_64-pc-windows-gnu

# 2. Build Go App
cd ..
$env:CGO_ENABLED="1"
go build -o bin/dirlocker-cli.exe ./cmd/cli
go build -o bin/dirlocker-gui.exe ./cmd/gui
```

**Linux / macOS**
```bash
# 1. Build Rust Core
cd vault-core && cargo build --release

# 2. Build Go App
cd ..
export CGO_ENABLED=1
go build -o bin/dirlocker ./cmd/cli
go build -o bin/dirlocker-gui ./cmd/gui
```

## 🎮 Usage

### Command Line Interface
```bash
# Create a new vault
./bin/dirlocker create secure.vault

# Open and interact
./bin/dirlocker open secure.vault

# Mount as a drive (Windows)
./bin/dirlocker mount secure.vault Z:
```

### Graphical Interface
Simply verify the build and launch:
```bash
./bin/dirlocker-gui
```

## 🏗️ Architecture

The project follows a robust layered architecture:

```mermaid
graph TD
    UI[🖥️ GUI / CLI] --> Go[🐹 Go Application Layer]
    Go --> Bindings[🔗 CGO Bindings]
    Bindings --> Rust[🦀 Rust Vault Core]
    Rust --> Crypto[🔒 Ring / ChaCha20]
```

*   **Rust Core**: Handles all low-level crypto, file format parsing, and memory security.
*   **Go Layer**: Manages OS integration, file mounting, and high-level logic.
*   **Interfaces**: Fyne-based GUI and Cobra-based CLI.

## 📂 Project Structure

```text
dirLocker/
├── 🦀 vault-core/        # Rust cryptographic engine
├── 🐹 pkg/               # Public Go APIs (Vault, Config, Mount)
├── 🖥️ cmd/               # Entry points (CLI, GUI)
├── 🔧 internal/          # Private implementation logic
├── 📜 scripts/           # Build & Packaging automation
├── 🧪 tests/             # Integration Test Suite
└── 📄 docs/              # Comprehensive Documentation
```

## 🧪 Testing

We maintain a comprehensive test suite covering unit, integration, and fuzz testing.

```bash
# Run the full suite (requires CGO)
export CGO_ENABLED=1
go test -tags cgo -v ./...
```

## 🤝 Contributing

Contributions are welcome! Check out our [Feature Specifications](.kiro/specs/) to see what's planned.

1.  Fork the Project
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the Branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request

## 📜 License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

---

<div align="center">
Made with ❤️ by aka-0x4C3DD
</div>

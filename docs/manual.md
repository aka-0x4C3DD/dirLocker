# User Manual

## Introduction

**dirLocker** is a cross-platform encrypted vault application. This manual guides you through creating, managing, and using your secure vaults.

## Command Line Interface (CLI)

The CLI binary `dirlocker` (or `dirlocker.exe` on Windows) provides scriptable access to all features.

### 1. Creating a Vault

Create a new encrypted container. You will be prompted for a password.

```bash
dirlocker create my_secrets.vault
```

### 2. Opening a Vault (Shell Mode)

Open a vault to enter an interactive shell for file management.

```bash
dirlocker open my_secrets.vault
```

### 3. Mounting a Vault

Mount the vault as a virtual filesystem drive. access your files effectively as if they were on a USB stick.

**Windows:**

```powershell
dirlocker mount my_secrets.vault Z:
```

**Linux/macOS:**

```bash
dirlocker mount my_secrets.vault /mnt/vault
```

> **Note (Linux):** Ensure `fuse3` is installed on your system.

**Advanced Mount Options:**

- `--readonly`: Mount in read-only mode.
- `--debug`: Enable verbose FUSE logging.
- `--allow-other`: Allow other users to access the mount (Linux/macOS).

### 4. Listing Files

List contents without fully opening/mounting (requires password).

```bash
dirlocker list my_secrets.vault
```

## Graphical User Interface (GUI)

The `dirlocker-gui` application provides a visual file manager.

1.  **Launch**: Run the executable.
2.  **Create/Open**: Use the "File" menu to create new vaults or open existing ones.
3.  **Browse**: Navigate the folder structure within the vault.
4.  **Drag & Drop**: Add files by collecting them into the window.
5.  **Mount**: Click the "Mount" button in the toolbar to expose the vault as a drive.

## Biometric Authentication

**dirLocker** supports biometric unlock (Windows Hello, TouchID, etc.) for convenience.

- **Enable**: Check "Enable Biometrics" when creating a new vault.
- **Usage**: Click "Unlock using Biometrics" on the login screen.
- **Security**: Credentials are stored in the OS Secure Store (Windows Credential Manager / macOS Keychain).
- **Robustness**: The link is bound to the Vault's internal unique ID, so you can safely rename or move your vault file without breaking biometric access.

## Strong Password Generator

A built-in secure password generator is available in the "Create Vault" view.

- **Customization**: Adjust length (8-64) and character sets (A-Z, a-z, 0-9, Symbols).
- **Privacy**: Generated passwords copied to the clipboard are **automatically cleared after 30 seconds** to prevent accidental leaks.

## Recovery System

If you lose your password, you can use the **Recovery Key** generated during vault creation.

> **Warning**: If you lose both your password and your recovery key, your data is cryptographically irretrievable.

To recover a vault:

```bash
dirlocker recover my_secrets.vault --key "YOUR-RECOVERY-KEY-STRING" --new-password "new_secure_password"
```

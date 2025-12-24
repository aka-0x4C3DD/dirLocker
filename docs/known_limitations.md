# Known Limitations & Project Registry
**Status**: Active  
**Last Updated**: 2025-12-24

This registry compiles known limitations, technical debt, and deferred items identified across all project documentation.

## 1. Security & Privacy Limitations
*   **[Resolved] Clipboard Clearing**: The Strong Password Generator now automatically clears the clipboard after 30 seconds.
    *   *Source*: `docs/security_risk_assessment.md` (PWD-01).
    *   *Status*: **Implemented** (v0.2.1).
    *   *Note*: Relies on `navigator.clipboard` access; some contexts might block read access but write access usually works.

*   **[High] Biometric Granularity**: The current implementation relies on `keyring-rs` which defaults to standard OS behavior. Secure enclaves (TPM/Secure Enclave) are used for storage, but access control policies ("User Presence") are not strictly enforced on every read if the OS session is already active.
    *   *Source*: `docs/security_risk_assessment.md` (BIO-01).
    *   *Investigation Results*: 
        *   **Windows**: Requires direct `winapi` calls to `CredWrite` with explicit UI flags or Windows Hello specific APIs (Passport).
        *   **macOS**: Requires `SecAccessControlCreateWithFlags` with `kSecAccessControlUserPresence`.
        *   **Linux**: Highly dependent on the desktop environment's Secret Service implementation (GNOME Keyring vs KWallet).
    *   *Mitigation*: Current state provides "Convenience vs Security" trade-off suitable for personal use but not high-security enterprise use.

*   **[Low] Memory Protection**: Passwords in React state and Go memory are not explicitly pinned/zeroed (though Rust core attempts zeroing).
    *   *Source*: General Architecture.
    *   *Impact*: Advanced local memory dump attacks.

## 2. Platform & Compatibility Limitations
*   **[Medium] Linux Dependencies**: The `keyring` crate on Linux requires `dbus` and `libsecret` development headers (`libsecret-1-dev`) to be installed on the host system.
    *   *Impact*: Deployment complexity on Linux.
*   **[High] Mobile Support**: Mobile implementation (iOS/Android) is currently non-existent.
    *   *Status*: Deferred.
    *   *Implementation Path*: Requires Flutter frontend + `dart:ffi` bindings to `vault-core`.

## 3. Functional Limitations
*   **[Resolved] Multiple Vaults**: The UI supports opening one vault. The credential store keys off the vault path. Moving the vault file breaks the biometric link.
    *   *Status*: **Implemented** (v0.2.1).
    *   *Solution*: Biometric credentials are now bound to the Vault's internal UUID (`vault_get_id`) rather than the file path. Moving the file no longer breaks authentication.
*   **[Resolved] Password Generator Config**: Length and character set can now be customized via an "Options" toggle in the Create view.
    *   *Status*: **Implemented** (v0.2.1).
    *   *Features*: Slider (8-64 chars), Character set toggles (Uppercase, Lowercase, Numbers, Symbols).

## 4. Technical Debt
*   **[Resolved] App.tsx Size**: The main `App.tsx` file was growing large.
    *   *Status*: **Refactored** (v0.2.1). Main logic split into `WelcomeView`, `CreateView`, `UnlockView`, `DashboardView`.

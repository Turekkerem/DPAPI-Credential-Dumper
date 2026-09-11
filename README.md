# Windows DPAPI & Security Credentials Abuse: Comprehensive Technical Overview

## 1. Introduction: Convenience vs. Security
**"How Windows made security comfortable, but failed a little bit"**

Modern operating systems face a fundamental design paradox: how to protect highly sensitive user secrets—such as browser credentials, Wi-Fi keys, and master encryption keys—while ensuring a completely seamless, friction-free user experience. Windows resolves this tension through the **Data Protection API (DPAPI)**, a cryptographic subsystem designed to transparently protect data using keys derived directly from the user's login credentials or the local system context.

This architecture fundamentally prioritizes user convenience. Because DPAPI operates automatically within the active user's session context, any code executed under that user's security rights can invoke the API to unprotect secrets without prompting for a password or multi-factor verification. The operating system implicitly assumes that if a user is authenticated, any application executing within their session context is trustworthy.

Consequently, this creates a significant security gap. Malware, unauthorized scripts, or local privilege escalation vectors running under a standard user account can effortlessly harvest plaintext Wi-Fi passwords, browser cookies, application tokens, and private cryptographic keys without ever needing to brute-force a master password.

---

## 2. Comprehensive Technical Module Breakdown

### 2.1 Core & Entry Point

* **`main.cpp`**:
  * Acts as the primary execution entry point.
  * Handles console encoding initialization (`SetConsoleOutputCP(CP_UTF8)`) to correctly render text output.
  * Sequentially orchestrates the execution flow across all underlying system and browser exfiltration modules.

* **`CryptoEngine.h`**:
  * Functions as the core cryptographic helper library for decryption routines.
  * Implements `DecryptDPAPI` utilizing `CryptUnprotectData` to reverse standard DPAPI blobs (such as legacy cookies or Master Key containers).
  * Parses browser configuration files (`Local State`) to locate base64-encoded, DPAPI-protected Master Keys prefixed with the `DPAPI` magic bytes, unprotecting them to recover the active 32-byte binary key.
  * Implements advanced AES-256-GCM authenticated decryption using the Windows CNG library (`BCryptOpenAlgorithmProvider`, `BCryptImportKey`, `BCryptDecrypt`) combined with extracted initialization vectors (IV) and authentication tags to extract modern browser credentials.
  * Also provides `DecryptAESCBC` for legacy v20 handling and Firefox `key4.db` blobs.

### 2.2 Windows System Credentials

* **`SystemCredentialsDump.h`**:
  * Manages the core Windows operating system credential harvesting layer.
  * Utilizes `CredEnumerateW` to query and dump stored credentials directly from the *Windows Credential Manager*.
  * Interfaces with the native WLAN API (`WlanOpenHandle`, `WlanEnumInterfaces`, `WlanGetProfile`) combined with the `WLAN_PROFILE_GET_PLAINTEXT_KEY` flag to force DPAPI into unprotecting and extracting plaintext Wi-Fi profiles and network keys.
  * Scans the user registry hive (`HKCU\Software\Microsoft\Windows\CurrentVersion\FVEAutoUnlock`) for BitLocker volume auto-unlock keys protected by the user's DPAPI scope.
  * Enumerates the personal certificate store (`MY` / `Personal`), evaluates certificate contexts for associated private keys via `CryptAcquireCertificatePrivateKey`, and exports them in PEM format for both CAPI (RSA) and CNG (PKCS#8) providers.

* **`DpapiMasterKeys.h`**:
  * Enumerates all DPAPI Master Keys stored under `%APPDATA%\Microsoft\Protect\{SID}\`.
  * For each GUID file found, attempts `CryptUnprotectData` in the current user context.
  * Prints the GUID and the decrypted 32-byte key material in hex.
  * This is the foundation for understanding what secrets the current user can actually unlock — without it, manual recovery of RDCMan, mRemoteNG and certificate blobs is impossible.

* **`VaultDump.h`**:
  * Wraps `vaultcmd /listcreds` for both `Web Credentials` and `Windows Credentials` vaults.
  * Produces a metadata-only dump (target name, username) of every stored vault entry.
  * Note: `vaultcmd` does **not** reveal the plaintext secret. Full extraction requires the Windows Vault COM API (`VaultEnumerateVaults`, `VaultGetItem`) — see `VaultDump.h` for a `TODO` marker.

### 2.3 Browser Credential Harvesting

* **`ChromiumDump.h`**:
  * Automates the targeted harvesting of sensitive credentials from Chromium-based browsers (Google Chrome, Microsoft Edge, Brave Browser, Vivaldi, Opera).
  * Bypasses active file-sharing locks on locked browser SQLite databases by dynamically copying *Login Data* and *Network/Cookies* databases to the local temporary folder (`GetTempPathW`).
  * Parses structured SQL databases using custom queries (`SELECT origin_url, username_value, password_value FROM logins;` and `SELECT host_key, name, encrypted_value FROM cookies;`) to isolate encrypted payloads.
  * Handles both legacy DPAPI-protected blobs and modern `v10` / `v11` AES-256-GCM entries.

* **`ChromiumV20.h`**:
  * Dedicated module for Chrome / Edge **App-Bound Encryption (ABE)** introduced in Chromium v20 (Chrome 127+, Edge 127+).
  * Implements the two-step `CryptUnprotectData` chain: SYSTEM impersonation first (requires administrator), then CurrentUser unprotect, followed by AES-GCM decryption of the flag-3 blob using a hardcoded key extracted from `elevation_service.exe`.
  * Ships with a placeholder `kChromeKey1[32]` array — **the actual key must be extracted from your specific Chrome build** for the module to produce usable output.
  * Marked as **administrator-only**; running without elevation will silently skip the ABE path and leave v20 entries encrypted.

* **`GeckoAndIECookies.h`**:
  * Extends cookie harvesting capabilities to alternative browser ecosystems.
  * Locates Mozilla Firefox and Tor Browser profiles within `%APPDATA%`, querying the `cookies.sqlite` database using SQL statements (`SELECT host, name, value, path, isSecure, isHttpOnly, expiry FROM moz_cookies;`) to extract plaintext session cookies.
  * Scans legacy Internet Explorer cookie storage paths (`%APPDATA%\Microsoft\Windows\Cookies`) to read plaintext `.txt` cookie files.

### 2.4 Remote Access & Developer Credentials

* **`RdpDump.h`**:
  * Recursively scans `%USERPROFILE%\Documents`, `Desktop`, `Downloads` and `%LOCALAPPDATA%\Temp` for RDP-related artefacts.
  * Parses **RDCMan** `.rdg` files (XML), extracts `<password>` blobs, base64-decodes them and decrypts via DPAPI.
  * Parses **mstsc** `.rdp` files, extracts the `password 51:b:<hex>` line, converts hex to bytes and decrypts via DPAPI.
  * Handles both plaintext and DPAPI-protected password entries.

* **`DevCredentialsDump.h`**:
  * Harvests credentials from common developer and CLI tooling.
  * Dumps **SSH private keys** from `%USERPROFILE%\.ssh\` (any file starting with `id_` or containing `key`).
  * Dumps **Git credentials** from `%USERPROFILE%\.git-credentials` (plaintext).
  * Dumps **AWS CLI** credentials from `%USERPROFILE%\.aws\credentials` (plaintext).
  * Dumps **Azure CLI** profile and access tokens from `%USERPROFILE%\.azure\azureProfile.json` and `accessTokens.json`.
  * Parses **mRemoteNG** `confCons.xml`, extracting and DPAPI-decrypting every `Password="..."` attribute.
  * Dumps **MobaXterm** `MobaXterm.ini` for manual analysis (master-password protected, not DPAPI).

### 2.5 Post-Exploitation

* **`Pillaging.h`**:
  * Lightweight file-system pillaging module for `Desktop`, `Documents` and `Downloads`.
  * Recursively scans `.txt`, `.json`, `.xml`, `.config`, `.ini`, `.yaml`, `.yml` files.
  * Uses a case-insensitive regex (`password|passwd|pwd|secret|api_key|token|credentials`) to surface lines that likely contain credentials.

### 2.6 Third-Party Libraries

* **`sqlite3.h`**, **`sqlite3.c`**, **`sqlite3.o`**, **`libsqlite3.a`**:
  * A static implementation of the SQLite database engine.
  * Linked directly into the project to give compiled binaries the native capability to parse embedded database architectures without requiring external DLL dependencies on the target host.
  * `libsqlite3.a` is the pre-built static archive used by the MSYS2 / MinGW toolchain.

---

## 3. Deep-Dive: How DPAPI Secures and Unlocks Browser Data

Modern browsers like Google Chrome or Microsoft Edge do not encrypt every single individual password or cookie directly through DPAPI. Doing so would invoke heavy cryptographic overhead and prompt performance degradation. Instead, they rely on a **two-tier envelope encryption model**:

1. **The Master Key Layer (DPAPI Protection)**:
   * Upon initialization, the browser generates a cryptographically secure, random 32-byte symmetric key known as the **Master Key**.
   * To safely persist this key to disk, the browser saves it inside the browser's profile configuration file (`Local State`) under the `os_crypt.encrypted_key` JSON property, prefixed with the literal ASCII string `DPAPI`.
   * When the browser (or an unauthorized PoC tool running in the user's session) needs the Master Key, it strips the `DPAPI` prefix, wraps the remaining raw binary blob into a `DATA_BLOB` structure, and passes it to the system function `CryptUnprotectData`.
   * Windows evaluates the calling thread's user context, validates the entropy, and seamlessly decrypts the payload, returning the raw 32-byte Master Key in memory.

2. **The Data Layer (AES-256-GCM Protection)**:
   * Individual records inside the *Login Data* (passwords) and *Cookies* databases are encrypted using the strong symmetric cipher **AES-256-GCM**.
   * Each encrypted database entry starts with a version identifier byte sequence (typically `v1` followed by 3 bytes).
   * The structure contains a 12-byte initialization vector (IV / Nonce) starting at offset 3, followed immediately by the ciphertext, and terminated by a 16-byte authentication tag.
   * The tool isolates these components, initializes a Windows CNG AES context in GCM chaining mode (`BCryptSetProperty` with `BCRYPT_CHAIN_MODE_GCM`), imports the plaintext Master Key recovered in step one, and feeds the IV, ciphertext, and tag into `BCryptDecrypt`.
   * The cryptographic subsystem validates the authentication tag and outputs the completely unencrypted plaintext (such as a cleartext password or active session cookie value).

---

## 4. Deep-Dive: App-Bound Encryption (Chromium v20+)

Starting with Chrome 127 and Edge 127, Chromium browsers introduced **App-Bound Encryption (ABE)** to defend against exactly the kind of cookie and credential theft this PoC demonstrates. ABE raises the bar significantly by binding the encryption key to the browser's own code integrity, not just the user's DPAPI context.

**Key changes:**

* The `Local State` file now stores a second encrypted key under `os_crypt.app_bound_encrypted_key`.
* The key is wrapped twice: once with **SYSTEM-scoped DPAPI**, and once with **user-scoped DPAPI** — meaning a plain user-context `CryptUnprotectData` call is no longer sufficient.
* The final unwrap is performed by a hardcoded AES key embedded inside `elevation_service.exe` (Chrome) or `msedge_elevation_service.exe` (Edge), which is only accessible from an elevated context.

**Attack path implemented in `ChromiumV20.h`:**

1. Impersonate SYSTEM (`OpenProcessToken` + `DuplicateTokenEx` + `ImpersonateLoggedOnUser`).
2. `CryptUnprotectData` on the SYSTEM-wrapped portion of `app_bound_encrypted_key`.
3. Revert to the current user (`RevertToSelf`).
4. `CryptUnprotectData` again on the user-wrapped portion.
5. AES-256-GCM decrypt the resulting flag-3 blob using the hardcoded key extracted from `elevation_service.exe`.

**Practical limitations:**

* Requires administrator privileges — this is not a pure user-context attack.
* The hardcoded key changes between Chrome versions; it must be re-extracted from the corresponding `elevation_service.exe`.
* When run without elevation, the module silently skips ABE entries and leaves them encrypted.

---

## 5. Project Compilation Guidelines

To compile the modular source code successfully within a Windows environment utilizing MSYS2 and the MinGW toolchain, execute the following command in the terminal:

bash
```
g++ main.cpp sqlite3.o -o DPAPI_PoC.exe -std=c++17 -O2 -lcrypt32 -lbcrypt -ladvapi32 -lwlanapi -lncrypt -lole32 -luuid -lshell32 -lshlwapi -static -lstdc++fs
```
---

## 6. Project Layout

```
DPAPI-Abuser-PoC/
├── .gitattributes
├── .gitignore
├── README.md
├── main.cpp
├── CryptoEngine.h
├── SystemCredentialsDump.h
├── DpapiMasterKeys.h
├── VaultDump.h
├── ChromiumDump.h
├── ChromiumV20.h
├── GeckoAndIECookies.h
├── RdpDump.h
├── DevCredentialsDump.h
├── Pillaging.h
├── sqlite3.h
└── DPAPI_PoC.exe        (compiled binary, git-ignored)
```

### 6.1 Files Ignored by Git

The following artefacts are present locally but excluded from the repository via `.gitignore`:

* **`sqlite3.c`** — the SQLite amalgamation source file.
* **`sqlite3.o`** — the compiled SQLite object file linked directly into the PoC.
* **`libsqlite3.a`** — the static SQLite archive, provided as an alternative linking option.
* **`DPAPI_PoC.exe`** — the compiled PoC binary.

As a result, a fresh clone contains only the headers, `main.cpp`, `sqlite3.h`, and the documentation. To build the project, the SQLite amalgamation must be compiled locally (or the pre-built `.o` / `.a` artefacts must be copied in manually) before running the build command.




---

## 7. MITRE ATT&CK Mapping

| Module | Technique | ID |
|---|---|---|
| `SystemCredentialsDump.h` (CredMan) | Credentials from Password Stores: Windows Credential Manager | T1555.004 |
| `SystemCredentialsDump.h` (Wi-Fi) | Credentials from Password Stores | T1555 |
| `SystemCredentialsDump.h` (BitLocker) | Credentials from Password Stores | T1555 |
| `SystemCredentialsDump.h` (Certificates) | Unsecured Credentials: Private Keys | T1552.004 |
| `DpapiMasterKeys.h` | Credentials from Password Stores | T1555 |
| `VaultDump.h` | Credentials from Password Stores | T1555 |
| `ChromiumDump.h` | Credentials from Web Browsers | T1555.003 |
| `ChromiumV20.h` | Credentials from Web Browsers | T1555.003 |
| `GeckoAndIECookies.h` | Credentials from Web Browsers | T1555.003 |
| `RdpDump.h` | Credentials from Password Stores | T1555 |
| `DevCredentialsDump.h` | Unsecured Credentials: Credentials In Files | T1552.001 |
| `Pillaging.h` | Data from Local System | T1005 |

---

## 8. Operational Security Notes

* **No network activity.** Every module operates strictly against local files, the registry and Win32 APIs. There is no C2, no exfiltration, no beaconing.
* **No persistence.** The binary does not install itself, modify autostart keys or schedule tasks. It is a one-shot harvester.
* **No privilege escalation.** Every module runs in the context of the invoking user. Only `ChromiumV20.h` requires administrator rights, and it does not attempt to obtain them — it simply skips ABE entries if not elevated.
* **Evidence left behind.** Reading `Login Data`, `Cookies`, `Local State` and `CREDHIST` leaves file-access artefacts; `CryptUnprotectData` calls are visible to EDR / ETW. This PoC is not stealthy by design — it is intended for controlled lab use where detection is part of the exercise.

---

> [!CAUTION]
> **DISCLAIMER (DPAPI PoC)**
>
> The author of this code (and the person providing this response) ASSUMES NO LIABILITY whatsoever for any damages, losses, or legal consequences arising from the use, modification, or redistribution of this tool.
>
> By using this code, you explicitly agree to the following CONDITIONS:
> 1. You may use it SOLELY in environments where you hold explicit, written permission from the legitimate owner.
> 2. The recommended testing environment is an ISOLATED VIRTUAL LABORATORY (e.g., offline VMs with no connection to production networks).
> 3. Any attempt to deploy this code against systems, networks, or data without proper authorization constitutes a CRIMINAL OFFENSE and violates applicable laws (including the Computer Fraud and Abuse Act and similar international regulations).
>
> **THE USER BEARS FULL CRIMINAL AND CIVIL LIABILITY for all actions performed using this tool.**

*(Note: Yes, I used AI because after sitting for 6 hours I asked AI and it said it didn't really know where the error was - after 10 prompts it finally said that well, the wlanapi library can block with wcout-s)*
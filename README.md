# Promiscuous-CredsHarvester

> Promiscuous-CredsHarvester — a Windows credential harvester built around DPAPI. Unlocks system credentials, browser secrets, developer tooling and cryptographic key material from a standard user session. Academic PoC for red/blue team training.*

---

## 1. Introduction: Convenience vs. Security

**"How Windows made security comfortable, but failed a little bit."**

Modern operating systems face a fundamental design paradox: how to protect highly sensitive user secrets — such as browser credentials, Wi-Fi keys, and master encryption keys — while ensuring a completely seamless, friction-free user experience. Windows resolves this tension through the **Data Protection API (DPAPI)**, a cryptographic subsystem designed to transparently protect data using keys derived directly from the user's login credentials or the local system context.

This architecture fundamentally prioritizes user convenience. Because DPAPI operates automatically within the active user's session context, any code executed under that user's security rights can invoke the API to unprotect secrets without prompting for a password or multi-factor verification. The operating system implicitly assumes that if a user is authenticated, any application executing within their session context is trustworthy.

This is why the project is called **Promiscuous** — DPAPI does not ask *who* is requesting the decryption. It does not validate code signatures, file paths, or caller identity. It only asks *which user* the calling thread is running as. Any process in the user's session can call `CryptUnprotectData` and receive plaintext secrets.

Consequently, this creates a significant security gap. Malware, unauthorized scripts, or local privilege escalation vectors running under a standard user account can effortlessly harvest plaintext Wi-Fi passwords, browser cookies, application tokens, and private cryptographic keys without ever needing to brute-force a master password.

---

## 2. Comprehensive Technical Module Breakdown

### 2.1 Core & Entry Point

* **`main.cpp`**:
  * Acts as the primary execution entry point.
  * Handles console encoding initialization (`SetConsoleOutputCP(CP_UTF8)`) to correctly render text output.
  * Sequentially orchestrates the execution flow across all underlying system, browser, developer and cryptographic exfiltration modules.

* **`CryptoEngine.h`**:
  * Functions as the core cryptographic helper library for decryption routines.
  * Implements `DecryptDPAPI` utilizing `CryptUnprotectData` to reverse standard DPAPI blobs (such as legacy cookies or Master Key containers).
  * Parses browser configuration files (`Local State`) to locate base64-encoded, DPAPI-protected Master Keys prefixed with the `DPAPI` magic bytes, unprotecting them to recover the active 32-byte binary key.
  * Implements advanced AES-256-GCM authenticated decryption using the Windows CNG library (`BCryptOpenAlgorithmProvider`, `BCryptImportKey`, `BCryptDecrypt`) combined with extracted initialization vectors (IV) and authentication tags to extract modern browser credentials.
  * Also provides `DecryptAESCBC` for legacy handling and other symmetric-key use cases.

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
  * Enumerates Windows Vault contents through the **native Vault API** (`vaultcli.dll`), loaded dynamically via `LoadLibrary` + `GetProcAddress` — no link-time dependency, no `-lvaultcli`.
  * Calls `VaultEnumerateVaults`, `VaultOpenVault` and `VaultEnumerateItems` to walk every vault (Web Credentials, Windows Credentials) and retrieve each item's `Resource`, `Identity`, `AuthenticatorElement` and `PackageSid`.
  * Extracts **plaintext secrets** from `ElementType_ByteArray` entries (interpreted as UTF-16LE), falling back to a hex dump when the payload cannot be decoded as a string.
  * Uses a runtime-corrected `VAULT_ITEM_WIN8` / `VAULT_ITEM_ELEMENT` layout. On Windows 10/11 the MSDN-documented structure is out of date: the runtime inserts two extra `DWORD` fields before `Type`, and orders `LastModified` before `dwFlags` / `dwPropertiesCount`. Both facts were confirmed empirically and are now encoded in the struct definitions.
  * If the native API returns zero items (typical on consumer machines, where the vault only holds Microsoft Store AppContainer tokens), the module falls back to `vaultcmd` via `_popen` and prints metadata only (target, username, SID). The fallback is language-independent: vault names are never hardcoded — GUIDs are extracted from `vaultcmd /list` and reused verbatim.
  * **Note:** on a standard consumer workstation the Web Credentials vault contains only internal UWP tokens (`SnapshotEncryptionIV`, `SnapshotEncryptionKey`) and no user passwords. Real user credentials live in `Credential Manager` (see `SystemCredentialsDump.h`) and browser `Login Data` databases (see `ChromiumDump.h`).

### 2.3 Browser Credential Harvesting

* **`ChromiumDump.h`**:
  * Automates the targeted harvesting of sensitive credentials from Chromium-based browsers (Google Chrome, Microsoft Edge, Brave Browser, Vivaldi, Opera).
  * Bypasses active file-sharing locks on locked browser SQLite databases by dynamically copying *Login Data* and *Network/Cookies* databases to the local temporary folder (`GetTempPathW`).
  * Parses structured SQL databases using custom queries (`SELECT origin_url, username_value, password_value FROM logins;` and `SELECT host_key, name, encrypted_value FROM cookies;`) to isolate encrypted payloads.
  * Handles both legacy DPAPI-protected blobs and modern `v10` / `v11` AES-256-GCM entries.

* **`GeckoAndIECookies.h`**:
  * Extends cookie harvesting capabilities to alternative browser ecosystems.
  * Locates Mozilla Firefox and Tor Browser profiles within `%APPDATA%`, querying the `cookies.sqlite` database using SQL statements (`SELECT host, name, value FROM moz_cookies;`) to extract plaintext session cookies.
  * Scans legacy Internet Explorer cookie storage paths (`%APPDATA%\Microsoft\Windows\Cookies`) to read plaintext `.txt` cookie files.

> **Note on App-Bound Encryption (v20):** Chrome 127+ and Edge 127+ introduced ABE, which binds credential encryption to the browser's own code integrity and requires administrator-level SYSTEM impersonation to bypass. This PoC **intentionally omits** ABE to remain a pure user-context, non-elevated tool. The design rationale is documented in section 4.

### 2.4 Remote Access & Developer Credentials

* **`RdpDump.h`**:
  * Recursively scans `%USERPROFILE%\Documents`, `Desktop`, `Downloads` and `%LOCALAPPDATA%\Temp` for RDP-related artefacts.
  * Parses **RDCMan** `.rdg` files (XML), extracts `<password>` blobs, base64-decodes them and decrypts via DPAPI.
  * Parses **mstsc** `.rdp` files, extracts the `password 51:b:<hex>` line, converts hex to bytes and decrypts via DPAPI.
  * Handles both plaintext and DPAPI-protected password entries.

* **`DevCredentialsDump.h`**:
  * Harvests credentials from common developer tooling and CLI utilities, **excluding raw key material** (which lives in `CryptoKeysDump.h`).
  * **Git** — `.git-credentials` (plaintext), `.gitconfig`.
  * **Cloud CLIs** — AWS `.aws\credentials` and `.aws\config`, Azure `.azure\azureProfile.json` and `.azure\accessTokens.json`, GCloud `application_default_credentials.json` and `credentials.db`.
  * **Package managers** — NPM `.npmrc`, PyPI `.pypirc`, `.netrc` / `_netrc`, RubyGems `.gem\credentials`.
  * **Containers & orchestration** — Docker `.docker\config.json`, Kubernetes `.kube\config`.
  * **Infrastructure as Code** — Terraform `.terraformrc` and `.terraform.d\credentials.tfrc.json`, Ansible `.ansible.cfg`.
  * **Remote access clients** — mRemoteNG `confCons.xml` (DPAPI-decrypted), MobaXterm `MobaXterm.ini` (raw).

### 2.5 Cryptographic Key Material

* **`CryptoKeysDump.h`**:
  * Dedicated module for cryptographic key material, separated from developer credentials to keep concerns clean.
  * **Known locations**:
    * SSH private keys (`.ssh\id_*`, `*key*`).
    * OpenSSH host keys (`%ProgramData%\ssh\`).
    * PuTTY host keys (registry `HKCU\Software\SimonTatham\PuTTY\SshHostKeys`).
    * GnuPG keyring: `private-keys-v1.d\*.key`, `pubring.kbx`, `gpg.conf`, plus armored `.asc` / `.gpg` / `.pgp` files.
    * WireGuard configurations (`%ProgramFiles%\WireGuard\Data\Configurations\`).
    * OpenVPN configurations (`.ovpn`, `.key`, `.crt`, `.pem`).
  * **Profile-root scan** — direct files in `%USERPROFILE%` (no recursion), catching keys users drop directly into their home directory.
  * **Full-profile recursive scan** — walks the entire user profile, matching key-block headers via regex (`-----BEGIN ... PRIVATE KEY-----` covering RSA, EC, DSA, OpenSSH, PGP, encrypted PKCS#8) and file extensions (`.asc`, `.key`, `.pem`, `.pub`, `.priv`, `.privkey`, `.crt`, `.cer`, `.pfx`, `.p12`, `.ppk`, `.gpg`, `.pgp`, `.jks`, `.keystore`).
  * **All-user scan** — walks `C:\Users\*` (excluding `Public`, `Default`, `Default User`, `All Users`) to catch other users' keys when the process runs with sufficient privileges. Inaccessible paths are skipped silently.
  * **Performance guards** — heavy directories (`Temp`, `Packages`, browser caches, `.cache`, `.gradle`, `node_modules`, `.vscode`, `OneDrive`, etc.) are pruned via `disable_recursion_pending()`. Global file cap and per-file size cap prevent runaway scans. Progress is logged every 10 000 files.

### 2.6 Post-Exploitation

* **`Pillaging.h`**:
  * Lightweight file-system pillaging module for `Desktop`, `Documents` and `Downloads`.
  * Recursively scans `.txt`, `.json`, `.xml`, `.config`, `.ini`, `.yaml`, `.yml` files.
  * Uses a case-insensitive regex (`password|passwd|pwd|secret|api_key|token|credentials`) to surface lines that likely contain credentials.

### 2.7 Third-Party Libraries

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

## 4. Why App-Bound Encryption (Chromium v20+) Is Out of Scope

Starting with Chrome 127 and Edge 127, Chromium browsers introduced **App-Bound Encryption (ABE)** to defend against exactly the kind of cookie and credential theft this PoC demonstrates. ABE raises the bar significantly by binding the encryption key to the browser's own code integrity, not just the user's DPAPI context.

**Key changes:**

* The `Local State` file now stores a second encrypted key under `os_crypt.app_bound_encrypted_key`.
* The key is wrapped twice: once with **SYSTEM-scoped DPAPI**, and once with **user-scoped DPAPI** — meaning a plain user-context `CryptUnprotectData` call is no longer sufficient.
* The final unwrap is performed by a hardcoded AES key embedded inside `elevation_service.exe` (Chrome) or `msedge_elevation_service.exe` (Edge), which is only accessible from an elevated context.

**Why this PoC does not implement ABE:**

* **Administrator privileges** would be required for SYSTEM impersonation — incompatible with a pure user-context tool.
* **`DuplicateTokenEx` + `ImpersonateLoggedOnUser`** generate immediate EDR telemetry and are not stealthy.
* **The hardcoded key rotates** between browser versions, making any implementation brittle and short-lived.

As a result, the project focuses on `v10` / `v11` (AES-256-GCM + DPAPI), which remain in use by Chrome, Brave, Vivaldi and Opera, and which can be decrypted entirely within the current user context.

---

## 5. Roadmap: Planned Extensions

The project is intentionally structured so that additional modules can be dropped in without changing the existing ones. The two areas below are **planned** and marked as future work.

### 5.1 Password Manager Vaults

Password managers are attractive PoC targets because they combine two distinct security layers:

* An **unlock layer** — often DPAPI-protected (Windows User Account component, biometric key, device key).
* A **vault layer** — encrypted with the manager's own key derivation (AES / ChaCha20 + master password).

A future module would target the unlock layer through DPAPI, and document the vault layer without attempting to break the underlying cryptographic construction. Candidates:

* **KeePass** — `ProtectedUserKey.bin` (Windows User Account component), decryptable with `CryptUnprotectData`.
* **Bitwarden** — `data.json` biometric key protected by DPAPI.
* **1Password** — device key, partially DPAPI-protected.

The goal is to demonstrate where DPAPI is — and where it is not — the actual security boundary.

### 5.2 Crypto Wallet Credentials

Many wallet applications use DPAPI to protect **saved configuration** and **session tokens**, even when the private keys themselves are encrypted with the wallet's own key derivation. A future module would target the DPAPI-protected layer only:

* Configuration files, saved passwords, session tokens.
* Documented case studies of real-world infostealers that abuse DPAPI-protected wallet data.

Extraction of private keys, seed phrases, or mnemonics is **explicitly out of scope** — this PoC remains a credential-harvesting research tool, not a crypto-stealer.

### 5.3 Additional Future Work

* **Full Windows Vault extraction** via the native COM API (`VaultEnumerateVaults`, `VaultGetItem`) to recover plaintext secrets.
* **CREDHIST** — DPAPI password history chain, with offline recovery support via Hashcat modes 15920 (3DES) and 15930 (AES-256).
* **Additional browser coverage** — Opera GX, Yandex Browser, Waterfox, Pale Moon.
* **Multi-profile iteration** for Chromium browsers (`Default`, `Profile 1`, `Profile 2`, …).
* **Firefox `key4.db` + `logins.json`** password decryption (NSS PBE).
* **JSON report export** for automated processing and MITRE ATT&CK mapping.

---

## 6. Project Compilation Guidelines

To compile the modular source code successfully within a Windows environment utilizing MSYS2 and the MinGW toolchain, execute the following command in the terminal:


```
g++ main.cpp sqlite3.o -o DPAPI_PoC.exe -std=c++17 -O2 -lcrypt32 -lbcrypt -ladvapi32 -lwlanapi -lncrypt -lole32 -luuid -lshell32 -lshlwapi -static
```

---

## 7. Project Layout

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
### 7.1 Files Ignored by Git

The following artefacts are present locally but excluded from the repository via `.gitignore`:

* **`sqlite3.c`** — the SQLite amalgamation source file.
* **`sqlite3.o`** — the compiled SQLite object file linked directly into the PoC.
* **`libsqlite3.a`** — the static SQLite archive, provided as an alternative linking option.
* **`DPAPI_PoC.exe`** — the compiled PoC binary.

As a result, a fresh clone contains only the headers, `main.cpp`, `sqlite3.h`, and the documentation. To build the project, the SQLite amalgamation must be compiled locally (or the pre-built `.o` / `.a` artefacts must be copied in manually) before running the build command.

---

## 8. MITRE ATT&CK Mapping

| Module | Technique | ID | Notes |
|---|---|---|---|
| `SystemCredentialsDump.h` (CredMan) | Credentials from Password Stores: Windows Credential Manager | T1555.004 | Direct match — `CredEnumerateW` queries the Credential Manager store. |
| `SystemCredentialsDump.h` (Wi-Fi) | Credentials from Password Stores | T1555 | Could also be classified under T1552.001 when Wi-Fi profiles are treated as XML config files. |
| `SystemCredentialsDump.h` (BitLocker) | Credentials from Password Stores | T1555 | Recovery keys may also live in files (T1552.001); DPAPI-protected registry values are the primary target here. |
| `SystemCredentialsDump.h` (Certificates) | Unsecured Credentials: Private Keys | T1552.004 | Certificate private keys exported via CAPI / CNG. |
| `DpapiMasterKeys.h` | Credentials from Password Stores | T1555 | In some reporting this overlaps with OS Credential Dumping (T1003); T1555 is the credential-store-centric view. |
| `VaultDump.h` | Credentials from Password Stores: Windows Credential Manager | T1555.004 | Windows Vault shares its backend with Credential Manager. Full plaintext extraction (COM API) would keep the same ID. |
| `ChromiumDump.h` | Credentials from Web Browsers | T1555.003 | Passwords and cookies from Chromium-based browsers (Chrome, Edge, Brave, Vivaldi, Opera). |
| `GeckoAndIECookies.h` | Steal Web Session Cookie | T1539 | **Primary:** the module harvests session cookies, not saved passwords. T1555.003 would apply only if `logins.json` were parsed. |
| `RdpDump.h` | Credentials from Password Stores | T1555 | Could also be classified under T1552.001 — RDCMan `.rdg` and mstsc `.rdp` are config files on disk. |
| `DevCredentialsDump.h` | Unsecured Credentials: Credentials In Files | T1552.001 | AWS, Azure, GCloud, NPM, PyPI, Netrc, Terraform, Docker, Kubernetes, mRemoteNG configs. |
| `CryptoKeysDump.h` (SSH, GPG, VPN) | Unsecured Credentials: Private Keys | T1552.004 | SSH `id_*`, GnuPG `private-keys-v1.d`, WireGuard and OpenVPN key material. |
| `CryptoKeysDump.h` (Cloud CLI, configs) | Unsecured Credentials: Credentials In Files | T1552.001 | Plaintext cloud CLI configurations and `.netrc`-style credential files. |
| `Pillaging.h` | Data from Local System | T1005 | Generic file-system collection across Desktop, Documents and Downloads. |

### 8.1 Mapping Notes

* **`GeckoAndIECookies.h`** — the module currently reads `cookies.sqlite` (Firefox / Tor) and legacy IE `.txt` cookie files. It does **not** decrypt Firefox `logins.json`. If password extraction is added in a future iteration, the module should be mapped **twice**: T1539 (Steal Web Session Cookie) for cookies and T1555.003 (Credentials from Web Browsers) for saved passwords.

* **`VaultDump.h`** — while the module currently only surfaces metadata (target, username, AppContainer SID) rather than plaintext secrets, the targeted store is the same as Windows Credential Manager, so T1555.004 remains the correct classification regardless of whether COM extraction is later added.

* **`ChromiumDump.h` / `ChromiumV20.h`** — Chromium v20 App-Bound Encryption was intentionally omitted from this PoC (see section 4). If a future iteration implements ABE decryption, the technique ID stays T1555.003 but the module gains administrator-level SYSTEM impersonation as a prerequisite.

* **`RdpDump.h`** and **`SystemCredentialsDump.h` (Wi-Fi)** — both operate on artefacts that live in files (`%USERPROFILE%\Documents\*.rdp`, `%USERPROFILE%\Documents\*.rdg`, Wi-Fi profile XMLs). Analysts who prefer the file-centric view can reasonably map these to T1552.001 in addition to the primary T1555.
---

## 9. Operational Security Notes

* **No network activity.** Every module operates strictly against local files, the registry and Win32 APIs. There is no C2, no exfiltration, no beaconing.
* **No persistence.** The binary does not install itself, modify autostart keys or schedule tasks. It is a one-shot harvester.
* **No privilege escalation.** Every module runs in the context of the invoking user. `CryptoKeysDump.h` will silently skip other users' profiles if the process lacks the necessary rights.
* **Evidence left behind.** Reading `Login Data`, `Cookies`, `Local State` and registry keys leaves file-access artefacts; `CryptUnprotectData` calls are visible to EDR / ETW. This PoC is not stealthy by design — it is intended for controlled lab use where detection is part of the exercise.

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

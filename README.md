# Windows DPAPI & Security Credentials Abuse: Comprehensive Technical Overview

## 1. Introduction: Convenience vs. Security
**"How Windows made security comfortable, but failed a little bit"**

Modern operating systems face a fundamental design paradox: how to protect highly sensitive user secrets—such as browser credentials, Wi-Fi keys, and master encryption keys—while ensuring a completely seamless, friction-free user experience. Windows resolves this tension through the **Data Protection API (DPAPI)**, a cryptographic subsystem designed to transparently protect data using keys derived directly from the user's login credentials or the local system context.

This architecture fundamentally prioritizes user convenience. Because DPAPI operates automatically within the active user's session context, any code executed under that user's security rights can invoke the API to unprotect secrets without prompting for a password or multi-factor verification. The operating system implicitly assumes that if a user is authenticated, any application executing within their session context is trustworthy. 

Consequently, this creates a significant security gap. Malware, unauthorized scripts, or local privilege escalation vectors running under a standard user account can effortlessly harvest plaintext Wi-Fi passwords, browser cookies, application tokens, and private cryptographic keys without ever needing to brute-force a master password.

---

## 2. Comprehensive Technical Module Breakdown

* **`main.cpp`**: 
  * Acts as the primary execution entry point.
  * Handles console encoding initialization (`SetConsoleOutputCP(CP_UTF8)`) to correctly render text output.
  * Sequentially orchestrates the execution flow across all underlying system and browser exfiltration modules.

* **`SystemCredentialsDump.h`**: 
  * Manages the core Windows operating system credential harvesting layer.
  * Utilizes `CredEnumerateW` to query and dump stored credentials directly from the *Windows Credential Manager*.
  * Interfaces with the native WLAN API (`WlanOpenHandle`, `WlanEnumInterfaces`, `WlanGetProfile`) combined with the `WLAN_PROFILE_GET_PLAINTEXT_KEY` flag to force DPAPI into unprotecting and extracting plaintext Wi-Fi profiles and network keys.
  * Scans the user registry hive (`HKCU\Software\Microsoft\Windows\CurrentVersion\FVEAutoUnlock`) for BitLocker volume auto-unlock keys protected by the user's DPAPI scope.
  * Enumerates the personal certificate store (`MY` / `Personal`), evaluates certificate contexts for associated private keys via `CryptAcquireCertificatePrivateKey`, and exports them in PEM format for both CAPI (RSA) and CNG (PKCS#8) providers.

* **`ChromiumDump.h`**: 
  * Automates the targeted harvesting of sensitive credentials from Chromium-based browsers (Google Chrome, Microsoft Edge, Brave Browser, Vivaldi, Opera).
  * Bypasses active file-sharing locks on locked browser SQLite databases by dynamically copying *Login Data* and *Network/Cookies* databases to the local temporary folder (`GetTempPathW`).
  * Parses structured SQL databases using custom queries (`SELECT origin_url, username_value, password_value FROM logins;` and `SELECT host_key, name, encrypted_value FROM cookies;`) to isolate encrypted payloads.

* **`CryptoEngine.h`**: 
  * Functions as the core cryptographic helper library for decryption routines.
  * Implements `DecryptDPAPI` utilizing `CryptUnprotectData` to reverse standard DPAPI blobs (such as legacy cookies or Master Key containers).
  * Parses browser configuration files (`Local State`) to locate base64-encoded, DPAPI-protected Master Keys prefixed with the `DPAPI` magic bytes, unprotecting them to recover the active 32-byte binary key.
  * Implements advanced AES-256-GCM authenticated decryption using the Windows CNG library (`BCryptOpenAlgorithmProvider`, `BCryptImportKey`, `BCryptDecrypt`) combined with extracted initialization vectors (IV) and authentication tags to extract modern browser credentials.

* **`GeckoAndIECookies.h`**: 
  * Extends cookie harvesting capabilities to alternative browser ecosystems.
  * Locates Mozilla Firefox and Tor Browser profiles within `%APPDATA%`, querying the `cookies.sqlite` database using SQL statements (`SELECT host, name, value, path, isSecure, isHttpOnly, expiry FROM moz_cookies;`) to extract plaintext session cookies.
  * Scans legacy Internet Explorer cookie storage paths (`%APPDATA%\Microsoft\Windows\Cookies`) to read plaintext `.txt` cookie files.

* **`sqlite3.h` & `sqlite3.o`**: 
  * A static implementation of the SQLite database engine.
  * Linked directly into the project to give compiled binaries the native capability to parse embedded database architectures without requiring external DLL dependencies on the target host.

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

## 4. Project Compilation Guidelines

To compile the modular source code successfully within a Windows environment utilizing MSYS2 and the MinGW toolchain, execute the following command in the terminal:

```bash
g++ main.cpp sqlite3.o -o DPAPI_PoC.exe -lcrypt32 -lbcrypt -ladvapi32 -lwlanapi -lncrypt -lole32 -luuid
```
<div style="border: 3px solid #cc0000; background-color: transparent; padding: 20px; border-radius: 6px; color: #FFFF; font-family: inherit;">

<strong>DISCLAIMER</strong>

The author of this code (and the person providing this response) ASSUMES NO LIABILITY whatsoever for any damages, losses, or legal consequences arising from the use, modification, or redistribution of this tool.

By using this code, you explicitly agree to the following CONDITIONS:
1. You may use it SOLELY in environments where you hold explicit, written permission from the legitimate owner.
2. The recommended testing environment is an ISOLATED VIRTUAL LABORATORY (e.g., offline VMs with no connection to production networks).
3. Any attempt to deploy this code against systems, networks, or data without proper authorization constitutes a CRIMINAL OFFENSE and violates applicable laws (including the Computer Fraud and Abuse Act and similar international regulations).

<strong>THE USER BEARS FULL CRIMINAL AND CIVIL LIABILITY for all actions performed using this tool.</strong>

</div>
*(Note: Yes, I used AI because after sitting for 6 hours I asked AI and it said it didn't really know where the error was - after 10 prompts it finally said that well, the wlanapi library can block with wcout-s)*
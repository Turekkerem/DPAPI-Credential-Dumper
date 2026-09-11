#ifndef PILLAGING_H
#define PILLAGING_H

#include <windows.h>
#include <shlobj.h>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <regex>

namespace Pillaging {

    inline void ScanFile(const std::filesystem::path& p) {
        std::ifstream f(p, std::ios::binary);
        if (!f) return;
        std::string content((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());

        std::regex re(
            "(password|passwd|pwd|secret|api_key|token|credentials)\\s*[:=]\\s*\\S+",
            std::regex::icase);

        std::smatch m;
        std::string::const_iterator start(content.cbegin());
        bool found = false;

        while (std::regex_search(start, content.cend(), m, re)) {
            if (!found) {
                std::cout << "\n[+] " << p.string() << "\n";
                found = true;
            }
            std::cout << "    " << m.str() << "\n";
            start = m.suffix().first;
        }
    }

    inline void Run() {
        std::cout << "\n=== File Pillaging ===\n";

        const char* up = std::getenv("USERPROFILE");
        if (!up) return;

        std::vector<std::filesystem::path> dirs = {
            std::filesystem::path(up) / "Desktop",
            std::filesystem::path(up) / "Documents",
            std::filesystem::path(up) / "Downloads"
        };

        for (auto& dir : dirs) {
            if (!std::filesystem::exists(dir)) continue;
            try {
                for (auto& p : std::filesystem::recursive_directory_iterator(dir)) {
                    if (!p.is_regular_file()) continue;
                    auto ext = p.path().extension().wstring();
                    if (ext == L".txt" || ext == L".json" || ext == L".xml" ||
                        ext == L".config" || ext == L".ini" || ext == L".yaml" ||
                        ext == L".yml") {
                        ScanFile(p.path());
                    }
                }
            } catch (...) {}
        }
    }
}

#endif
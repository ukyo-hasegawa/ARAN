#include <iostream>
#include <string>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <cstring>

// RSA鍵管理
class RSAKeyManager {
public:
    // 鍵ペアの生成
    static EVP_PKEY* generateKeyPair() {
        EVP_PKEY* pkey = EVP_PKEY_new();
        if (!pkey) {
            std::cerr << "Failed to create EVP_PKEY!" << std::endl;
            exit(EXIT_FAILURE);
        }

        RSA* rsa = RSA_new();
        if (!rsa) {
            std::cerr << "Failed to create RSA object!" << std::endl;
            EVP_PKEY_free(pkey);
            exit(EXIT_FAILURE);
        }

        BIGNUM* e = BN_new();
        if (!BN_set_word(e, RSA_F4)) {
            std::cerr << "Failed to set public exponent!" << std::endl;
            RSA_free(rsa);
            EVP_PKEY_free(pkey);
            BN_free(e);
            exit(EXIT_FAILURE);
        }

        if (!RSA_generate_key_ex(rsa, 2048, e, nullptr)) {
            std::cerr << "Failed to generate RSA key pair!" << std::endl;
            RSA_free(rsa);
            EVP_PKEY_free(pkey);
            BN_free(e);
            exit(EXIT_FAILURE);
        }

        EVP_PKEY_assign_RSA(pkey, rsa);
        BN_free(e);
        return pkey;
    }

    // メッセージ署名
    static std::string signMessage(const std::string& message, EVP_PKEY* privateKey) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            std::cerr << "Failed to create EVP_MD_CTX!" << std::endl;
            exit(EXIT_FAILURE);
        }

        if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, privateKey) <= 0) {
            std::cerr << "EVP_DigestSignInit failed!" << std::endl;
            EVP_MD_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }

        if (EVP_DigestSignUpdate(ctx, message.c_str(), message.size()) <= 0) {
            std::cerr << "EVP_DigestSignUpdate failed!" << std::endl;
            EVP_MD_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }

        size_t signature_len = 0;
        if (EVP_DigestSignFinal(ctx, nullptr, &signature_len) <= 0) {
            std::cerr << "EVP_DigestSignFinal failed to calculate signature length!" << std::endl;
            EVP_MD_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }

        std::vector<unsigned char> signature(signature_len);
        if (EVP_DigestSignFinal(ctx, signature.data(), &signature_len) <= 0) {
            std::cerr << "EVP_DigestSignFinal failed to generate signature!" << std::endl;
            EVP_MD_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }

        EVP_MD_CTX_free(ctx);
        return std::string(signature.begin(), signature.end());
    }

    // メッセージの検証
    static bool verifyMessage(const std::string& message, const std::string& signature, EVP_PKEY* publicKey) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            std::cerr << "Failed to create EVP_MD_CTX!" << std::endl;
            exit(EXIT_FAILURE);
        }

        if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, publicKey) <= 0) {
            std::cerr << "EVP_DigestVerifyInit failed!" << std::endl;
            EVP_MD_CTX_free(ctx);
            return false;
        }

        if (EVP_DigestVerifyUpdate(ctx, message.c_str(), message.size()) <= 0) {
            std::cerr << "EVP_DigestVerifyUpdate failed!" << std::endl;
            EVP_MD_CTX_free(ctx);
            return false;
        }

        bool is_valid = EVP_DigestVerifyFinal(ctx, (unsigned char*)signature.c_str(), signature.size()) == 1;

        EVP_MD_CTX_free(ctx);
        return is_valid;
    }
};
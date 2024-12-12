#include <iostream>
#include <string>
#include <vector>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <cstring>
#include <map>

// RSA鍵管理
class RSAKeyManager {
public:
    static RSA* generateKeyPair() {
        RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
        if (!rsa) {
            std::cerr << "Failed to generate RSA key pair!" << std::endl;
            exit(EXIT_FAILURE);
        }
        return rsa;
    }

    static std::string signMessage(const std::string& message, RSA* privateKey) {
        unsigned char signature[256];
        unsigned int signature_len;

        if (!RSA_sign(NID_sha256, (const unsigned char*)message.c_str(), message.size(),
                      signature, &signature_len, privateKey)) {
            std::cerr << "Error signing message!" << std::endl;
            exit(EXIT_FAILURE);
        }
        return std::string((char*)signature, signature_len);
    }

    static bool verifyMessage(const std::string& message, const std::string& signature, RSA* publicKey) {
        return RSA_verify(NID_sha256, (const unsigned char*)message.c_str(), message.size(),
                          (const unsigned char*)signature.c_str(), signature.size(), publicKey);
    }
};
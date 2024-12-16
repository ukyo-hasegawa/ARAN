#ifndef RSA
#define RSA

#include <openssl/evp.h>
#include <string>
#include <vector>

class RSAUtils {
public:
    // キーペアの生成
    static EVP_PKEY* createRSAKeyPair();

    // 公開鍵をPEM形式で取得
    static std::string getPublicKey(EVP_PKEY* pkey);

    // 秘密鍵をPEM形式で取得
    static std::string getPrivateKey(EVP_PKEY* pkey);

    // メッセージの暗号化
    static std::vector<unsigned char> encryptMessage(EVP_PKEY* pkey, const std::string& message);

    // メッセージの復号
    static std::string decryptMessage(EVP_PKEY* pkey, const std::vector<unsigned char>& encryptedMessage);
};

#endif
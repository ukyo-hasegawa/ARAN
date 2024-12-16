#ifndef RSA_UTILS_H
#define RSA_UTILS_H

#include <openssl/evp.h>
#include <string>
#include <vector>

// キーペアの生成
EVP_PKEY* createRSAKeyPair();

// 公開鍵をPEM形式で取得
std::string getPublicKey(EVP_PKEY* pkey);

// 秘密鍵をPEM形式で取得
std::string getPrivateKey(EVP_PKEY* pkey);

// メッセージの暗号化
std::vector<unsigned char> encryptMessage(EVP_PKEY* pkey, const std::string& message);

// メッセージの復号
std::string decryptMessage(EVP_PKEY* pkey, const std::vector<unsigned char>& encryptedMessage);

// メッセージに署名を付与
std::vector<unsigned char> signMessage(EVP_PKEY* privateKey, const std::string& message);

// 署名の検証
bool verifySignature(EVP_PKEY* publicKey, const std::string& message, const std::vector<unsigned char>& signature);

#endif // RSA_UTILS_H
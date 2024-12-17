#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <string>
#include <chrono>
#include <ctime>
#include <vector>
#include "RSA.h"

// キーペアの生成
EVP_PKEY* createRSAKeyPair() {
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cerr << "鍵生成の初期化に失敗しました。" << std::endl;
        return NULL;
    }

    // RSA鍵長を2048ビットに設定
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        std::cerr << "鍵長の設定に失敗しました。" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    // キーペア生成
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cerr << "キーペア生成に失敗しました。" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// 公開鍵をPEM形式で取得
std::string getPublicKey(EVP_PKEY* pkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);

    size_t pubKeyLen = BIO_pending(bio);
    std::vector<char> pubKey(pubKeyLen + 1);
    BIO_read(bio, pubKey.data(), pubKeyLen);
    pubKey[pubKeyLen] = '\0';

    BIO_free_all(bio);
    return std::string(pubKey.data());
}

// 秘密鍵をPEM形式で取得
std::string getPrivateKey(EVP_PKEY* pkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);

    size_t privKeyLen = BIO_pending(bio);
    std::vector<char> privKey(privKeyLen + 1);
    BIO_read(bio, privKey.data(), privKeyLen);
    privKey[privKeyLen] = '\0';

    BIO_free_all(bio);
    return std::string(privKey.data());
}

// メッセージの暗号化
std::vector<unsigned char> encryptMessage(EVP_PKEY* pkey, const std::string& message) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0) {
        std::cerr << "暗号化の初期化に失敗しました。" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    // 出力バッファのサイズを取得
    size_t outLen;
    if (EVP_PKEY_encrypt(ctx, NULL, &outLen, reinterpret_cast<const unsigned char*>(message.c_str()), message.size()) <= 0) {
        std::cerr << "暗号化サイズの取得に失敗しました。" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    std::vector<unsigned char> encryptedMessage(outLen);
    if (EVP_PKEY_encrypt(ctx, encryptedMessage.data(), &outLen, reinterpret_cast<const unsigned char*>(message.c_str()), message.size()) <= 0) {
        std::cerr << "暗号化に失敗しました。" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    EVP_PKEY_CTX_free(ctx);
    encryptedMessage.resize(outLen); // 実際のデータサイズに調整
    return encryptedMessage;
}

// メッセージの復号
std::string decryptMessage(EVP_PKEY* pkey, const std::vector<unsigned char>& encryptedMessage) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0) {
        std::cerr << "復号の初期化に失敗しました。" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    // 出力バッファのサイズを取得
    size_t outLen;
    if (EVP_PKEY_decrypt(ctx, NULL, &outLen, encryptedMessage.data(), encryptedMessage.size()) <= 0) {
        std::cerr << "復号サイズの取得に失敗しました。" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> decryptedMessage(outLen);
    if (EVP_PKEY_decrypt(ctx, decryptedMessage.data(), &outLen, encryptedMessage.data(), encryptedMessage.size()) <= 0) {
        std::cerr << "復号に失敗しました。" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    EVP_PKEY_CTX_free(ctx);
    decryptedMessage.resize(outLen); // 実際のデータサイズに調整
    return std::string(decryptedMessage.begin(), decryptedMessage.end());
}

// メッセージに署名を付与
std::vector<unsigned char> signMessage(EVP_PKEY* privateKey, const std::string& message) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "署名コンテキストの作成に失敗しました。" << std::endl;
        return {};
    } else {
        std::cout << "generate signature" << std::endl;
    }

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, privateKey) <= 0) {
        std::cerr << "署名の初期化に失敗しました。" << std::endl;
        EVP_MD_CTX_free(ctx);
        return {};
    }

    size_t sigLen;
    if (EVP_DigestSign(ctx, NULL, &sigLen, reinterpret_cast<const unsigned char*>(message.c_str()), message.size()) <= 0) {
        std::cerr << "署名長の取得に失敗しました。" << std::endl;
        EVP_MD_CTX_free(ctx);
        return {};
    } 

    std::vector<unsigned char> signature(sigLen);
    if (EVP_DigestSign(ctx, signature.data(), &sigLen, reinterpret_cast<const unsigned char*>(message.c_str()), message.size()) <= 0) {
        std::cerr << "署名の生成に失敗しました。" << std::endl;
        EVP_MD_CTX_free(ctx);
        return {};
    }

    EVP_MD_CTX_free(ctx);
    signature.resize(sigLen);
    return signature;
}

// 署名の検証
bool verifySignature(EVP_PKEY* publicKey, const std::string& message, const std::vector<unsigned char>& signature) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "検証コンテキストの作成に失敗しました。" << std::endl;
        return false;
    }

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, publicKey) <= 0) {
        std::cerr << "検証の初期化に失敗しました。" << std::endl;
        EVP_MD_CTX_free(ctx);
        return false;
    }

    int result = EVP_DigestVerify(ctx, signature.data(), signature.size(), reinterpret_cast<const unsigned char*>(message.c_str()), message.size());
    EVP_MD_CTX_free(ctx);

    if (result == 1) {
        return true; // 検証成功
    } else if (result == 0) {
        std::cerr << "署名が一致しません。" << std::endl;
    } else {
        std::cerr << "検証中にエラーが発生しました。" << std::endl;
    }
    return false;
}


/*
署名生成及び検証用main関数
int main() {
    // キーペア生成
    EVP_PKEY* pkey = createRSAKeyPair();
    if (!pkey) {
        return -1;
    }

    std::string message;
    std::cout << "署名するメッセージを入力してください: ";
    std::getline(std::cin, message);

    // 署名の生成
    std::vector<unsigned char> signature = signMessage(pkey, message);
    if (signature.empty()) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    std::cout << "生成された署名 (バイナリデータ):" << std::endl;
    for (unsigned char c : signature) {
        printf("%02X", c);
    }
    std::cout << std::endl;

    // 公開鍵の取得
    std::string publicKeyPEM = getPublicKey(pkey);
    std::cout << "\n公開鍵 (PEM形式):\n" << publicKeyPEM << std::endl;

    // 署名の検証
    bool isValid = verifySignature(pkey, message, signature);
    std::cout << "署名の検証結果: " << (isValid ? "成功" : "失敗") << std::endl;

    // メモリの解放
    EVP_PKEY_free(pkey);

    return 0;
}
*/
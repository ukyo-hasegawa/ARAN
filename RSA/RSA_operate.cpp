#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <string>

#include <vector>

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

int main() {
    // キーペアの生成
    EVP_PKEY* pkey = createRSAKeyPair();
    if (!pkey) {
        return -1;
    }

    std::string message;
    // 平文の入力
    std::cout << "平文を入力してください: ";
    std::getline(std::cin, message);

    // 公開鍵と秘密鍵の取得と表示
    std::string publicKey = getPublicKey(pkey);
    std::string privateKey = getPrivateKey(pkey);
    std::cout << "\n公開鍵:\n" << publicKey << std::endl;
    std::cout << "秘密鍵:\n" << privateKey << std::endl;

    // メッセージの暗号化
    auto encryptedMessage = encryptMessage(pkey, message);
    if (encryptedMessage.empty()) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    std::cout << "暗号化された文字列 (バイナリデータ):" << std::endl;
    for (unsigned char c : encryptedMessage) {
        printf("%02X", c);
    }
    std::cout << std::endl;

    // メッセージの復号
    std::string decryptedMessage = decryptMessage(pkey, encryptedMessage);
    if (decryptedMessage.empty()) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    std::cout << "復号された文字列: " << decryptedMessage << std::endl;

    // EVP_PKEYの解放
    EVP_PKEY_free(pkey);

    return 0;
}
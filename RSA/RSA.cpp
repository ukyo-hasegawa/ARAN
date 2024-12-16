#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <string>

//コンパイラオプション
//g++ -o RSA.exe RSA.cpp -I"C:\Program Files\OpenSSL-Win64\include" -L"C:\Program Files\OpenSSL-Win64\lib\VC\x64\MTd" -lssl -lcrypto -Wno-deprecated-declarations

// キーペアの生成
RSA* createRSAKeyPair() {
    int keyLength = 2048;
    unsigned long e = RSA_F4; // 公開指数（通常はRSA_F4）

    RSA* rsa = RSA_generate_key(keyLength, e, NULL, NULL);
    if (rsa == NULL) {
        std::cerr << "鍵の生成に失敗しました" << std::endl;
        return NULL;
    }

    return rsa;
}

// 公開鍵をPEM形式で取得
std::string getPublicKey(RSA* rsa) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio, rsa);
    
    size_t pubKeyLen = BIO_pending(bio);
    char* pubKey = new char[pubKeyLen + 1];
    BIO_read(bio, pubKey, pubKeyLen);
    pubKey[pubKeyLen] = '\0';

    std::string publicKey(pubKey);
    delete[] pubKey;
    BIO_free_all(bio);

    return publicKey;
}

// 秘密鍵をPEM形式で取得
std::string getPrivateKey(RSA* rsa) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);

    size_t privKeyLen = BIO_pending(bio);
    char* privKey = new char[privKeyLen + 1];
    BIO_read(bio, privKey, privKeyLen);
    privKey[privKeyLen] = '\0';

    std::string privateKey(privKey);
    delete[] privKey;
    BIO_free_all(bio);

    return privateKey;
}

// メッセージの暗号化
std::string encryptMessage(RSA* rsa, const std::string& message) {
    size_t rsaLen = RSA_size(rsa);
    unsigned char* encryptedMessage = new unsigned char[rsaLen];

    int result = RSA_public_encrypt(message.length(), 
                                    reinterpret_cast<const unsigned char*>(message.c_str()), 
                                    encryptedMessage, 
                                    rsa, 
                                    RSA_PKCS1_PADDING);

    if (result == -1) {
        char* err = new char[130];
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        std::cerr << "暗号化に失敗しました " << err << std::endl;
        delete[] err;
        return "";
    }

    std::string encryptedString(reinterpret_cast<char*>(encryptedMessage), result);
    delete[] encryptedMessage;

    return encryptedString;
}

// メッセージの復号
std::string decryptMessage(RSA* rsa, const std::string& encryptedMessage) {
    size_t rsaLen = RSA_size(rsa);
    unsigned char* decryptedMessage = new unsigned char[rsaLen];

    int result = RSA_private_decrypt(encryptedMessage.length(), 
                                     reinterpret_cast<const unsigned char*>(encryptedMessage.c_str()), 
                                     decryptedMessage, 
                                     rsa, 
                                     RSA_PKCS1_PADDING);

    if (result == -1) {
        char* err = new char[130];
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        std::cerr << "復号に失敗しました" << err << std::endl;
        delete[] err;
        return "";
    }

    std::string decryptedString(reinterpret_cast<char*>(decryptedMessage), result);
    delete[] decryptedMessage;

    return decryptedString;
}

int main() {
    //キーペアの生成
    RSA* rsa = createRSAKeyPair();
    if (rsa == NULL) {
        return -1;
    }

    
    std::string message ;
    // 文字列の入力
    std::cout << "平文を入力してください: ";
    std::getline(std::cin,  message);

    //公開鍵と秘密鍵の取得と表示
    std::string publicKey = getPublicKey(rsa);
    std::string privateKey = getPrivateKey(rsa);
    std::cout << "\n公開鍵:\n" << publicKey << std::endl;
    std::cout << "秘密鍵:\n" << privateKey << std::endl;

    std::string encryptedMessage = encryptMessage(rsa, message);
    std::cout << "暗号化された文字列:\n-----BEGIN ENCRYPTED STRING-----\n" << encryptedMessage <<"\n-----END ENCRYPTED STRING-----\n"<< std::endl;

    //メッセージの復号
    std::string decryptedMessage = decryptMessage(rsa, encryptedMessage);
    std::cout << "復号された文字列: " << decryptedMessage << std::endl;

    //RSAオブジェクトの解放
    RSA_free(rsa);

    return 0;
}

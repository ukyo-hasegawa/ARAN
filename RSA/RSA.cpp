#include <openssl/evp.h>
#include <openssl/pem.h>
#include <iostream>

int main() {
    //RSA鍵ペア生成用のコンテキストを初期化、RSA鍵を指定。
    EVP_PKEY_CTX *KeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,NULL);
    //エラーチェック
    if (!KeyCtx) {
        std::cerr << "Failed to initialize KeyCtx" << std::endl;
        return 1;
    } else {
        std::cout << "KeyCtx initialize success" << std::endl;
    }

    //鍵生成の準備、KeyCtxに関連する設定を有効にする。
    if(EVP_PKEY_keygen_init(KeyCtx)<= 0) {
        std::cerr << "Failed to initialize Keygen" << std::endl;
        EVP_PKEY_CTX_free(KeyCtx);
        return 1;
    } else {
        std::cout << "Keygen initialize success" << std::endl;
    }

    //4096byteの鍵長を指定
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(KeyCtx, 4096) <= 0) {
        std::cerr << "Failed to set keygen bits" << std::endl;
        EVP_PKEY_CTX_free(KeyCtx);
        return 1;
    } else {
        std::cout << "Keygen_bits set up success" << std::endl;
    }

    //鍵構造をNULLで初期化
    EVP_PKEY *key = NULL;

    if (EVP_PKEY_keygen(KeyCtx, &key) <= 0) {
        std::cerr << "Failed to generate RSA key" << std::endl;
        EVP_PKEY_CTX_free(KeyCtx);
        return 1;
    } else {
        std::cout << "Generate RSA key success" << std::endl;
    }

    //コンテキストオブジェクトの解放
    EVP_PKEY_CTX_free(KeyCtx);
    
    //以下、秘密鍵生成のコード
    BIO *privateBIO = BIO_new(BIO_s_mem());

    PEM_write_bio_PrivateKey(privateBIO, key, NULL, NULL, 0, 0, NULL); 
    int privatekeyLen = BIO_pending(privateBIO);

    unsigned char *privateKeyChar = (unsigned char *) malloc(privatekeyLen);

    BIO_read(privateBIO, privateKeyChar, privatekeyLen);
    //この時点で秘密鍵を保存可能

    // privateKeyChar(秘密鍵) の内容を出力
    std::cout << "Private Key:\n" << privateKeyChar << std::endl;

    //以下公開鍵生成のコード
    BIO *publicBIO = BIO_new(BIO_s_mem());
    if(!publicBIO) {
        std::cerr << "Failed to create public BIO" << std::endl;
        return 1;
    }
    //PEM形式でkeyをpublicBIOに書き込む
    PEM_write_bio_PUBKEY(publicBIO, key);

    int publickeyLen = BIO_pending(publicBIO);
    //メモリ確保
    unsigned char *publicKeyChar = (unsigned char *) malloc(publickeyLen);

    BIO_read(publicBIO, publicKeyChar, publickeyLen);

    // publicKeyChar(公開鍵) の内容を出力
    std::cout << "Public Key:\n";

    unsigned char *rsaPublicKeyChar = publicKeyChar;

    BIO *rsaPublicBIO = BIO_new_mem_buf(rsaPublicKeyChar, -1);

    EVP_PKEY *rsaPublicKey = NULL;
    EVP_PKEY *publicKey = PEM_read_bio_PUBKEY(rsaPublicBIO, &rsaPublicKey, NULL, NULL);
    
    if (!publicKey) {
    std::cerr << "Failed to read public key from BIO" << std::endl;
    BIO_free(rsaPublicBIO);
    return 1;
    } else {
        std::cout << "Success Read public key from BIO" << std::endl;
    }

    // BIO を解放
    BIO_free(rsaPublicBIO);

    //EVP_PKEY *publicKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(publicKey, rsaPublicKey);

    EVP_CIPHER_CTX *rsaEncryptCtx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(rsaEncryptCtx);

    unsigned char *ek = (unsigned char *) malloc(EVP_PKEY_size(publicKey));
    int ekLen = 0;
    //ivのメモリを動的に確保
    unsigned char *iv = (unsigned char *) malloc(EVP_MAX_IV_LENGTH);

    EVP_SealInit(rsaEncryptCtx, EVP_aes_256_cbc(), &ek, &ekLen, iv, &publicKey, 1);
    
    std::string message = "test_message";

    const unsigned char* messageChar = (const unsigned char*) message.c_str();

    int messagegLen = message.size()+1;

    unsigned char *encryptedMessage = (unsigned char *) malloc(messagegLen + EVP_MAX_IV_LENGTH);

    int encryptedMessageLen = 0;
    int encryptedBlockLen = 0;

    EVP_SealUpdate(rsaEncryptCtx, encryptedMessage, &encryptedBlockLen, messageChar, messagegLen);
    encryptedMessageLen = encryptedBlockLen;

    EVP_SealFinal(rsaEncryptCtx, encryptedMessage+encryptedBlockLen, &encryptedBlockLen);
    encryptedMessageLen += encryptedBlockLen;

    unsigned char *rsaPrivateKeyChar = privateKeyChar;

    BIO *RSAPrivateBIO = BIO_new_mem_buf(rsaPublicKeyChar, -1);

    EVP_PKEY *rsaPrivateKey = NULL;
    PEM_read_bio_PrivateKey(RSAPrivateBIO, &rsaPrivateKey, NULL, NULL);

    EVP_PKEY *privateKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(privateKey, rsaPrivateKey);

    EVP_CIPHER_CTX *rsaDecryptCtx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(rsaDecryptCtx);

    EVP_OpenInit(rsaDecryptCtx, EVP_aes_256_cbc(), ek, ekLen, iv, privateKey);

    unsigned char *decryptedMessage = (unsigned char *) malloc(encryptedMessageLen + EVP_MAX_IV_LENGTH);

    int decryptedMessageLen = 0;
    int decryptedBlockLen = 0;

    EVP_OpenUpdate(rsaDecryptCtx, decryptedMessage, &decryptedBlockLen, encryptedMessage, decryptedMessageLen);
    decryptedBlockLen = decryptedBlockLen;

    EVP_OpenFinal(rsaDecryptCtx, decryptedMessage + decryptedBlockLen, &decryptedBlockLen);
    decryptedMessageLen += decryptedBlockLen;

    std::cout << "Encryptmessage:" << encryptedMessage << std::endl;
    std::cout << "Decryptmessage:" << decryptedMessage << std::endl; 

}
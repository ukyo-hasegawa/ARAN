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
    }

    //鍵生成の準備、KeyCtxに関連する設定を有効にする。
    if(EVP_PKEY_keygen_init(KeyCtx)<= 0) {
        std::cerr << "Failed to initialize Keygen" << std::endl;
        EVP_PKEY_CTX_free(KeyCtx);
        return 1;
    };

    //4096byteの鍵長を指定
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(KeyCtx, 4096) <= 0) {
        std::cerr << "Failed to set keygen bits" << std::endl;
        EVP_PKEY_CTX_free(KeyCtx);
        return 1;
    }

    //鍵構造をNULLで初期化
    EVP_PKEY *key = NULL;
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
    std::cout << "Private Key:\n" << publicKeyChar << std::endl;

    unsigned char *rsaPublicKeyChar = publicKeyChar;

    BIO *rsaPublicBIO = BIO_new_mem_buf(rsaPublicKeyChar, -1);

    RSA *rsaPublicKey = NULL;
    PEM_read_bio_RSA_PUBKEY(rsaPublicBIO, &rsaPublicKey, NULL, NULL);
















    

    




}
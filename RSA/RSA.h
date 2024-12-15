#include <openssl/evp.h>
#include <openssl/pem.h>

int main() {
    //RSA鍵ペア生成用のコンテキストを初期化、RSA鍵を指定。
    EVP_PKEY_CTX *KeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,NULL);
    //鍵生成の準備、KeyCtxに関連する設定を有効にする。
    EVP_PKEY_keygen_init(KeyCtx);

    //4096byteの鍵長を指定
    EVP_PKEY_CTX_set_rsa_keygen_bits(KeyCtx,4096);

    //鍵構造をNULLで初期化
    EVP_PKEY *key = NULL;
    //コンテキストオブジェクトの解放
    EVP_PKEY_CTX_free(KeyCtx);

    BIO *privateBIO = BIO_new(BIO_s_mem());

    PEM_write_bio_PrivateKey(privateBIO, key, NULL, NULL, 0, 0, NULL);

    int privatekeyLen = BIO_pending(privateBIO);

    unsigned char *privateKeyChar = (unsigned char *) malloc(privatekeyLen);

    BIO_read(privateBIO, privateKeyChar, privatekeyLen);
    //この時点で秘密鍵を保存可能







    

    




}
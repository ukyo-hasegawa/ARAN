#include <openssl/evp.h>

int main() {
    EVP_PKEY_CTX *KeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,NULL);

}
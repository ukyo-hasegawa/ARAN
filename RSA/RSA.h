#include <openssl/evp.h>
#include <openssl/pem.h>

int main() {
    EVP_PKEY_CTX *KeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,NULL);
    EVP_PKEY_keygen_init(KeyCtx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(KeyCtx,4096);
}
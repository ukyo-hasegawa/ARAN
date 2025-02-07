#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <iostream>

using namespace std;

// 秘密鍵を読み込む関数
EVP_PKEY* load_private_key(const string& filename) {
    FILE* file = fopen(filename.c_str(), "rb");
    if (!file) {
        cerr << "Failed to open private key file: " << filename << endl;
        return nullptr;
    }

    EVP_PKEY* pkey = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
    fclose(file);

    if (!pkey) {
        cerr << "Failed to load private key" << endl;
        ERR_print_errors_fp(stderr);
    }

    return pkey;
}

// 公開鍵を読み込む関数
EVP_PKEY* load_public_key(const string& filename) {
    FILE* file = fopen(filename.c_str(), "rb");
    if (!file) {
        cerr << "Failed to open public key file: " << filename << endl;
        return nullptr;
    }

    EVP_PKEY* pkey = PEM_read_PUBKEY(file, nullptr, nullptr, nullptr);
    fclose(file);

    if (!pkey) {
        cerr << "Failed to load public key" << endl;
        ERR_print_errors_fp(stderr);
    }

    return pkey;
}

int main() {
    EVP_PKEY* private_key = load_private_key("private_key.pem");
    if (!private_key) {
        cerr << "Error: Could not load private key!" << endl;
        return 1;
    }
    cout << "Private key loaded successfully!" << endl;

    EVP_PKEY* public_key = load_public_key("public_key.pem");
    if (!public_key) {
        cerr << "Error: Could not load public key!" << endl;
        EVP_PKEY_free(private_key);
        return 1;
    }
    cout << "Public key loaded successfully!" << endl;

    // メモリ解放
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);

    return 0;
}
#include <string>
#include <iostream>
#include <vector>
#include <random>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdint.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "RSA/RSA.h"

struct data_format {
    std::string type;
    std::string own_ip;
    std::string dest_ip;
    std::string cert;
    std::uint32_t n;
    std::string t;
    std::string expires;
    std::vector<unsigned char> signature;
};

// 秘密鍵を読み込む
EVP_PKEY* load_private_key(const std::string& filename) {
    FILE* file = fopen(filename.c_str(), "rb");
    if (!file) {
        std::cerr << "Failed to open private key file: " << filename << std::endl;
        return nullptr;
    }
    EVP_PKEY* private_key = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
    fclose(file);
    return private_key;
}

// 公開鍵を読み込む
EVP_PKEY* load_public_key(const std::string& filename) {
    FILE* file = fopen(filename.c_str(), "rb");
    if (!file) {
        std::cerr << "Failed to open public key file: " << filename << std::endl;
        return nullptr;
    }
    EVP_PKEY* public_key = PEM_read_PUBKEY(file, nullptr, nullptr, nullptr);
    fclose(file);
    return public_key;
}

// 有効期限を計算
std::string calculateExpirationTime(int durationHours) {
    auto now = std::chrono::system_clock::now();
    auto expirationTime = now + std::chrono::hours(durationHours);
    std::time_t expiration = std::chrono::system_clock::to_time_t(expirationTime);
    std::tm* localExpiration = std::localtime(&expiration);
    std::ostringstream timeStream;
    timeStream << std::put_time(localExpiration, "%Y-%m-%d %H:%M:%S");
    return timeStream.str();
}

int main() {
    EVP_PKEY* public_key = load_public_key("public_key.pem");
    if (!public_key) return 1;

    EVP_PKEY* private_key = load_private_key("private_key.pem");
    if (!private_key) return 1;

    // 現在時刻の取得
    auto now = std::chrono::system_clock::now();
    std::time_t currentTime = std::chrono::system_clock::to_time_t(now);
    std::tm* localTime = std::localtime(&currentTime);
    std::ostringstream timeStream;
    timeStream << std::put_time(localTime, "%Y-%m-%d %H:%M:%S");
    std::string formattedTime = timeStream.str();

    std::string expirationTime = calculateExpirationTime(24);

    // 公開鍵を取得して証明書に含める
    std::string publicKeyPEM = getPublicKey(public_key);
    std::string cert_info = publicKeyPEM + "," + formattedTime + "," + expirationTime;

    data_format test_rdp1 = {
        "RDP",
        "10.0.0.1",
        "10.0.0.2",
        cert_info,
        std::random_device()(),
        formattedTime,
        expirationTime,
        {}
    };

    // 署名対象メッセージを作成
    std::ostringstream messageStream;
    messageStream << test_rdp1.type << "|"
                  << test_rdp1.dest_ip << "|"
                  << test_rdp1.cert << "|"
                  << test_rdp1.n << "|"
                  << test_rdp1.t;
    std::string message = messageStream.str();

    // 署名の生成
    test_rdp1.signature = signMessage(private_key, message);
    if (test_rdp1.signature.empty()) return -1;

    // シリアライズ処理
    std::vector<uint8_t> buf;
    auto serialize_string = [&buf](const std::string& str) {
        std::uint32_t len = str.size();
        buf.push_back((len >> 0) & 0xFF);
        buf.push_back((len >> 8) & 0xFF);
        buf.push_back((len >> 16) & 0xFF);
        buf.push_back((len >> 24) & 0xFF);
        buf.insert(buf.end(), str.begin(), str.end());
    };

    serialize_string(test_rdp1.type);
    serialize_string(test_rdp1.dest_ip);
    serialize_string(test_rdp1.cert);

    for (int i = 0; i < 4; i++) {
        buf.push_back((test_rdp1.n >> (8 * i)) & 0xFF);
    }

    serialize_string(test_rdp1.t);
    serialize_string(std::string(test_rdp1.signature.begin(), test_rdp1.signature.end()));

    // 送信処理
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 1;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);
    addr.sin_addr.s_addr = inet_addr("10.0.0.2");

    if (sendto(sock, buf.data(), buf.size(), 0, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(sock);
        return 1;
    } else {
        std::cout << "send success" << std::endl;
    }

    close(sock);
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);
    return 0;
}
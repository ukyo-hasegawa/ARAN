#include <string>
#include <iostream>
#include <fstream>
#include <cstring>

struct Certificate_Format {
    std::string own_ip[16];
    std::string t[20];
    std::string expires[20];
};

// Function to serialize the Certificate_Format structure
void serialize_to_buffer(const Certificate_Format& cert, char* buf, size_t buf_size) {
    if (buf_size < 2048) {
        std::cerr << "Buffer size is too small for serialization." << std::endl;
        return;
    }

    size_t offset = 0;

    // シリアライズ: own_ip
    for (const auto& ip : cert.own_ip) {
        std::memcpy(buf + offset, ip.c_str(), 16);
        offset += 16;
    }

    // シリアライズ: t
    for (const auto& t : cert.t) {
        std::memcpy(buf + offset, t.c_str(), 20);
        offset += 20;
    }

    // シリアライズ: expires
    for (const auto& expires : cert.expires) {
        std::memcpy(buf + offset, expires.c_str(), 20);
        offset += 20;
    }
}

void deserialize_from_buffer(Certificate_Format& cert, const char* buf, size_t buf_size) {
    if (buf_size < 2048) {
        std::cerr << "Buffer size is too small for deserialization." << std::endl;
        return;
    }

    size_t offset = 0;

    // デシリアライズ: own_ip
    for (auto& ip : cert.own_ip) {
        char temp[16] = {};
        std::memcpy(temp, buf + offset, 16);
        ip = temp;
        offset += 16;
    }

    // デシリアライズ: t
    for (auto& t : cert.t) {
        char temp[20] = {};
        std::memcpy(temp, buf + offset, 20);
        t = temp;
        offset += 20;
    }

    // デシリアライズ: expires
    for (auto& expires : cert.expires) {
        char temp[20] = {};
        std::memcpy(temp, buf + offset, 20);
        expires = temp;
        offset += 20;
    }
}

// Test code
int main() {
    Certificate_Format cert;

    // データを初期化
    for (int i = 0; i < 16; ++i) {
        cert.own_ip[i] = "IP" + std::to_string(i);
    }
    for (int i = 0; i < 20; ++i) {
        cert.t[i] = "T" + std::to_string(i);
        cert.expires[i] = "E" + std::to_string(i);
    }

    // シリアライズ用バッファ
    char buf[2048] = {};

    // シリアライズ
    serialize_to_buffer(cert, buf, sizeof(buf));

    // デシリアライズ用の新しい構造体
    Certificate_Format new_cert;

    // デシリアライズ
    deserialize_from_buffer(new_cert, buf, sizeof(buf));

    // データの検証
    for (int i = 0; i < 16; ++i) {
        std::cout << "IP[" << i << "]: " << new_cert.own_ip[i] << std::endl;
    }
    for (int i = 0; i < 20; ++i) {
        std::cout << "T[" << i << "]: " << new_cert.t[i] << std::endl;
        std::cout << "Expires[" << i << "]: " << new_cert.expires[i] << std::endl;
    }

    return 0;
}
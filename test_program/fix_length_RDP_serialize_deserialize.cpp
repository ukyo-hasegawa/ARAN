#include <stdint.h>
#include <string>
#include <vector>
#include <cstring>
#include <iostream>

enum class MessageType : uint8_t {
    RDP = 0x01,
    REP = 0x02
};

struct Certificate_Format {
    std::string own_ip[16];
    std::string t[20];
    std::string expires[20];
};

struct RDP_format {
    MessageType type; //1バイト
    char source_ip[16]; //16バイト
    char dest_ip[16];
    Certificate_Format cert;
    std::uint32_t nonce;
    char time_stamp[20];
    std::vector<unsigned char> signature[256];
};

void serialize(const RDP_format& rdp, unsigned char* buf) {
    size_t offset = 0;

    // Serialize type
    buf[offset] = static_cast<uint8_t>(rdp.type);
    offset += sizeof(uint8_t);

    // Serialize source_ip
    std::memcpy(buf + offset, rdp.source_ip, sizeof(rdp.source_ip));
    offset += sizeof(rdp.source_ip);

    // Serialize dest_ip
    std::memcpy(buf + offset, rdp.dest_ip, sizeof(rdp.dest_ip));
    offset += sizeof(rdp.dest_ip);

    // Serialize cert (own_ip, t, expires)
    for (const auto& ip : rdp.cert.own_ip) {
        size_t len = ip.size();
        std::memcpy(buf + offset, &len, sizeof(len)); // 文字列の長さを保存
        offset += sizeof(len);
        std::memcpy(buf + offset, ip.c_str(), len);  // 文字列の内容を保存
        offset += len;
    }
    for (const auto& t : rdp.cert.t) {
        size_t len = t.size();
        std::memcpy(buf + offset, &len, sizeof(len));
        offset += sizeof(len);
        std::memcpy(buf + offset, t.c_str(), len);
        offset += len;
    }
    for (const auto& expires : rdp.cert.expires) {
        size_t len = expires.size();
        std::memcpy(buf + offset, &len, sizeof(len));
        offset += sizeof(len);
        std::memcpy(buf + offset, expires.c_str(), len);
        offset += len;
    }

    // Serialize nonce
    std::memcpy(buf + offset, &rdp.nonce, sizeof(rdp.nonce));
    offset += sizeof(rdp.nonce);

    // Serialize time_stamp
    std::memcpy(buf + offset, rdp.time_stamp, sizeof(rdp.time_stamp));
    offset += sizeof(rdp.time_stamp);

    // Serialize signature
    for (size_t i = 0; i < 256; ++i) {
        std::memcpy(buf + offset, rdp.signature[i].data(), rdp.signature[i].size());
        offset += rdp.signature[i].size();
    }
}

void deserialize(const unsigned char* buf, RDP_format& rdp) {
    size_t offset = 0;

    // Deserialize type
    rdp.type = static_cast<MessageType>(buf[offset]);
    offset += sizeof(uint8_t);

    // Deserialize source_ip
    std::memcpy(rdp.source_ip, buf + offset, sizeof(rdp.source_ip));
    offset += sizeof(rdp.source_ip);

    // Deserialize dest_ip
    std::memcpy(rdp.dest_ip, buf + offset, sizeof(rdp.dest_ip));
    offset += sizeof(rdp.dest_ip);

    // Deserialize cert (own_ip, t, expires)
    for (auto& ip : rdp.cert.own_ip) {
        size_t len = 0;
        std::memcpy(&len, buf + offset, sizeof(len)); // 文字列の長さを取得
        offset += sizeof(len);
        char temp[256] = {};
        std::memcpy(temp, buf + offset, len);        // 文字列の内容を取得
        offset += len;
        ip = temp;
    }
    for (auto& t : rdp.cert.t) {
        size_t len = 0;
        std::memcpy(&len, buf + offset, sizeof(len));
        offset += sizeof(len);
        char temp[256] = {};
        std::memcpy(temp, buf + offset, len);
        offset += len;
        t = temp;
    }
    for (auto& expires : rdp.cert.expires) {
        size_t len = 0;
        std::memcpy(&len, buf + offset, sizeof(len));
        offset += sizeof(len);
        char temp[256] = {};
        std::memcpy(temp, buf + offset, len);
        offset += len;
        expires = temp;
    }

    // Deserialize nonce
    std::memcpy(&rdp.nonce, buf + offset, sizeof(rdp.nonce));
    offset += sizeof(rdp.nonce);

    // Deserialize time_stamp
    std::memcpy(rdp.time_stamp, buf + offset, sizeof(rdp.time_stamp));
    offset += sizeof(rdp.time_stamp);

    // Deserialize signature
    for (size_t i = 0; i < 256; ++i) {
        rdp.signature[i].resize(1); // Assuming 1 byte per signature element
        std::memcpy(rdp.signature[i].data(), buf + offset, rdp.signature[i].size());
        offset += rdp.signature[i].size();
    }
}

int main() {
    RDP_format original;
    original.type = MessageType::RDP;
    std::strcpy(original.source_ip, "192.168.1.1");
    std::strcpy(original.dest_ip, "192.168.1.2");
    original.cert.own_ip[0] ="192.168.1.1";
    original.cert.t[0]="2023-01-01";
    original.cert.expires[0]="2024-01-01";
    original.nonce = 12345;
    std::strcpy(original.time_stamp, "2023-10-01T12:00:00");
    for (size_t i = 0; i < 256; ++i) {
        original.signature[i] = {static_cast<unsigned char>(i)};
    }

    unsigned char buf[2048] = {0};
    serialize(original, buf);

    RDP_format deserialized;
    deserialize(buf, deserialized);

    // Test output
    std::cout << "Original source_ip: " << original.source_ip << "\n";
    std::cout << "Deserialized source_ip: " << deserialized.source_ip << "\n";
    std::cout << "Original nonce: " << original.nonce << "\n";
    std::cout << "Deserialized nonce: " << deserialized.nonce << "\n";
    std::cout << "Original time_stamp: " << original.time_stamp << "\n";
    std::cout << "Deserialized time_stamp: " << deserialized.time_stamp << "\n";
    std::cout << "Original signature[0]: " << static_cast<int>(original.signature[0][0]) << "\n";
    std::cout << "Deserialized signature[0]: " << static_cast<int>(deserialized.signature[0][0]) << "\n";
    return 0;
}
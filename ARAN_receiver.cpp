#include <netinet/in.h>
#include <string>
#include <cstring>
#include <vector>
#include <iostream>
#include <sstream>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
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

std::string get_own_ip(const std::string& keyword = "wlan0") {
    struct ifaddrs *ifaddr, *ifa;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        std::cerr << "Failed to get network interfaces" << std::endl;
        return "";
    }

    // インターフェースをリストし、名前に「wlan0」が含まれているインターフェースのIPを取得
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;

        // インターフェース名がキーワードに一致する場合
        if (std::string(ifa->ifa_name).find(keyword) != std::string::npos) {
            if (ifa->ifa_addr->sa_family == AF_INET) { // IPv4アドレスを取得
                struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
                inet_ntop(AF_INET, &addr->sin_addr, host, NI_MAXHOST);
                freeifaddrs(ifaddr);
                return std::string(host);  // IPアドレスを返す
            }
        }
    }

    freeifaddrs(ifaddr);
    std::cerr << "No IPv4 address found for an interface containing '" << keyword << "' in its name" << std::endl;
    return "";
}

void forward_message(const std::string& dest_ip, const std::string& message, const std::vector<unsigned char>& signature) {
    int sock;
    struct sockaddr_in dest_addr;
    char buf[2048];

    // ソケット作成
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return;
    }

    // 宛先のIPアドレスとポート設定
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(12345);
    if (inet_pton(AF_INET, dest_ip.c_str(), &dest_addr.sin_addr) <= 0) {
        std::cerr << "Invalid destination IP address" << std::endl;
        close(sock);
        return;
    }

    // 署名とメッセージを組み合わせて送信データを構築
    std::vector<unsigned char> data;
    data.insert(data.end(), message.begin(), message.end());
    data.insert(data.end(), signature.begin(), signature.end());

    // メッセージ送信
    ssize_t sent_bytes = sendto(sock, data.data(), data.size(), 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    if (sent_bytes < 0) {
        std::cerr << "Failed to send data" << std::endl;
    } else {
        std::cout << "Forwarded message to " << dest_ip << " with signature" << std::endl;
    }

    close(sock);
}

// 公開鍵を読み込む関数
EVP_PKEY* load_public_key(const std::string& filename) {
    FILE* file = fopen(filename.c_str(), "rb");
    if (!file) {
        std::cerr << "Failed to open public key file: " << filename << std::endl;
        return nullptr;
    }

    EVP_PKEY* pkey = PEM_read_PUBKEY(file, nullptr, nullptr, nullptr);
    fclose(file);

    if (!pkey) {
        std::cerr << "Failed to load public key" << std::endl;
        ERR_print_errors_fp(stderr);
    }

    return pkey;
}

int main() {
    // ブロードキャスト受信の設定
    int sock;
    struct sockaddr_in addr;
    char buf[2048];
    std::string ip_address = get_own_ip();
    std::string dest_ip = "";

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);
    addr.sin_addr.s_addr = INADDR_ANY;

    // バインド処理
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        std::cerr << "Failed to bind socket" << std::endl;
        return 1;
    }
    std::cout << "bind success" << std::endl;

    // 受信処理
    memset(buf, 0, sizeof(buf));
    ssize_t received_bytes = recv(sock, buf, sizeof(buf), 0);
    if (received_bytes < 0) {
        std::cerr << "Failed to receive data" << std::endl;
        return 1;
    }
    std::cout << "receive success" << std::endl;

    // 公開鍵の取得
    EVP_PKEY* public_key = load_public_key("public_key.pem");
    if (!public_key) {
        std::cerr << "Error: Could not load public key!" << std::endl;
        return 1;
    }
    std::cout << "Public key loaded successfully!" << std::endl;

    // 受信データを std::vector<uint8_t> に変換
    std::vector<uint8_t> recv_buf(buf, buf + received_bytes);


    data_format deserialized_rdp;
    std::size_t offset = 0;

    // ヘルパー関数: バッファから文字列をデシリアライズ
    auto deserialize_string = [&recv_buf, &offset]() {
        if (offset + 4 > recv_buf.size()) throw std::runtime_error("Buffer underflow while reading string length");

        std::uint32_t len = 0;
        len |= recv_buf[offset + 0] << 0;
        len |= recv_buf[offset + 1] << 8;
        len |= recv_buf[offset + 2] << 16;
        len |= recv_buf[offset + 3] << 24;
        offset += 4;

        if (offset + len > recv_buf.size()) throw std::runtime_error("Buffer underflow while reading string data");

        std::string result(recv_buf.begin() + offset, recv_buf.begin() + offset + len);
        offset += len;
        return result;
    };

    // ヘルパー関数: バッファから整数をデシリアライズ
    auto deserialize_int32 = [&recv_buf, &offset]() {
        if (offset + 4 > recv_buf.size()) throw std::runtime_error("Buffer underflow while reading int32");

        std::int32_t value = 0;
        value |= recv_buf[offset + 0] << 0;
        value |= recv_buf[offset + 1] << 8;
        value |= recv_buf[offset + 2] << 16;
        value |= recv_buf[offset + 3] << 24;
        offset += 4;
        return value;
    };

    // デシリアライズ処理
    deserialized_rdp.type = deserialize_string();
    deserialized_rdp.dest_ip = deserialize_string();
    deserialized_rdp.cert = deserialize_string();
    deserialized_rdp.n = deserialize_int32();
    deserialized_rdp.t = deserialize_string();

    // 署名をデシリアライズ
    std::string signature_str = deserialize_string();
    deserialized_rdp.signature = std::vector<unsigned char>(signature_str.begin(), signature_str.end());

    // 送信側と同じ `message` を構築
    std::ostringstream messageStream;
    messageStream << deserialized_rdp.type << "|"
                    << deserialized_rdp.dest_ip << "|"
                    << deserialized_rdp.cert << "|"
                    << deserialized_rdp.n << "|"
                    << deserialized_rdp.t;
    std::string message = messageStream.str();

    // 署名の検証
    bool isValid = verifySignature(public_key, message, deserialized_rdp.signature);
    std::cout << "署名の検証結果: " << (isValid ? "成功" : "失敗") << std::endl;

    //std::cout << "ip_address: " << ip_address << std::endl;

    // デバッグ出力
    std::cout << "Own IP Addresses:" << std::endl;
    for (const auto& ip : ip_address) {
        std::cout << ip << std::endl;
    }

    // 宛先 IP を取得
    dest_ip = deserialized_rdp.dest_ip;
    std::cout << "Destination IP (deserialized_rdp.dest_ip): " << dest_ip << std::endl;

    // 宛先が自分自身か確認
    if (isValid) {
        if (dest_ip == ip_address) {
            std::cout << "This message is for this device!" << std::endl;
        } else {
            std::cout << "This message is for another device." << std::endl;
        }
    } else {
        std::cout << "isValid is false" << std::endl;
    }
    //宛先でない場合、転送する。
    forward_message(dest_ip,message,deserialized_rdp.signature);


    return 0;
}
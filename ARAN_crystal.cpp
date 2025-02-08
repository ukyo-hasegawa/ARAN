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
#include <netdb.h>
#include <ifaddrs.h>
#include "dilithium.h"

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

int send_process(std::vector<uint8_t> buf) {
    int yes=1;
    // 送信処理
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 1;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);
    addr.sin_addr.s_addr = inet_addr("10.255.255.255");

    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));

    if (sendto(sock, buf.data(), buf.size(), 0, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("send failed");
        close(sock);
        return 0;
    } else {
        std::cout << "send success" << std::endl;
        close(sock);
        return 1;
    }
}

// シリアライズ処理
void serialize_data(const data_format& test_rdp, std::vector<uint8_t>& buf) {
    auto serialize_string = [&buf](const std::string& str) {
        std::uint32_t len = str.size();
        buf.push_back((len >> 0) & 0xFF);
        buf.push_back((len >> 8) & 0xFF);
        buf.push_back((len >> 16) & 0xFF);
        buf.push_back((len >> 24) & 0xFF);
        buf.insert(buf.end(), str.begin(), str.end());
    };

    serialize_string(test_rdp.type);
    serialize_string(test_rdp.dest_ip);
    serialize_string(test_rdp.cert);

    // nを4バイトにシリアライズ
    for (int i = 0; i < 4; i++) {
        buf.push_back((test_rdp.n >> (8 * i)) & 0xFF);
    }

    serialize_string(test_rdp.t);
    serialize_string(std::string(test_rdp.signature.begin(), test_rdp.signature.end()));
}

// 現在時刻の取得
std::string get_time(){
    auto now = std::chrono::system_clock::now();
    std::time_t currentTime = std::chrono::system_clock::to_time_t(now);
    std::tm* localTime = std::localtime(&currentTime);
    std::ostringstream timeStream;
    timeStream << std::put_time(localTime, "%Y-%m-%d %H:%M:%S");
    std::string formattedTime = timeStream.str();
    return formattedTime;
}

std::string calculateExpirationTime(int durationHours, const std::string& formattedTime) {
    // formattedTimeをstd::tmに変換
    std::tm tm = {};
    std::istringstream ss(formattedTime);
    ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");

    // 時間を出力 std::cout << "現在時刻: " << formattedTime << std::endl;
    
    if (ss.fail()) {
        std::cerr << "時間のフォーマットが無効です。" << std::endl;
        return "";
    }

    // std::tmをstd::chrono::system_clock::time_pointに変換
    auto timePoint = std::chrono::system_clock::from_time_t(std::mktime(&tm));

    // 24時間（1日）を加算
    auto expirationTime = timePoint + std::chrono::hours(24);

    // time_pointをstd::time_tに変換
    std::time_t expiration = std::chrono::system_clock::to_time_t(expirationTime);

    // 時間をフォーマット
    std::tm* localExpiration = std::localtime(&expiration);
    std::ostringstream timeStream;
    timeStream << std::put_time(localExpiration, "%Y-%m-%d %H:%M:%S");

    // 時間を出力 std::cout << "24時間後: " << timeStream.str() << std::endl;

    return timeStream.str();
}

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

std::vector<unsigned char> signMessage(const std::string& message, const std::vector<unsigned char>& private_key) {
    std::vector<unsigned char> signature(CRYPTO_BYTES);
    if (crypto_sign(signature.data(), nullptr, reinterpret_cast<const unsigned char*>(message.data()), message.size(), private_key.data()) != 0) {
        std::cerr << "Failed to sign message" << std::endl;
        return {};
    }
    return signature;
}

bool verifySignature(const std::string& message, const std::vector<unsigned char>& signature, const std::vector<unsigned char>& public_key) {
    if (crypto_sign_verify(signature.data(), reinterpret_cast<const unsigned char*>(message.data()), message.size(), public_key.data()) != 0) {
        std::cerr << "Failed to verify signature" << std::endl;
        return false;
    }
    return true;
}

int main() {
    std::vector<unsigned char> public_key(CRYPTO_PUBLICKEYBYTES);
    std::vector<unsigned char> private_key(CRYPTO_SECRETKEYBYTES);
    if (crypto_sign_keypair(public_key.data(), private_key.data()) != 0) {
        std::cerr << "Failed to generate key pair" << std::endl;
        return 1;
    }

    // 現在時刻の取得
    std::string formattedTime = get_time();
    std::string expirationTime = calculateExpirationTime(24, formattedTime);

    // 公開鍵を取得して証明書に含める
    std::string publicKeyPEM(reinterpret_cast<char*>(public_key.data()), public_key.size());
    std::string cert_info = get_own_ip() + publicKeyPEM + "," + formattedTime + "," + expirationTime;

    data_format test_rdp1 = {
        "RDP",
        "10.0.0.1",
        "10.0.0.3",
        cert_info,
        std::random_device()(),
        formattedTime,
        expirationTime,
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
    test_rdp1.signature = signMessage(message, private_key);
    if (test_rdp1.signature.empty()) return -1;

    // シリアライズ処理
    std::vector<uint8_t> buf;
    serialize_data(test_rdp1, buf);

    if (send_process(buf)) {
        std::cout << "Message sent successfully" << std::endl;
    }

    return 0;
}
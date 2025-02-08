#include <netinet/in.h>
#include <string>
#include <cstring>
#include <chrono>
#include <vector>
#include <iostream>
#include <iomanip>
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

// 文字列のデシリアライズ
std::string deserialize_string(const std::vector<uint8_t>& buf, std::size_t& offset) {
    if (offset + 4 > buf.size()) throw std::runtime_error("Buffer underflow while reading string length");

    std::uint32_t len = 0;
    len |= buf[offset + 0] << 0;
    len |= buf[offset + 1] << 8;
    len |= buf[offset + 2] << 16;
    len |= buf[offset + 3] << 24;
    offset += 4;

    if (offset + len > buf.size()) throw std::runtime_error("Buffer underflow while reading string data");

    std::string result(buf.begin() + offset, buf.begin() + offset + len);
    offset += len;
    return result;
}

// 整数のデシリアライズ
std::int32_t deserialize_int32(const std::vector<uint8_t>& buf, std::size_t& offset) {
    if (offset + 4 > buf.size()) throw std::runtime_error("Buffer underflow while reading int32");

    std::int32_t value = 0;
    value |= buf[offset + 0] << 0;
    value |= buf[offset + 1] << 8;
    value |= buf[offset + 2] << 16;
    value |= buf[offset + 3] << 24;
    offset += 4;
    return value;
}

// デシリアライズ処理
data_format deserialize_data(const std::vector<uint8_t>& buf) {
    data_format deserialized_rdp;
    std::size_t offset = 0;

    // データをデシリアライズ
    deserialized_rdp.type = deserialize_string(buf, offset);
    deserialized_rdp.dest_ip = deserialize_string(buf, offset);
    deserialized_rdp.cert = deserialize_string(buf, offset);
    deserialized_rdp.n = deserialize_int32(buf, offset);
    deserialized_rdp.t = deserialize_string(buf, offset);

    // 署名をデシリアライズ
    std::string signature_str = deserialize_string(buf, offset);
    deserialized_rdp.signature = std::vector<unsigned char>(signature_str.begin(), signature_str.end());

    return deserialized_rdp;
}

std::string construct_message(const data_format& deserialized_rdp) {
    std::ostringstream messageStream;
    messageStream << deserialized_rdp.type << "|"
                  << deserialized_rdp.dest_ip << "|"
                  << deserialized_rdp.cert << "|"
                  << deserialized_rdp.n << "|"
                  << deserialized_rdp.t;
    return messageStream.str();
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

data_format Makes_RDP(std::string type, std::string own_ip, std::string dest_ip, std::string cert, std::uint32_t n, std::string t, std::string expires, std::vector<unsigned char> signature) {
    data_format rdp;
    rdp.type = type;
    rdp.own_ip = own_ip;
    rdp.dest_ip = dest_ip;
    rdp.cert = cert;
    rdp.n = n;
    rdp.t = t;
    rdp.expires = expires;
    rdp.signature = signature;
    return rdp;
}

int main() {
    data_format rdp;
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
    struct sockaddr_in sender_addr;
    socklen_t addr_len = sizeof(sender_addr);
    memset(buf, 0, sizeof(buf));
    ssize_t received_bytes = recvfrom(sock, buf, sizeof(buf), 0, reinterpret_cast<struct sockaddr*>(&sender_addr), &addr_len);
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

    //デシリアライズ処理
    data_format deserialized_rdp = deserialize_data(recv_buf);

    std::string publicKeyPEM = getPublicKey(public_key);
    std::string cert_info = get_own_ip() +publicKeyPEM + "," + get_time() + "," + calculateExpirationTime(24,get_time());

    // 送信側と同じ `message` を構築
    std::string message = construct_message(deserialized_rdp);

    // 署名の検証
    bool isValid = verifySignature(public_key, message, deserialized_rdp.signature);
    std::cout << "署名の検証結果: " << (isValid ? "成功" : "失敗") << std::endl;

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

    // 署名の生成
    std::vector<unsigned char> signature = signMessage(load_private_key("private_key.pem"), message);
    if (signature.empty()) return -1;

    rdp = Makes_RDP(deserialized_rdp.type, get_own_ip(), deserialized_rdp.dest_ip, cert_info, deserialized_rdp.n, deserialized_rdp.t, deserialized_rdp.expires, signature);

    serialize_data(rdp,recv_buf);

    //宛先でない場合、転送する。
    send_process(recv_buf);

    return 0;
}
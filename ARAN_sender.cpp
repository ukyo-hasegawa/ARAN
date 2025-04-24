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
#include <netdb.h>
#include <ifaddrs.h>
#include "RSA/RSA.h"

struct Certificate_Format {
    std::string own_ip;
    std::string own_public_key;
    std::string t;
    std::string expires;
};

struct RDP_format {
    std::string type;
    std::string source_ip;
    std::string dest_ip;
    Certificate_Format cert;
    std::uint32_t n;
    std::string t;
    std::vector<unsigned char> signature;
};
//何この構造体？
struct Forwarding_RDP_format {
    RDP_format rdp;
    std::vector<unsigned char> receiver_signature;
    Certificate_Format receiver_cert;
};

Forwarding_RDP_format Makes_RDP(RDP_format RDP, std::vector<unsigned char> receiver_signature, Certificate_Format receiver_cert) {
    Forwarding_RDP_format rdp;
    rdp.rdp.type = RDP.type;
    rdp.rdp.source_ip = RDP.source_ip;
    rdp.rdp.dest_ip = RDP.dest_ip;
    rdp.rdp.cert = RDP.cert;
    rdp.rdp.n = RDP.n;
    rdp.rdp.t = RDP.t;
    rdp.rdp.signature = RDP.signature;
    rdp.receiver_cert = receiver_cert;
    rdp.receiver_signature = receiver_signature;
    return rdp;
}

Certificate_Format Makes_Certificate(std::string own_ip, std::string own_public_key, std::string t, std::string expires) {
    Certificate_Format Certificate;
    Certificate.own_ip = own_ip;
    Certificate.own_public_key = own_public_key;
    Certificate.t = t;
    Certificate.expires = expires;
    return Certificate;
}

int send_process(std::vector<uint8_t> buf) {
    int yes=1;
    // 送信処理
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) 
    {
        perror("socket failed");
        return 1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);
    addr.sin_addr.s_addr = inet_addr("10.255.255.255");

    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));

    std::cout << "Sending data of size: " << buf.size() << " bytes" << std::endl;

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

std::vector<uint8_t> receving_process(int sock) {
    std::cout << "receive process start" << std::endl;
    // ブロードキャスト受信の設定
    //int sock;
    struct sockaddr_in addr;
    char buf[2048];
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);
    addr.sin_addr.s_addr = INADDR_ANY;

    //受信処理
    struct sockaddr_in sender_addr;
    socklen_t addr_len = sizeof(sender_addr);
    memset(buf, 0, sizeof(buf));
    ssize_t received_bytes = recvfrom(sock, buf, sizeof(buf), 0, reinterpret_cast<struct sockaddr*>(&sender_addr), &addr_len);
    
    if (received_bytes < 0) {
        std::cerr << "Failed to receive data" << std::endl;
        return {};
    }

    // 受信データを std::vector<uint8_t> に変換
    std::vector<uint8_t> recv_buf(buf, buf + received_bytes);

    std::cout << "-----------------------------------receive data--------------------------------------" << std::endl;

    std::cout << "Received data size: " << recv_buf.size() << " bytes" << std::endl;

    return recv_buf;
}

std::string certificate_to_string(const Certificate_Format& cert) {
    std::ostringstream certStream;
    certStream << cert.own_ip << "|\n"
               << cert.own_public_key << "|\n"
               << cert.t << "|\n"
               << cert.expires << "|\n";
    return certStream.str();
}

// シリアライズ処理
void serialize_data(const RDP_format& test_rdp, std::vector<uint8_t>& buf) {
    auto serialize_string = [&buf](const std::string& str) {
        std::uint32_t len = str.size();
        buf.push_back((len >> 0) & 0xFF);
        buf.push_back((len >> 8) & 0xFF);
        buf.push_back((len >> 16) & 0xFF);
        buf.push_back((len >> 24) & 0xFF);
        buf.insert(buf.end(), str.begin(), str.end());
    };

    serialize_string(test_rdp.type);
    serialize_string(test_rdp.source_ip);
    serialize_string(test_rdp.dest_ip);

    // Certificate_Format のシリアライズ
    serialize_string(test_rdp.cert.own_ip);
    serialize_string(test_rdp.cert.own_public_key);
    serialize_string(test_rdp.cert.t);
    serialize_string(test_rdp.cert.expires);

    // nを4バイトにシリアライズ
    for (int i = 0; i < 4; i++) {
        buf.push_back((test_rdp.n >> (8 * i)) & 0xFF);
    }

    serialize_string(test_rdp.t);

    // 署名のシリアライズ
    std::uint32_t sig_len = test_rdp.signature.size();
    buf.push_back((sig_len >> 0) & 0xFF);
    buf.push_back((sig_len >> 8) & 0xFF);
    buf.push_back((sig_len >> 16) & 0xFF);
    buf.push_back((sig_len >> 24) & 0xFF);
    buf.insert(buf.end(), test_rdp.signature.begin(), test_rdp.signature.end());

    std::cout << "Serialized data size: " << buf.size() << " bytes" << std::endl;
    /*
    std::cout << "Serialized data (hex): ";
    for (unsigned char c : buf) {
        std::cout << std::hex << (int)c << " ";
    }
    std::cout << std::dec << std::endl;
    */
}

// Forwarding_RDP_format のシリアライズ処理
void serialize_forwarding_data(const Forwarding_RDP_format& forwarding_rdp, std::vector<uint8_t>& buf) {
    auto serialize_string = [&buf](const std::string& str) {
        std::uint32_t len = str.size();
        buf.push_back((len >> 0) & 0xFF);
        buf.push_back((len >> 8) & 0xFF);
        buf.push_back((len >> 16) & 0xFF);
        buf.push_back((len >> 24) & 0xFF);
        buf.insert(buf.end(), str.begin(), str.end());
    };

    serialize_string(forwarding_rdp.rdp.type);
    serialize_string(forwarding_rdp.rdp.source_ip);
    serialize_string(forwarding_rdp.rdp.dest_ip);

    // Certificate_Format のシリアライズ
    serialize_string(forwarding_rdp.rdp.cert.own_ip);
    serialize_string(forwarding_rdp.rdp.cert.own_public_key);
    serialize_string(forwarding_rdp.cert.t);
    serialize_string(forwarding_rdp.cert.expires);

    // nを4バイトにシリアライズ
    for (int i = 0; i < 4; i++) {
        buf.push_back((forwarding_rdp.n >> (8 * i)) & 0xFF);
    }

    serialize_string(forwarding_rdp.t);

    // 署名のシリアライズ
    std::uint32_t sig_len = forwarding_rdp.signature.size();
    buf.push_back((sig_len >> 0) & 0xFF);
    buf.push_back((sig_len >> 8) & 0xFF);
    buf.push_back((sig_len >> 16) & 0xFF);
    buf.push_back((sig_len >> 24) & 0xFF);
    buf.insert(buf.end(), forwarding_rdp.signature.begin(), forwarding_rdp.signature.end());

    // receiver_signature のシリアライズ
    std::uint32_t receiver_sig_len = forwarding_rdp.receiver_signature.size();
    buf.push_back((receiver_sig_len >> 0) & 0xFF);
    buf.push_back((receiver_sig_len >> 8) & 0xFF);
    buf.push_back((receiver_sig_len >> 16) & 0xFF);
    buf.push_back((receiver_sig_len >> 24) & 0xFF);
    buf.insert(buf.end(), forwarding_rdp.receiver_signature.begin(), forwarding_rdp.receiver_signature.end());

    // receiver_cert のシリアライズ
    serialize_string(forwarding_rdp.receiver_cert.own_ip);
    serialize_string(forwarding_rdp.receiver_cert.own_public_key);
    serialize_string(forwarding_rdp.receiver_cert.t);
    serialize_string(forwarding_rdp.receiver_cert.expires);

    std::cout << "Serialized forwarding data size: " << buf.size() << " bytes" << std::endl;
    /*
    std::cout << "Serialized forwarding data (hex): ";
    for (unsigned char c : buf) {
        std::cout << std::hex << (int)c << " ";
    }
    std::cout << std::dec << std::endl;
    */
}

// デシリアライズ処理
RDP_format deserialize_data(const std::vector<uint8_t>& buf) {
    RDP_format deserialized_rdp;
    std::size_t offset = 0;

    // 汎用のデシリアライズ関数
    auto deserialize_vector = [&buf, &offset]() {
        if (offset + 4 > buf.size()) throw std::runtime_error("Buffer underflow while reading vector length");
        std::uint32_t len = 0;
        len |= buf[offset + 0] << 0;
        len |= buf[offset + 1] << 8;
        len |= buf[offset + 2] << 16;
        len |= buf[offset + 3] << 24;
        offset += 4;
        if (offset + len > buf.size()) throw std::runtime_error("Buffer underflow while reading vector data");
        std::vector<unsigned char> result(buf.begin() + offset, buf.begin() + offset + len);
        offset += len;
        return result;
    };

    // std::string を vector から変換するラッパー
    auto deserialize_string = [&deserialize_vector]() {
        std::vector<unsigned char> vec = deserialize_vector();
        return std::string(vec.begin(), vec.end());
    };

    // データをデシリアライズ
    deserialized_rdp.type = deserialize_string();
    deserialized_rdp.dest_ip = deserialize_string();

    // Certificate_Format のデシリアライズ
    deserialized_rdp.cert.own_ip = deserialize_string();
    deserialized_rdp.cert.own_public_key = deserialize_string();
    deserialized_rdp.cert.t = deserialize_string();
    deserialized_rdp.cert.expires = deserialize_string();

    // n のデシリアライズ
    if (offset + 4 > buf.size()) throw std::runtime_error("Buffer underflow while reading int32");
    deserialized_rdp.n = 0;
    deserialized_rdp.n |= buf[offset + 0] << 0;
    deserialized_rdp.n |= buf[offset + 1] << 8;
    deserialized_rdp.n |= buf[offset + 2] << 16;
    deserialized_rdp.n |= buf[offset + 3] << 24;
    offset += 4;

    deserialized_rdp.t = deserialize_string();
    deserialized_rdp.signature = deserialize_vector();

    return deserialized_rdp;
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

// 公開鍵をPEM形式の文字列に変換する関数
std::string get_PublicKey_As_String(EVP_PKEY* pkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);

    size_t pubKeyLen = BIO_pending(bio);
    std::vector<char> pubKey(pubKeyLen + 1);
    BIO_read(bio, pubKey.data(), pubKeyLen);
    pubKey[pubKeyLen] = '\0';

    BIO_free_all(bio);
    return std::string(pubKey.data());
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

// メッセージを構築する関数
std::string construct_message(const Forwarding_RDP_format& deserialized_rdp) {
    std::ostringstream messageStream;
    messageStream << deserialized_rdp.type << "|\n"
                  << deserialized_rdp.dest_ip << "|\n" 
                  << certificate_to_string(deserialized_rdp.cert) << "|\n"
                  << deserialized_rdp.n << "|\n"
                  << deserialized_rdp.t << "|\n";
    return messageStream.str();
}

// メッセージを構築する関数
std::string construct_message_with_key(const RDP_format& deserialized_rdp, const std::string& public_key_str) {
    std::ostringstream messageStream;
    messageStream << deserialized_rdp.type << "|\n"
                  << deserialized_rdp.dest_ip << "|\n" 
                  << certificate_to_string(deserialized_rdp.cert) << "|\n"<< deserialized_rdp.n << "|\n"
                  << deserialized_rdp.t << "|\n"
                  << public_key_str  // 公開鍵を追加
                  << "Message-with-public-key-end\n"; 

    std::cout << messageStream.str() << std::endl;
    
    return messageStream.str();
}

std::vector<unsigned char> signMessage(EVP_PKEY* private_key, const std::string& message) {
    std::vector<unsigned char> signature;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to create EVP_MD_CTX" << std::endl;
        return signature;
    }

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, private_key) <= 0) {
        std::cerr << "EVP_DigestSignInit failed" << std::endl;
        EVP_MD_CTX_free(ctx);
        return signature;
    }

    if (EVP_DigestSignUpdate(ctx, message.c_str(), message.size()) <= 0) {
        std::cerr << "EVP_DigestSignUpdate failed" << std::endl;
        EVP_MD_CTX_free(ctx);
        return signature;
    }

    size_t siglen = 0;
    if (EVP_DigestSignFinal(ctx, nullptr, &siglen) <= 0) {
        std::cerr << "EVP_DigestSignFinal (get length) failed" << std::endl;
        EVP_MD_CTX_free(ctx);
        return signature;
    }

    signature.resize(siglen);
    if (EVP_DigestSignFinal(ctx, signature.data(), &siglen) <= 0) {
        std::cerr << "EVP_DigestSignFinal (sign) failed" << std::endl;
        EVP_MD_CTX_free(ctx);
        return signature;
    }

    EVP_MD_CTX_free(ctx);
    return signature;
}


bool verifySignature(EVP_PKEY* public_key, const std::string& message, const std::vector<unsigned char>& signature) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to create EVP_MD_CTX" << std::endl;
        return false;
    }

    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, public_key) <= 0) {
        std::cerr << "EVP_DigestVerifyInit failed" << std::endl;
        EVP_MD_CTX_free(ctx);
        return false;
    }

    if (EVP_DigestVerifyUpdate(ctx, message.c_str(), message.size()) <= 0) {
        std::cerr << "EVP_DigestVerifyUpdate failed" << std::endl;
        EVP_MD_CTX_free(ctx);
        return false;
    }

    int result = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
    EVP_MD_CTX_free(ctx);

    if (result == 1) {
        return true; // 署名が正しい
    } else if (result == 0) {
        return false; // 署名が正しくない
    } else {
        std::cerr << "EVP_DigestVerifyFinal failed" << std::endl;
        return false;
    }
}

int main() {
    Forwarding_RDP_format test_rdp1;
    Certificate_Format test_cert1;
    char recive_buf[2048];
    int sock;

    // 公開鍵の取得
    EVP_PKEY* public_key = load_public_key("public_key.pem");
    if (!public_key) return 1;

    // 秘密鍵の取得
    EVP_PKEY* private_key = load_private_key("private_key.pem");
    if (!private_key) return 1;

    // 現在時刻の取得
    std::string Formatted_Time = get_time();
    
    // 有効期限の取得
    std::string expirationTime = calculateExpirationTime(24, Formatted_Time);
    
    // 送信元の公開鍵を取得して証明書を作成
    test_cert1 = Makes_Certificate(
        get_own_ip(), 
        get_PublicKey_As_String(public_key), 
        Formatted_Time, 
        expirationTime
    );

    test_rdp1 = Makes_RDP(
        "RDP",
        "10.0.0.1",
        "10.0.0.4",
        test_cert1,
        std::random_device()(),
        Formatted_Time,
        expirationTime,
        {},
        {},
        {}
    );
    
    // 署名対象メッセージを作成
    std::string message = construct_message(test_rdp1);
    std::cout << "-------------------------------------Message-------------------------------------: " << std::endl;
    std::cout << message << std::endl;
    std::cout << "-------------------------------------Message-End-------------------------------------: " << std::endl;

    test_rdp1.signature = signMessage(private_key, message);
    if (test_rdp1.signature.empty()) return -1;

    std::cout << "-------------------------------------Signature-------------------------------------: " << std::endl;
    for (unsigned char c : test_rdp1.signature) {
        std::cout << std::hex << (int)c << " ";
    }
    std::cout << std::dec << std::endl;

    // シリアライズ処理
    std::vector<uint8_t> buf;
    serialize_forwarding_data(test_rdp1, buf);

    if(send_process(buf)) {
        std::cout << "Message sent successfully" << std::endl;
    }

    while (true)
    {
        //受信処理
        struct sockaddr_in sender_addr;
        socklen_t addr_len = sizeof(sender_addr);
        memset(recive_buf, 0, sizeof(recive_buf));
        
        std::vector<uint8_t> recv_buf = receving_process(sock);
    }

    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);
    return 0;
}
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
#include <cstring>
#include "RSA/RSA.h"

enum class MessageType : uint8_t {
    RDP = 0x01,
    REP = 0x02
};

struct Certificate_Format {
    std::string own_ip[16];
    std::string own_public_key;
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

struct Forwarding_RDP_format {
    RDP_format rdp;
    std::vector<unsigned char> receiver_signature;
    Certificate_Format receiver_cert;
};

Forwarding_RDP_format Makes_RDP(RDP_format RDP, std::vector<unsigned char> receiver_signature, Certificate_Format receiver_cert) {
    Forwarding_RDP_format rdp;
    rdp.rdp = RDP;
    rdp.receiver_cert = receiver_cert;
    rdp.receiver_signature = receiver_signature;
    return rdp;
}

struct Forwarding_REP_format {
    MessageType type;
    std::string dest_ip;
    Certificate_Format cert;
    std::uint32_t n;
    std::string t;
    std::vector<unsigned char> signature;
    std::vector<unsigned char> receiver_signature;
    Certificate_Format receiver_cert;
};

Certificate_Format Makes_Certificate(std::string own_ip, std::string own_public_key, std::string t, std::string expires) {
    Certificate_Format Certificate;
    Certificate.own_ip = own_ip;
    Certificate.own_public_key = own_public_key;
    Certificate.t = t;
    Certificate.expires = expires;
    return Certificate;
}

void RDP_serialize(const RDP_format& rdp, unsigned char* buf) {
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

void RDP_deserialize(const unsigned char* buf, RDP_format& rdp) {
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

MessageType get_packet_type(const std::vector<uint8_t>& buf) {
    if (buf.size() < 1) {
        throw std::runtime_error("Buffer too small to determine packet type");
    }

    // バッファの先頭1バイトを MessageType に変換
    return static_cast<MessageType>(buf[0]);
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

std::tuple<std::vector<uint8_t>, std::string> receving_process(int sock) {
    //std::cout << "receive process start" << std::endl;

    struct sockaddr_in sender_addr;
    socklen_t addr_len = sizeof(sender_addr);
    char buf[2048];
    memset(buf, 0, sizeof(buf));

    ssize_t received_bytes = recvfrom(sock, buf, sizeof(buf), 0, reinterpret_cast<struct sockaddr*>(&sender_addr), &addr_len);
    
    if (received_bytes < 0) {
        //std::cerr << "Failed to receive data" << std::endl;
        return std::make_tuple(std::vector<unsigned char>(), std::string());
    }

    // 送信元IPアドレスを取得
    std::string sender_ip = inet_ntoa(sender_addr.sin_addr);
    
    // 受信データを std::vector<uint8_t> に変換
    std::vector<uint8_t> recv_buf(buf, buf + received_bytes);

    std::cout << "-----------------------------------receive data--------------------------------------" << std::endl;


    std::cout << "Received data size: " << recv_buf.size() << " bytes" << std::endl;
    std::cout << std::dec << std::endl; // 10進数に戻す


    return {recv_buf, sender_ip};
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

    buf.push_back(static_cast<uint8_t>(test_rdp.type)); //RDP/REPのシリアライズ
    
    serialize_string(test_rdp.source_ip);
    serialize_string(test_rdp.dest_ip);

    // Certificate_Format のシリアライズ
    serialize_string(test_rdp.cert.own_ip);
    serialize_string(test_rdp.cert.own_public_key);
    serialize_string(test_rdp.cert.t);
    serialize_string(test_rdp.cert.expires);

    // nを4バイトにシリアライズ
    for (int i = 0; i < 4; i++) {
        buf.push_back((test_rdp.nonce >> (8 * i)) & 0xFF);
    }

    serialize_string(test_rdp.time_stamp);

    // 署名のシリアライズ
    std::uint32_t sig_len = test_rdp.signature.size();
    buf.push_back((sig_len >> 0) & 0xFF);
    buf.push_back((sig_len >> 8) & 0xFF);
    buf.push_back((sig_len >> 16) & 0xFF);
    buf.push_back((sig_len >> 24) & 0xFF);
    buf.insert(buf.end(), test_rdp.signature.begin(), test_rdp.signature.end());

    std::cout << "Serialized data size: " << buf.size() << " bytes" << std::endl;
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

    buf.push_back(static_cast<uint8_t>(forwarding_rdp.rdp.type)); //RDP/REPのシリアライズ
    serialize_string(forwarding_rdp.rdp.source_ip);
    serialize_string(forwarding_rdp.rdp.dest_ip);

    // Certificate_Format のシリアライズ
    serialize_string(forwarding_rdp.rdp.cert.own_ip);
    serialize_string(forwarding_rdp.rdp.cert.own_public_key);
    serialize_string(forwarding_rdp.rdp.cert.t);
    serialize_string(forwarding_rdp.rdp.cert.expires);

    // nを4バイトにシリアライズ
    for (int i = 0; i < 4; i++) {
        buf.push_back((forwarding_rdp.rdp.nonce >> (8 * i)) & 0xFF);
    }

    serialize_string(forwarding_rdp.rdp.time_stamp);

    // 署名のシリアライズ
    std::uint32_t sig_len = forwarding_rdp.rdp.signature.size();
    buf.push_back((sig_len >> 0) & 0xFF);
    buf.push_back((sig_len >> 8) & 0xFF);
    buf.push_back((sig_len >> 16) & 0xFF);
    buf.push_back((sig_len >> 24) & 0xFF);
    buf.insert(buf.end(), forwarding_rdp.rdp.signature.begin(), forwarding_rdp.rdp.signature.end());

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
    // type のデシリアライズ
    if (offset >= buf.size()) throw std::runtime_error("Buffer underflow while reading type");
    deserialized_rdp.type = static_cast<MessageType>(buf[offset]);
    offset += 1;
    deserialized_rdp.dest_ip = deserialize_string();

    // Certificate_Format のデシリアライズ
    deserialized_rdp.cert.own_ip = deserialize_string();
    deserialized_rdp.cert.own_public_key = deserialize_string();
    deserialized_rdp.cert.t = deserialize_string();
    deserialized_rdp.cert.expires = deserialize_string();

    // n のデシリアライズ
    if (offset + 4 > buf.size()) throw std::runtime_error("Buffer underflow while reading int32");
    deserialized_rdp.nonce = 0;
    deserialized_rdp.nonce |= buf[offset + 0] << 0;
    deserialized_rdp.nonce |= buf[offset + 1] << 8;
    deserialized_rdp.nonce |= buf[offset + 2] << 16;
    deserialized_rdp.nonce |= buf[offset + 3] << 24;
    offset += 4;

    deserialized_rdp.time_stamp = deserialize_string();
    deserialized_rdp.signature = deserialize_vector();

    return deserialized_rdp;
}

//REP専用のデシリアライズ関数
Forwarding_REP_format deserialize_forwarding_rep(const std::vector<uint8_t>& buf) {
    Forwarding_REP_format rep;
    std::size_t offset = 0;

    auto deserialize_string = [&buf, &offset]() {
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
    };

    // type のデシリアライズ
    if (offset >= buf.size()) throw std::runtime_error("Buffer underflow while reading type");
    rep.type = static_cast<MessageType>(buf[offset]);
    offset += 1;

    // dest_ip のデシリアライズ
    rep.dest_ip = deserialize_string();

    // Certificate_Format のデシリアライズ
    rep.cert.own_ip = deserialize_string();
    rep.cert.own_public_key = deserialize_string();
    rep.cert.t = deserialize_string();
    rep.cert.expires = deserialize_string();

    // n のデシリアライズ
    if (offset + 4 > buf.size()) throw std::runtime_error("Buffer underflow while reading int32");
    rep.n = 0;
    rep.n |= buf[offset + 0] << 0;
    rep.n |= buf[offset + 1] << 8;
    rep.n |= buf[offset + 2] << 16;
    rep.n |= buf[offset + 3] << 24;
    offset += 4;

    // t のデシリアライズ
    rep.t = deserialize_string();

    // signature のデシリアライズ
    if (offset + 4 > buf.size()) throw std::runtime_error("Buffer underflow while reading signature length");
    std::uint32_t sig_len = 0;
    sig_len |= buf[offset + 0] << 0;
    sig_len |= buf[offset + 1] << 8;
    sig_len |= buf[offset + 2] << 16;
    sig_len |= buf[offset + 3] << 24;
    offset += 4;
    if (offset + sig_len > buf.size()) throw std::runtime_error("Buffer underflow while reading signature data");
    rep.signature = std::vector<unsigned char>(buf.begin() + offset, buf.begin() + offset + sig_len);
    offset += sig_len;

    // receiver_signature のデシリアライズ
    if (offset + 4 > buf.size()) throw std::runtime_error("Buffer underflow while reading receiver signature length");
    std::uint32_t receiver_sig_len = 0;
    receiver_sig_len |= buf[offset + 0] << 0;
    receiver_sig_len |= buf[offset + 1] << 8;
    receiver_sig_len |= buf[offset + 2] << 16;
    receiver_sig_len |= buf[offset + 3] << 24;
    offset += 4;
    if (offset + receiver_sig_len > buf.size()) throw std::runtime_error("Buffer underflow while reading receiver signature data");
    rep.receiver_signature = std::vector<unsigned char>(buf.begin() + offset, buf.begin() + offset + receiver_sig_len);
    offset += receiver_sig_len;

    // receiver_cert のデシリアライズ
    rep.receiver_cert.own_ip = deserialize_string();
    rep.receiver_cert.own_public_key = deserialize_string();
    rep.receiver_cert.t = deserialize_string();
    rep.receiver_cert.expires = deserialize_string();

    return rep;
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
char Get_time(){
    auto now = std::chrono::system_clock::now();
    std::time_t currentTime = std::chrono::system_clock::to_time_t(now);
    std::tm* localTime = std::localtime(&currentTime);
    std::ostringstream timeStream;
    timeStream << std::put_time(localTime, "%Y-%m-%d %H:%M:%S");
    char formattedTime = timeStream.str();
    return formattedTime;
}
void set_time_stamp(RDP_format& rdp) {
    // 現在時刻を取得
    auto now = std::chrono::system_clock::now();
    std::time_t currentTime = std::chrono::system_clock::to_time_t(now);
    std::tm* localTime = std::localtime(&currentTime);

    // 時刻をフォーマット
    char formattedTime[20];
    std::strftime(formattedTime, sizeof(formattedTime), "%Y-%m-%d %H:%M:%S", localTime);

    // time_stamp にコピー
    std::strncpy(rdp.time_stamp, formattedTime, sizeof(rdp.time_stamp) - 1);
    rdp.time_stamp[sizeof(rdp.time_stamp) - 1] = '\0'; // ヌル終端を保証
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
    messageStream << static_cast<int>(deserialized_rdp.rdp.type) << "|\n"
                  << deserialized_rdp.rdp.dest_ip << "|\n" 
                  << certificate_to_string(deserialized_rdp.rdp.cert) << "|\n"
                  << deserialized_rdp.rdp.nonce << "|\n"
                  << deserialized_rdp.rdp.time_stamp << "|\n";
    return messageStream.str();
}

// メッセージを構築する関数
std::string construct_message_with_key(const RDP_format& deserialized_rdp, const std::string& public_key_str) {
    std::ostringstream messageStream;
    messageStream <<static_cast<int>(deserialized_rdp.type)<< "|\n"
                  << deserialized_rdp.dest_ip << "|\n" 
                  << certificate_to_string(deserialized_rdp.cert) << "|\n"<< deserialized_rdp.nonce << "|\n"
                  << deserialized_rdp.time_stamp << "|\n"
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
    RDP_format rdp1;
    Certificate_Format test_cert1;
    char recive_buf[2048];
    int sock;

    // ソケット作成
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return 1;
    }

    // バインド処理
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345); // ポート番号
    addr.sin_addr.s_addr = INADDR_ANY; // すべてのインターフェースで受信

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        std::cerr << "Failed to bind socket" << std::endl;
        close(sock);
        return 1;
    }

    std::cout << "bind success" << std::endl;

    // 公開鍵の取得
    EVP_PKEY* public_key = load_public_key("public_key.pem");
    if (!public_key) return 1;

    // 秘密鍵の取得
    EVP_PKEY* private_key = load_private_key("private_key.pem");
    if (!private_key) return 1;

    // 現在時刻の取得
    char Formatted_Time = set_time_stamp();
    
    // 有効期限の取得
    std::string expirationTime = calculateExpirationTime(24, Formatted_Time);
    
    // 送信元の公開鍵を取得して証明書を作成
    test_cert1 = Makes_Certificate(
        get_own_ip(), 
        get_PublicKey_As_String(public_key), 
        Formatted_Time, 
        expirationTime
    );

    // RDP_format オブジェクトを作成
    RDP_format rdp = {
        MessageType::RDP,
        "10.0.0.1", // 送信元IP
        "10.0.0.3", // 宛先IP
        test_cert1,
        std::random_device()(),
        Formatted_Time,
        {}, // 空の署名
    };

    test_rdp1 = Makes_RDP(
        rdp,
        {},
        {}
    );
    
    // 署名対象メッセージを作成
    std::string message = construct_message(test_rdp1);
    
    test_rdp1.rdp.signature = signMessage(private_key, message);
    if (test_rdp1.rdp.signature.empty()) return -1;
    
    std::cout << std::dec << std::endl;

    // シリアライズ処理
    std::vector<uint8_t> buf(2048);
    serialize_forwarding_data(test_rdp1, buf);
    
    // データ送信
    if (send_process(buf)) {
        std::cout << "Message sent successfully" << std::endl;
    }

    // レスポンス受信
    std::cout << "-------------------------------------Waiting for response-------------------------------------" << std::endl;
    while (true) {
        // 受信処理
        std::vector<uint8_t> recv_buf;
        std::string sender_ip;

        // 受信処理
        std::tie(recv_buf, sender_ip) = receving_process(sock);
        std::cout << "sender_ip: " << sender_ip << std::endl;

        try {
            // パケットタイプを取得
            MessageType packet_type = get_packet_type(recv_buf);
            std::cout << "Received packet_type:" << static_cast<int>(packet_type) << std::endl;

            if (packet_type == MessageType::REP) {
                // REP メッセージのデシリアライズ
                Forwarding_REP_format deserialized_rep = deserialize_forwarding_rep(recv_buf);

                // REP メッセージの内容をログに出力
                std::cout << "Received REP:" << std::endl;
                std::cout << "  Type: " << static_cast<int>(deserialized_rep.type) << std::endl;
                std::cout << "  Destination IP: " << deserialized_rep.dest_ip << std::endl;
                std::cout << "  Certificate Own IP: " << deserialized_rep.cert.own_ip << std::endl;
                std::cout << "  Certificate Public Key: " << deserialized_rep.cert.own_public_key << std::endl;
                std::cout << "  Certificate Timestamp: " << deserialized_rep.cert.t << std::endl;
                std::cout << "  Certificate Expiration: " << deserialized_rep.cert.expires << std::endl;
                std::cout << "  Nonce: " << deserialized_rep.n << std::endl;
                std::cout << "  Timestamp: " << deserialized_rep.t << std::endl;
                std::cout << "  Signature Size: " << deserialized_rep.signature.size() << std::endl;
                std::cout << "  Receiver Signature Size: " << deserialized_rep.receiver_signature.size() << std::endl;
                std::cout << "  Receiver Certificate Own IP: " << deserialized_rep.receiver_cert.own_ip << std::endl;
                std::cout << "  Receiver Certificate Public Key: " << deserialized_rep.receiver_cert.own_public_key << std::endl;
                std::cout << "  Receiver Certificate Timestamp: " << deserialized_rep.receiver_cert.t << std::endl;
                std::cout << "  Receiver Certificate Expiration: " << deserialized_rep.receiver_cert.expires << std::endl;

                break; // レスポンスを受信したらループを終了
            } else {
                std::cout << "Received non-REP message. Ignoring..." << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error during response processing: " << e.what() << std::endl;
        }
    }

    // リソース解放
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);
    close(sock);

    return 0;
}
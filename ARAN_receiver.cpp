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
#include <tuple>
#include <list>
#include <algorithm>

enum class MessageType : uint8_t {
    RDP = 0x01,
    REP = 0x02,
    ForwardRDP = 0x03
};

struct Certificate_Format {
    char own_ip[16]; //16byteのIPアドレス
    char own_public_key[256]; //256byteの公開鍵 ここはunsigned charにするか要検討
    char time_stamp[20]; //20byteのタイムスタンプ
    char expires[20]; //20byteの有効期限
};

struct RDP_format {
    MessageType type; //1バイト
    //char source_ip[16]; //16バイト
    char dest_ip[16];
    Certificate_Format cert;
    std::uint32_t nonce;
    char time_stamp[20];
    std::array<unsigned char,256> signature;
};

struct Forwarding_RDP_format {
    RDP_format rdp;
    std::vector<unsigned char> receiver_signature;
    Certificate_Format receiver_cert;
};

struct Forwarding_REP_format {
    MessageType type; //1バイト
    char source_ip[16]; //16バイト
    char dest_ip[16];
    Certificate_Format cert;
    std::uint32_t nonce;
    char time_stamp[20];
    std::array<unsigned char,256> signature;
    std::array<unsigned char,256> receiver_signature;
    Certificate_Format receiver_cert;
};

//重複確認用の構造体
struct InfoSet {
    char ip[16];
    uint32_t nonce;
    char time_stamp[20];
};

// 重複確認用関数
bool isDuplicate(const std::list<InfoSet>& infoList, const InfoSet& newInfo) {
    for (const InfoSet& info : infoList) {
        if (std::strcmp(info.ip, newInfo.ip) == 0 && info.nonce == newInfo.nonce && std::strcmp(info.time_stamp, newInfo.time_stamp) == 0) {
            return true; // 重複している
        }
    }
    return false; // 重複していない
}

MessageType get_packet_type(const std::vector<uint8_t>& buf) {
    if (buf.size() < 1) {
        throw std::runtime_error("Buffer too small to determine packet type");
    }

    // バッファの先頭1バイトを MessageType に変換
    return static_cast<MessageType>(buf[0]);
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

int broadcast_send_process(std::vector<uint8_t> buf) {
    std::cout << "Broadcatst send process" << std::endl;
    int yes=1;
    // 送信処理
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 1;

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
        //std::cout << "send success" << std::endl;
        close(sock);
        return 1;
    }
}

int unicast_send_process(std::vector<uint8_t> buf, std::string next_ip) {
    // 送信処理
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 1;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);
    addr.sin_addr.s_addr = inet_addr(next_ip.c_str());

    std::cout << "Sending data of size: " << buf.size() << " bytes" << std::endl;

    if (sendto(sock, buf.data(), buf.size(), 0, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("send failed");
        close(sock);
        return 0;
    } else {
        std::cout << "unicast send success" << std::endl;
        close(sock);
        return 1;
    }
}
// シリアライズ処理(RDP)
void serialize(const Forwarding_RDP_format& rdp, unsigned char* buf) {
    size_t offset = 0;

    //type
    buf[offset] = static_cast<uint8_t>(rdp.rdp.type);
    offset += sizeof(uint8_t);

    // //source_ip
    // std::memcpy(buf + offset, rdp.rdp.source_ip, sizeof(rdp.rdp.source_ip));
    // offset += sizeof(rdp.rdp.source_ip);

    //dest_ip
    std::memcpy(buf + offset, rdp.rdp.dest_ip, sizeof(rdp.rdp.dest_ip));
    offset += sizeof(rdp.rdp.dest_ip);

    //cert_own_ip
    std::memcpy(buf + offset, rdp.rdp.cert.own_ip, sizeof(rdp.rdp.cert.own_ip));
    offset += sizeof(rdp.rdp.cert.own_ip);
    //cert_own_public_key
    std::memcpy(buf + offset, rdp.rdp.cert.own_public_key, sizeof(rdp.rdp.cert.own_public_key));
    offset += sizeof(rdp.rdp.cert.own_public_key);

    //cert_timestamp
    std::memcpy(buf + offset, rdp.rdp.cert.time_stamp, sizeof(rdp.rdp.cert.time_stamp));
    offset += sizeof(rdp.rdp.cert.time_stamp);

    //cert_expires
    std::memcpy(buf + offset, rdp.rdp.cert.expires, sizeof(rdp.rdp.cert.expires));
    offset += sizeof(rdp.rdp.cert.expires);


    //nonce
    std::memcpy(buf + offset, &rdp.rdp.nonce, sizeof(rdp.rdp.nonce));
    offset += sizeof(rdp.rdp.nonce);

    //time_stamp
    std::memcpy(buf + offset, rdp.rdp.time_stamp, sizeof(rdp.rdp.time_stamp));
    offset += sizeof(rdp.rdp.time_stamp);

    //signature
    std::memcpy(buf + offset, rdp.rdp.signature.data(), rdp.rdp.signature.size());
    offset += rdp.rdp.signature.size();
}
//RDP_formatのシリアライズ処理
void serialize(const RDP_format& rdp, unsigned char* buf) {
    size_t offset = 0;

    //type
    buf[offset] = static_cast<uint8_t>(rdp.type);
    offset += sizeof(uint8_t);

    //source_ip
    // std::memcpy(buf + offset, rdp.source_ip, sizeof(rdp.source_ip));
    // offset += sizeof(rdp.source_ip);

    //dest_ip
    std::memcpy(buf + offset, rdp.dest_ip, sizeof(rdp.dest_ip));
    offset += sizeof(rdp.dest_ip);

    //cert_own_ip
    std::memcpy(buf + offset, rdp.cert.own_ip, sizeof(rdp.cert.own_ip));
    offset += sizeof(rdp.cert.own_ip);
    //cert_own_public_key
    std::memcpy(buf + offset, rdp.cert.own_public_key, sizeof(rdp.cert.own_public_key));
    offset += sizeof(rdp.cert.own_public_key);

    //cert_timestamp
    std::memcpy(buf + offset, rdp.cert.time_stamp, sizeof(rdp.cert.time_stamp));
    offset += sizeof(rdp.cert.time_stamp);

    //cert_expires
    std::memcpy(buf + offset, rdp.cert.expires, sizeof(rdp.cert.expires));
    offset += sizeof(rdp.cert.expires);


    //nonce
    std::memcpy(buf + offset, &rdp.nonce, sizeof(rdp.nonce));
    offset += sizeof(rdp.nonce);

    //time_stamp
    std::memcpy(buf + offset, rdp.time_stamp, sizeof(rdp.time_stamp));
    offset += sizeof(rdp.time_stamp);

    //signature
    std::memcpy(buf + offset, rdp.signature.data(), rdp.signature.size());
    offset += rdp.signature.size();
}

// デシリアライズ処理(RDP)
void deserialize(const std::vector<uint8_t>& buf, RDP_format& rdp) {
    size_t offset = 0;

    //type
    rdp.type = static_cast<MessageType>(buf[offset]);
    offset += sizeof(uint8_t);
    //printf("rdp.type: %d\n",rdp.type);

    //source_ip
    // std::memcpy(rdp.source_ip, buf.data() + offset, sizeof(rdp.source_ip));
    // offset += sizeof(rdp.source_ip);
    //printf("rdp.source_ip: %s\n",rdp.source_ip);

    //dest_ip
    std::memcpy(rdp.dest_ip, buf.data() + offset, sizeof(rdp.dest_ip));
    offset += sizeof(rdp.dest_ip);
    //printf("rdp.dest_ip: %s\n",rdp.dest_ip);

    //cert_own_ip
    std::memcpy(rdp.cert.own_ip, buf.data() + offset, sizeof(rdp.cert.own_ip));
    offset += sizeof(rdp.cert.own_ip);
    //printf("rdp.cert.own_ip: %s\n",rdp.cert.own_ip);
    
    //cert_own_public_key
    std::memcpy(rdp.cert.own_public_key, buf.data() + offset, sizeof(rdp.cert.own_public_key));
    offset += sizeof(rdp.cert.own_public_key);
    //printf("rdp.cert.own_public_key: %s\n",rdp.cert.own_public_key);
    
    //cert_timestamp
    std::memcpy(rdp.cert.time_stamp, buf.data() + offset, sizeof(rdp.cert.time_stamp));
    offset += sizeof(rdp.cert.time_stamp);
    //printf("rdp.cert.time_stamp: %s\n",rdp.cert.time_stamp);
    
    //cert_expires
    std::memcpy(rdp.cert.expires, buf.data() + offset, sizeof(rdp.cert.expires));
    offset += sizeof(rdp.cert.expires);
    //printf("rdp.cert.expires: %s\n",rdp.cert.expires);
    
    //nonce
    std::memcpy(&rdp.nonce, buf.data() + offset, sizeof(rdp.nonce));
    offset += sizeof(rdp.nonce);
    //printf("rdp.nonce: %u\n",rdp.nonce);

    //time_stamp
    std::memcpy(rdp.time_stamp, buf.data() + offset, sizeof(rdp.time_stamp));
    offset += sizeof(rdp.time_stamp);
    printf("rdp.time_stamp: %s\n",rdp.time_stamp);

    //signature
    std::memcpy(rdp.signature.data(), buf.data() + offset, rdp.signature.size());
    //printf("rdp.signature: %s\n",rdp.signature.data());
}

// デシリアライズ処理(REP)
void deserialize(const std::vector<uint8_t>& buf, Forwarding_RDP_format& rep) {
    size_t offset = 0;

    //type
    rep.rdp.type = static_cast<MessageType>(buf[offset]);
    offset += sizeof(uint8_t);

    //dest_ip
    std::memcpy(rep.rdp.dest_ip, buf.data() + offset, sizeof(rep.rdp.dest_ip));
    offset += sizeof(rep.rdp.dest_ip);

    //cert_own_ip
    std::memcpy(rep.rdp.cert.own_ip, buf.data() + offset, sizeof(rep.rdp.cert.own_ip));
    offset += sizeof(rep.rdp.cert.own_ip);
    //cert_own_public_key
    std::memcpy(rep.rdp.cert.own_public_key, buf.data() + offset, sizeof(rep.rdp.cert.own_public_key));
    offset += sizeof(rep.rdp.cert.own_public_key);
    //cert_timestamp
    std::memcpy(rep.rdp.cert.time_stamp, buf.data() + offset, sizeof(rep.rdp.cert.time_stamp));
    offset += sizeof(rep.rdp.cert.time_stamp);
    //cert_expires
    std::memcpy(rep.rdp.cert.expires, buf.data() + offset, sizeof(rep.rdp.cert.expires));
    offset += sizeof(rep.rdp.cert.expires);
    
    //cert_nonce
    std::memcpy(&rep.rdp.nonce, buf.data() + offset, sizeof(rep.rdp.nonce));
    offset += sizeof(rep.rdp.nonce);

    //time_stamp
    std::memcpy(rep.rdp.time_stamp, buf.data() + offset, sizeof(rep.rdp.time_stamp));
    offset += sizeof(rep.rdp.time_stamp);

    //signature
    std::memcpy(rep.rdp.signature.data(), buf.data() + offset, rep.rdp.signature.size());
}

// デシリアライズ処理(REP)
void deserialize(const std::vector<uint8_t>& buf, Forwarding_REP_format& rep) {
    size_t offset = 0;

    //type
    rep.type = static_cast<MessageType>(buf[offset]);
    offset += sizeof(uint8_t);

    //dest_ip
    std::memcpy(rep.dest_ip, buf.data() + offset, sizeof(rep.dest_ip));
    offset += sizeof(rep.dest_ip);

    //cert_own_ip
    std::memcpy(rep.cert.own_ip, buf.data() + offset, sizeof(rep.cert.own_ip));
    offset += sizeof(rep.cert.own_ip);
    //cert_own_public_key
    std::memcpy(rep.cert.own_public_key, buf.data() + offset, sizeof(rep.cert.own_public_key));
    offset += sizeof(rep.cert.own_public_key);
    //cert_timestamp
    std::memcpy(rep.cert.time_stamp, buf.data() + offset, sizeof(rep.cert.time_stamp));
    offset += sizeof(rep.cert.time_stamp);
    //cert_expires
    std::memcpy(rep.cert.expires, buf.data() + offset, sizeof(rep.cert.expires));
    offset += sizeof(rep.cert.expires);
    
    //nonce
    std::memcpy(&rep.nonce, buf.data() + offset, sizeof(rep.nonce));
    offset += sizeof(rep.nonce);

    //time_stamp
    std::memcpy(rep.time_stamp, buf.data() + offset, sizeof(rep.time_stamp));
    offset += sizeof(rep.time_stamp);

    //signature
    std::memcpy(rep.signature.data(), buf.data() + offset, rep.signature.size());
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
//REP専用のシリアライズ関数
void serialize_forwarding_rep(const Forwarding_REP_format& rep, std::vector<uint8_t>& buf) {
    auto serialize_string = [&buf](const std::string& str) {
        std::uint32_t len = str.size();
        buf.push_back((len >> 0) & 0xFF);
        buf.push_back((len >> 8) & 0xFF);
        buf.push_back((len >> 16) & 0xFF);
        buf.push_back((len >> 24) & 0xFF);
        buf.insert(buf.end(), str.begin(), str.end());
    };

    // type のシリアライズ
    buf.push_back(static_cast<uint8_t>(rep.type));

    // dest_ip のシリアライズ
    serialize_string(rep.dest_ip);

    // Certificate_Format のシリアライズ
    serialize_string(rep.cert.own_ip);
    serialize_string(rep.cert.own_public_key);
    serialize_string(rep.cert.time_stamp);
    serialize_string(rep.cert.expires);

    // n のシリアライズ
    for (int i = 0; i < 4; i++) {
        buf.push_back((rep.nonce >> (8 * i)) & 0xFF);
    }

    // t のシリアライズ
    serialize_string(rep.time_stamp);

    // signature のシリアライズ
    std::uint32_t sig_len = rep.signature.size();
    buf.push_back((sig_len >> 0) & 0xFF);
    buf.push_back((sig_len >> 8) & 0xFF);
    buf.push_back((sig_len >> 16) & 0xFF);
    buf.push_back((sig_len >> 24) & 0xFF);
    buf.insert(buf.end(), rep.signature.begin(), rep.signature.end());

    // receiver_signature のシリアライズ
    std::uint32_t receiver_sig_len = rep.receiver_signature.size();
    buf.push_back((receiver_sig_len >> 0) & 0xFF);
    buf.push_back((receiver_sig_len >> 8) & 0xFF);
    buf.push_back((receiver_sig_len >> 16) & 0xFF);
    buf.push_back((receiver_sig_len >> 24) & 0xFF);
    buf.insert(buf.end(), rep.receiver_signature.begin(), rep.receiver_signature.end());

    // receiver_cert のシリアライズ
    serialize_string(rep.receiver_cert.own_ip);
    serialize_string(rep.receiver_cert.own_public_key);
    serialize_string(rep.receiver_cert.time_stamp);
    serialize_string(rep.receiver_cert.expires);
}

std::string certificate_to_string(const Certificate_Format& cert) {
    std::ostringstream certStream;
    certStream << cert.own_ip << "|\n"
               << cert.own_public_key << "|\n"
               << cert.time_stamp << "|\n"
               << cert.expires << "|\n";
    return certStream.str();
}

// 署名付きメッセージを分割する関数
std::tuple<std::string, std::vector<unsigned char>, std::string> split_sign_message(const std::string& signed_message) {
    std::string delimiter = "Message-with-public-key-end";
    size_t pos = signed_message.find(delimiter);
    if (pos == std::string::npos) {
        throw std::runtime_error("Delimiter not found in signed message");
    }

    // メッセージ部分と署名部分を分割
    std::string message = signed_message.substr(0, pos + delimiter.length());
    std::string signature_and_ip = signed_message.substr(pos + delimiter.length());

    std::string receiver_delimiter = "receiver-signature-and-certificate";
    size_t receiver_pos = signature_and_ip.find(receiver_delimiter);
    if (receiver_pos == std::string::npos) {
        throw std::runtime_error("Delimiter not found in signed message");
    }

    // 署名部分と証明書部分を分割
    std::string receiver_splited_signature = signature_and_ip.substr(0, receiver_pos);
    std::string receiver_splited_certificate = signature_and_ip.substr(receiver_pos + receiver_delimiter.length());

    // 署名部分をバイト列に変換
    std::vector<unsigned char> signature;
    for (size_t i = 0; i < receiver_splited_signature.length(); i += 2) {
        std::string byteString = receiver_splited_signature.substr(i, 2);
        try {
            unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
            signature.push_back(byte);
        } catch (const std::exception& e) {
            std::cerr << "Error converting hex to byte: " << e.what() << std::endl;
            throw;
        }
    }

    return {message, signature, receiver_splited_certificate};
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
std::string construct_message_with_key(const Forwarding_RDP_format& deserialized_rdp, const std::string& public_key_str) {
    std::ostringstream messageStream;
    messageStream << static_cast<int>(deserialized_rdp.rdp.type) << "|\n"
                  << deserialized_rdp.rdp.dest_ip << "|\n" 
                  << certificate_to_string(deserialized_rdp.rdp.cert) << "|\n"
                  << deserialized_rdp.rdp.nonce << "|\n"
                  << deserialized_rdp.rdp.time_stamp << "|\n"
                  << public_key_str  // 公開鍵を追加
                  << "Message-with-public-key-end\n"; 
    return messageStream.str();
}

// メッセージを構築する関数
std::string construct_message_with_key(const Forwarding_REP_format& deserialized_rep, const std::string& public_key_str) {
    std::ostringstream messageStream;
    messageStream << static_cast<int>(deserialized_rep.type) << "|\n"
                  << deserialized_rep.dest_ip << "|\n" 
                  << certificate_to_string(deserialized_rep.cert) << "|\n"<< deserialized_rep.nonce << "|\n"
                  << deserialized_rep.time_stamp << "|\n"
                  << public_key_str  // 公開鍵を追加
                  << "Message-with-public-key-end\n"; 

    //std::cout << messageStream.str() << std::endl;
    
    return messageStream.str();
}

std::string get_time(bool forceError = false) {
    if (forceError) {
        std::cerr << "Forced error: Failed to get local time" << std::endl;
        return std::string(20, '\0'); // エラー時は20バイトのヌル文字列を返す
    }

    auto now = std::chrono::system_clock::now();
    std::time_t currentTime = std::chrono::system_clock::to_time_t(now);
    std::tm* localTime = std::localtime(&currentTime);

    // 時刻をフォーマット
    char formattedTime[20] = {};
    if (localTime) {
        std::strftime(formattedTime, sizeof(formattedTime), "%Y-%m-%d %H:%M:%S", localTime);
    } else {
        std::cerr << "Failed to get local time" << std::endl;
        return std::string(20, '\0'); // エラー時は20バイトのヌル文字列を返す
    }

    return std::string(formattedTime); // std::string に変換して返す
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

Forwarding_REP_format Makes_REP(MessageType type,const char* dest_ip, Certificate_Format cert, std::uint32_t nonce,const char* time_stamp, std::array<unsigned char,256> signature, std::array<unsigned char,256> receiver_signature, Certificate_Format receiver_cert) 
{
    Forwarding_REP_format rep;
    // type の設定
    rep.type = type;
    //dest_ip の設定
    std::strncpy(rep.dest_ip, dest_ip, sizeof(rep.dest_ip) - 1);
    rep.dest_ip[sizeof(rep.dest_ip) - 1] = '\0'; // Null-terminate
    //cert の設定
    rep.cert = cert;

    //nonce の設定
    rep.nonce = nonce;
    //time_stamp の設定
    std::strncpy(rep.time_stamp, time_stamp, sizeof(rep.time_stamp) - 1);
    rep.time_stamp[sizeof(rep.time_stamp) - 1] = '\0'; // Null-terminate

    //signature の設定
    rep.signature = signature;
    //receiver_signature の設定
    rep.receiver_signature = receiver_signature;
    //receiver_cert の設定
    rep.receiver_cert = receiver_cert;

    return rep;
}


Certificate_Format Makes_Certificate(const char* own_ip,const char* own_public_key,const char* time_stamp,const char* expires) {  //own_public_keyはunsigned charにするか要検討
    Certificate_Format Certificate = {};
    std::strncpy(Certificate.own_ip, own_ip, sizeof(Certificate.own_ip) - 1);
    Certificate.own_ip[sizeof(Certificate.own_ip) - 1] = '\0'; // Null-terminate

    std::strncpy(Certificate.own_public_key, own_public_key, sizeof(Certificate.own_public_key) - 1);
    Certificate.own_public_key[sizeof(Certificate.own_public_key) - 1] = '\0'; // Null-terminate

    std::strncpy(Certificate.time_stamp, time_stamp, sizeof(Certificate.time_stamp) - 1);
    Certificate.time_stamp[sizeof(Certificate.time_stamp) - 1] = '\0'; // Null-terminate

    std::strncpy(Certificate.expires, expires, sizeof(Certificate.expires) - 1);
    Certificate.expires[sizeof(Certificate.expires) - 1] = '\0'; // Null-terminate

    return Certificate;
}

//Infosetを作成する関数
InfoSet Makes_InfoSet(const char* ip, const uint32_t nonce, const char* time_stamp) {
    InfoSet infoSet;
    std::strncpy(infoSet.ip, ip, sizeof(infoSet.ip) - 1);
    infoSet.ip[sizeof(infoSet.ip) - 1] = '\0'; // Null-terminate

    infoSet.nonce = nonce;

    std::strncpy(infoSet.time_stamp, time_stamp, sizeof(infoSet.time_stamp) - 1);
    infoSet.time_stamp[sizeof(infoSet.time_stamp) - 1] = '\0'; // Null-terminate

    return infoSet;
}
// 署名を生成する関数(固定長署名)
std::vector<unsigned char> sign_message(EVP_PKEY* private_key, const std::string& message) {
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

    std::cout << "---------------------------signature generation is success-----------------" << std::endl;

    EVP_MD_CTX_free(ctx);
    return signature;
}
// 署名を検証する関数(可変長署名)
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

bool verifySignature(EVP_PKEY* public_key, const std::string& message, const unsigned char* signature, size_t sig_len) {
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

    int result = EVP_DigestVerifyFinal(ctx, reinterpret_cast<const unsigned char*>(signature), sig_len);
    EVP_MD_CTX_free(ctx);

    if (result == 1) return true;
    if (result == 0) return false;

    std::cerr << "EVP_DigestVerifyFinal failed" << std::endl;
    return false;
}

// std::tuple<std::string, std::string, std::uint32_t> get_time_nonce_address(const char* time_stamp, std::string sender_ip, std::uint32_t nonce) {
//     std::string formattedTime = time_stamp;
//     std::uint32_t nonce = nonce;
//     std::string ip_address = sender_ip;

//     return {formattedTime, ip_address, nonce};
// }


std::tuple<std::vector<uint8_t>, std::string> receving_process(int sock) {
    std::cout << "receive process start" << std::endl;

    struct sockaddr_in sender_addr;
    socklen_t addr_len = sizeof(sender_addr);
    char buf[2048];
    memset(buf, 0, sizeof(buf));

    ssize_t received_bytes = recvfrom(sock, buf, sizeof(buf), 0, reinterpret_cast<struct sockaddr*>(&sender_addr), &addr_len);
    
    if (received_bytes < 0) {
        std::cerr << "Failed to receive data" << std::endl;
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

int main() {
    // ブロードキャスト受信の設定
    int sock;
    struct sockaddr_in addr;
    char buf[2048];
    std::string own_ip_address = get_own_ip();
    std::string dest_ip = "";
    std::string next_ip = "";
    std::vector<uint8_t> send_buf(2048);


    // タイムスタンプ,ノンスと受信ノードのIPアドレスを管理するリスト
    InfoSet new_info_set = {};
    //既に受信したメッセージのリスト
    std::list<InfoSet> received_info_set = {};
    //std::list<std::tuple<std::string, std::string, std::uint32_t>> received_messages; //改善する必要あり

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return 1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);
    addr.sin_addr.s_addr = INADDR_ANY;

    // バインド処理
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        std::cerr << "Failed to bind socket" << std::endl;
        return 1;
    }

    std::cout << "bind success" << std::endl;

    while (true)
    {
        //受信処理
        struct sockaddr_in sender_addr;
        socklen_t addr_len = sizeof(sender_addr);
        memset(buf, 0, sizeof(buf));

        std::vector<uint8_t> recv_buf;
        std::string sender_ip_raw; //インターフェースから受信する生データ。おいおいchar[16]に格納する。

        // 受信処理
        std::tie(recv_buf, sender_ip_raw) = receving_process(sock);
        std::cout << "sender_ip: " << sender_ip_raw << std::endl;
        
        // 受信処理
        
        // 公開鍵の取得
        EVP_PKEY* public_key = load_public_key("public_key.pem");
        if (!public_key) {
            std::cerr << "Error: Could not load public key!" << std::endl;
            continue;
        }
        
        // 秘密鍵の取得
        EVP_PKEY* private_key = load_private_key("private_key.pem");
        if (!private_key) {
            std::cerr << "Error: Could not load private key!" << std::endl;
            continue;
        }
        
        try {
            //REPかRDPか、Forwarding_RDPかを判断。
            MessageType packet_type = get_packet_type(recv_buf);
            //std::cout.flush();

            if(static_cast<int>(packet_type) == 1) {
                std::cout << "-----------------------------------RDP--------------------------------------" << std::endl;
                RDP_format deserialized_rdp = {};
                deserialize(recv_buf, deserialized_rdp);
                //受信データを確認
                std::cout << "deserialize_rdp.type:" << static_cast<int>(deserialized_rdp.type)<< std::endl;
                std::cout << "deserialize_rdp.dest_ip:" << deserialized_rdp.dest_ip << std::endl;
                std::cout << "deserialize_rdp.cert.own_ip:" << deserialized_rdp.cert.own_ip << std::endl;
                std::cout << "deserialize_rdp.cert.own_public_key:" << deserialized_rdp.cert.own_public_key << std::endl;
                std::cout << "deserialize_rdp.cert.time_stamp:" << deserialized_rdp.cert.time_stamp << std::endl;
                std::cout << "deserialize_rdp.cert.expires:" << deserialized_rdp.cert.expires << std::endl;
                std::cout << "deserialize_rdp.nonce:" << deserialized_rdp.nonce << std::endl;
                std::cout << "deserialize_rdp.time_stamp:" << deserialized_rdp.time_stamp << std::endl;
                std::cout << "deserialize_rdp.signature.size:" << deserialized_rdp.signature.size() << std::endl;
                std::cout << "deserialize_rdp.signature:" << deserialized_rdp.signature.data() << std::endl;
                std::cout << "-----------------------------------RDP--------------------------------------" << std::endl;
                
                //新たに受信したデータをnew_info_setに追加
                new_info_set = Makes_InfoSet(deserialized_rdp.cert.own_ip, deserialized_rdp.nonce, deserialized_rdp.time_stamp);
            
                // 受信したメッセージのtime stamp:tとnonce:nが既に受信したものかどうかを確認する
                if(isDuplicate(received_info_set, new_info_set)) {
                    std::cout << "Duplicate message detected. Ignoring..." << std::endl;
                    continue; // 重複している場合は無視
                } else {
                    std::cout << "New message detected. Adding to list..." << std::endl;
                    received_info_set.push_back(new_info_set); // 新しいメッセージをリストに追加
                }
                std::cout << "New message received. Processing..." << std::endl;
            
                // 宛先確認
                if (deserialized_rdp.dest_ip == own_ip_address) {
                    std::cout << "This message is for me." << std::endl;

                    // 現在時刻の取得
                    std::string Formatted_Time = get_time();
                    
                    // 有効期限の取得
                    std::string expirationTime = calculateExpirationTime(24, Formatted_Time);

                    char own_ip[16] = {};
                    std::strncpy(own_ip, get_own_ip().c_str(), sizeof(own_ip) - 1);

                    char own_public_key[256] = {};
                    std::strncpy(own_public_key, get_PublicKey_As_String(public_key).c_str(), sizeof(own_public_key) - 1);

                    char formatted_Time[20] = {};
                    std::strncpy(formatted_Time, Formatted_Time.data(), sizeof(formatted_Time) - 1);

                    char expiration_time[20] = {};
                    std::strncpy(expiration_time, expirationTime.data(), sizeof(expiration_time) - 1);
                    
                    //REPの作成
                    //自身の証明書を作成
                    Certificate_Format own_certificate = Makes_Certificate(own_ip, own_public_key, formatted_Time, expiration_time);
                    //署名サイズを出力
                    std::cout << "Signature size:" << deserialized_rdp.signature.size() << std::endl;   

                    std::cout << "-------------------------------------Destination sends REP-------------------------------------" << std::endl;
                    Forwarding_REP_format rep = Makes_REP(MessageType::REP, deserialized_rdp.cert.own_ip, own_certificate, deserialized_rdp.nonce, deserialized_rdp.time_stamp, deserialized_rdp.signature , {}, {});
                    std::cout << "rep.type: "<< static_cast<int>(rep.type) << std::endl;
                    std::cout << "rep.dest_ip:" << rep.dest_ip << std::endl;
                    std::cout << "rep.cert.own_ip" << rep.cert.own_ip << std::endl;
                    std::cout << "rep.cert.own_public_key:"<< rep.cert.own_public_key << std::endl;
                    std::cout << "rep.cert.t:"<< rep.cert.time_stamp << std::endl;
                    std::cout << "rep.cert.expires:" <<rep.cert.expires << std::endl;
                    std::cout <<"rep.n:" << rep.nonce << std::endl;
                    std::cout << "rep.signature.size:"<< rep.signature.size() << std::endl;
                    std::cout << "recp.receiver_singature:"<< rep.receiver_signature.size() << std::endl;
                    std::cout << "rep.receiver_cert.own_ip:"<< rep.receiver_cert.own_ip << std::endl;
                    std::cout << "rep.receiver_cert.own_public_key:"<< rep.receiver_cert.own_public_key << std::endl;
                    std::cout << "rep.receiver_cert.t:"<< rep.receiver_cert.time_stamp << std::endl;
                    std::cout << "rep.receiver_cert.expires:" << rep.receiver_cert.expires << std::endl;

                    
                    // REPをシリアライズ
                    std::vector<uint8_t> rep_buf;
                    serialize_forwarding_rep(rep, rep_buf);

                    // REPを送信(宛先は一つ前の端末に向けて送信)
                    struct sockaddr_in rep_addr;
                    rep_addr.sin_family = AF_INET;
                    rep_addr.sin_port = htons(12345);
                    std::cout << "Send REP to : " << sender_ip_raw<< std::endl;
                    std::cout << "Send REP size:" << rep_buf.size() << std::endl; 
                    rep_addr.sin_addr.s_addr = inet_addr(sender_ip_raw.c_str());

                    int rep_sock = socket(AF_INET, SOCK_DGRAM, 0);
                    if (rep_sock < 0) {
                        std::cerr << "Failed to create socket for REP" << std::endl;
                    }
                    std::cout << "Next ip:" << sender_ip_raw << std::endl;
                    if (sendto(rep_sock, rep_buf.data(), rep_buf.size(), 0, reinterpret_cast<struct sockaddr*>(&rep_addr), sizeof(rep_addr)) < 0) {
                        perror("sendto failed for REP");
                    } else {
                        std::cout << "---------------------------REP sent successfully to " << sender_ip_raw <<"------------------------------" << std::endl;

                    }

                    close(rep_sock);

                } else {
                std::cout << "This message is not for me. Forwarding..." << std::endl;

                }
                //deserialized_rdp.receiver_signature = signature;
                // 現在時刻の取得
                std::string Formatted_Time = get_time();
    
                // 有効期限の取得
                std::string expirationTime = calculateExpirationTime(24, Formatted_Time);


                char own_ip[16] = {};
                std::strncpy(own_ip, get_own_ip().c_str(), sizeof(own_ip) - 1);

                char own_public_key[256] = {};
                std::strncpy(own_public_key, get_PublicKey_As_String(public_key).c_str(), sizeof(own_public_key) - 1);

                char formatted_Time[20] = {};
                std::strncpy(formatted_Time, Formatted_Time.data(), sizeof(formatted_Time) - 1);

                char expiration_time[20] = {};
                std::strncpy(expiration_time, expirationTime.data(), sizeof(expiration_time) - 1);
                        
                // 転送端末の証明書を作成
                Certificate_Format forwarder_certificate = Makes_Certificate(own_ip, own_public_key, formatted_Time, expiration_time);
            
                //deserialized_rdp.receiver_cert = forwarder_certificate;
                // Forwarding_RDP_format をシリアライズ
                serialize(deserialized_rdp, send_buf.data());

                //RDPならブロードキャスト転送する。
                broadcast_send_process(send_buf);
            
            } else if(static_cast<int>(packet_type) == 2){
                // REPのデシリアライズ
                Forwarding_REP_format deserialized_rep = {};
                deserialize(recv_buf, deserialized_rep);
                std::cout << "deserialize_rep.type:" << static_cast<int>(deserialized_rep.type)<< std::endl;
                std::cout << "deserialize_rep.dest_ip:" << deserialized_rep.dest_ip << std::endl;
                std::cout << "deserialize_rep.cert.own_ip" << deserialized_rep.cert.own_ip << std::endl;
                std::cout << "deserialize_rep.cert.own_public_key:"<< deserialized_rep.cert.own_public_key << std::endl;
                std::cout << "deserialize_rep.n:" << deserialized_rep.nonce << std::endl;
                std::cout << "deserialize_rep.cert.t:"<< deserialized_rep.cert.time_stamp << std::endl;
                std::cout << "deserialize_rep.signature.size:"<< deserialized_rep.signature.size() << std::endl;
                std::cout << "deserialize_rep.cert.expires:" << deserialized_rep.cert.expires << std::endl;
                std::cout << "-------------------------------------Forwarding REP-------------------------------------" << std::endl;

                // 受信したメッセージの中に転送端末の署名および証明書がないかを確認
                if (!deserialized_rep.receiver_signature.empty() && strlen(deserialized_rep.receiver_cert.own_ip) == 0) {
                    std::cout << "Forwarder signature and certificate found. Removing them..." << std::endl;
                    std::cout << "receiver_cert.own_ip:" << deserialized_rep.receiver_cert.own_ip << std::endl;

                    // 転送端末の署名および証明書を取り除く(0バイトの配列にする)
                    std::memset(deserialized_rep.receiver_signature.data(), 0, sizeof(deserialized_rep.receiver_signature));
                    deserialized_rep.receiver_cert = Certificate_Format();
                } else {
                    std::cout << "Forwarder signature and certificate not found." << std::endl;
                }

                    // 現在時刻の取得
                    std::string Formatted_Time = get_time();
    
                    // 有効期限の取得
                    std::string expirationTime = calculateExpirationTime(24, Formatted_Time);

                    char own_ip[16] = {};
                    std::strncpy(own_ip, get_own_ip().c_str(), sizeof(own_ip) - 1);

                    char own_public_key[256] = {};
                    std::strncpy(own_public_key, get_PublicKey_As_String(public_key).c_str(), sizeof(own_public_key) - 1);

                    char formatted_Time[20] = {};
                    std::strncpy(formatted_Time, Formatted_Time.data(), sizeof(formatted_Time) - 1);

                    char expiration_time[20] = {};
                    std::strncpy(expiration_time, expirationTime.data(), sizeof(expiration_time) - 1);

                    std::string signed_message = construct_message_with_key(deserialized_rep, get_PublicKey_As_String(public_key));
                    std::vector<unsigned char> signature = sign_message(private_key, signed_message);
                    if (signature.empty()) {
                        std::cerr << "Failed to sign the message" << std::endl;
                        return 1;
                    }
                    memcpy(deserialized_rep.receiver_signature.data(), signature.data(), signature.size());
                    //deserialized_rep.receiver_signature = signature;
                
                    // 転送端末の証明書を作成
                    Certificate_Format forwarder_certificate = Makes_Certificate(own_ip, own_public_key, formatted_Time, expiration_time);
                
                    deserialized_rep.receiver_cert = forwarder_certificate;
                    // Forwarding_REP_format をシリアライズ
                    serialize_forwarding_rep(deserialized_rep, send_buf);
                    //REPならユニキャスト転送する, next_ipは一つ前の端末のIPアドレスで設定する必要がある
                    unicast_send_process(send_buf, next_ip);
                } else if(static_cast<int>(packet_type) == 3){
                    //forwarding RDPの処理を行っていく。
                    // 署名付きメッセージを分割
                    std::string signed_message = std::string(recv_buf.begin(), recv_buf.end());
                    auto [message, signature, receiver_cert] = split_sign_message(signed_message);
                    std::cout << "Message: " << message << std::endl;
                    std::cout << "Signature: " << signature.size() << " bytes" << std::endl;
                    std::cout << "Receiver Certificate: " << receiver_cert << std::endl;

                    // 署名の検証
                    if (!verifySignature(public_key, message, signature)) {
                        std::cerr << "Signature verification failed!" << std::endl;
                        continue;
                    }
                    std::cout << "Signature verification succeeded!" << std::endl;

                } else {
                    std::cerr << "Unknown packet type" << std::endl;
                }    
        } catch (const std::exception& e) {
            std::cerr << "Error during deserialization: " << e.what() << std::endl;
        }
    }


    return 0;
}

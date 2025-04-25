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

struct Forwarding_RDP_format {
    std::string type;
    std::string source_ip;
    std::string dest_ip;
    Certificate_Format cert;
    std::uint32_t n;
    std::string t;
    std::vector<unsigned char> signature;
    std::vector<unsigned char> receiver_signature;
    Certificate_Format receiver_cert;
};

struct Forwarding_REP_format {
    std::string type;
    //std::string source_ip;
    std::string dest_ip;
    Certificate_Format cert;
    std::uint32_t n;
    std::string t;
    std::vector<unsigned char> signature;
    std::vector<unsigned char> receiver_signature;
    Certificate_Format receiver_cert;
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

// シリアライズ処理
void serialize_data_RDP_format(const RDP_format& test_rdp, std::vector<uint8_t>& buf) {
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
void serialize_data(const Forwarding_RDP_format& forwarding_rdp, std::vector<uint8_t>& buf) {
    auto serialize_string = [&buf](const std::string& str) {
        std::uint32_t len = str.size();
        buf.push_back((len >> 0) & 0xFF);
        buf.push_back((len >> 8) & 0xFF);
        buf.push_back((len >> 16) & 0xFF);
        buf.push_back((len >> 24) & 0xFF);
        buf.insert(buf.end(), str.begin(), str.end());
    };

    serialize_string(forwarding_rdp.type);
    serialize_string(forwarding_rdp.source_ip);
    serialize_string(forwarding_rdp.dest_ip);

    // Certificate_Format のシリアライズ
    serialize_string(forwarding_rdp.cert.own_ip);
    serialize_string(forwarding_rdp.cert.own_public_key);
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

// Forwarding_REP_format のシリアライズ処理
void REP_serialize_data(const Forwarding_REP_format& forwarding_rep, std::vector<uint8_t>& buf) {
    auto serialize_string = [&buf](const std::string& str) {
        std::uint32_t len = str.size();
        buf.push_back((len >> 0) & 0xFF);
        buf.push_back((len >> 8) & 0xFF);
        buf.push_back((len >> 16) & 0xFF);
        buf.push_back((len >> 24) & 0xFF);
        buf.insert(buf.end(), str.begin(), str.end());
    };

    serialize_string(forwarding_rep.type);
    serialize_string(forwarding_rep.dest_ip);

    // Certificate_Format のシリアライズ
    serialize_string(forwarding_rep.cert.own_ip);
    serialize_string(forwarding_rep.cert.own_public_key);
    serialize_string(forwarding_rep.cert.t);
    serialize_string(forwarding_rep.cert.expires);

    // nを4バイトにシリアライズ
    for (int i = 0; i < 4; i++) {
        buf.push_back((forwarding_rep.n >> (8 * i)) & 0xFF);
    }

    serialize_string(forwarding_rep.t);

    // 署名のシリアライズ
    std::uint32_t sig_len = forwarding_rep.signature.size();
    buf.push_back((sig_len >> 0) & 0xFF);
    buf.push_back((sig_len >> 8) & 0xFF);
    buf.push_back((sig_len >> 16) & 0xFF);
    buf.push_back((sig_len >> 24) & 0xFF);
    buf.insert(buf.end(), forwarding_rep.signature.begin(), forwarding_rep.signature.end());

    // receiver_signature のシリアライズ
    std::uint32_t receiver_sig_len = forwarding_rep.receiver_signature.size();
    buf.push_back((receiver_sig_len >> 0) & 0xFF);
    buf.push_back((receiver_sig_len >> 8) & 0xFF);
    buf.push_back((receiver_sig_len >> 16) & 0xFF);
    buf.push_back((receiver_sig_len >> 24) & 0xFF);
    buf.insert(buf.end(), forwarding_rep.receiver_signature.begin(), forwarding_rep.receiver_signature.end());

    // receiver_cert のシリアライズ
    serialize_string(forwarding_rep.receiver_cert.own_ip);
    serialize_string(forwarding_rep.receiver_cert.own_public_key);
    serialize_string(forwarding_rep.receiver_cert.t);
    serialize_string(forwarding_rep.receiver_cert.expires);

    std::cout << "Serialized REP data size: " << buf.size() << " bytes" << std::endl;
    std::cout << "Serialized REP data (hex): ";
    for (unsigned char c : buf) {
        std::cout << std::hex << (int)c << " ";
    }
    std::cout << std::dec << std::endl;
}

std::vector<unsigned char> deserialize_vector(const std::vector<uint8_t>& buf, std::size_t& offset) {
    std::cout << "buf.size(): " << buf.size() << std::endl;
    std::cout << "offset: " << offset << std::endl;
    
    // 1. offset + 4 のチェック (オーバーフロー防止)
    if (offset + 4 > buf.size()) {  // 修正
        std::cout << "Buffer underflow while reading vector length" << std::endl;
        throw std::runtime_error("Buffer underflow while reading vector length");
    }

    // 2. リトルエンディアンで長さを取得
    std::uint32_t len = 0;
    len |= static_cast<std::uint32_t>(buf[offset + 0]) << 0;
    len |= static_cast<std::uint32_t>(buf[offset + 1]) << 8;
    len |= static_cast<std::uint32_t>(buf[offset + 2]) << 16;
    len |= static_cast<std::uint32_t>(buf[offset + 3]) << 24;
    offset += 4;

    std::cout << "Vector length: " << len << std::endl;

    // 3. offset + len のチェック (オーバーフロー防止)
    if (offset + len > buf.size()) {  // 修正
        std::cout << "Buffer underflow while reading vector data" << std::endl;
        throw std::runtime_error("Buffer underflow while reading vector data");
    }

    // 4. vector にデータを格納
    std::vector<unsigned char> result(buf.begin() + offset, buf.begin() + offset + len);
    offset += len;
    
    return result;
}

std::int32_t deserialize_int32(const std::vector<uint8_t>& buf, std::size_t& offset) {
    if (offset + 4 > buf.size()) {
        std::cerr << "Buffer underflow while reading int32" << std::endl;
        throw std::runtime_error("Buffer underflow while reading int32");
    }

    std::int32_t value = 0;
    value |= static_cast<std::int32_t>(buf[offset + 0]) << 0;
    value |= static_cast<std::int32_t>(buf[offset + 1]) << 8;
    value |= static_cast<std::int32_t>(buf[offset + 2]) << 16;
    value |= static_cast<std::int32_t>(buf[offset + 3]) << 24;  // ここが重要！
    
    offset += 4;
    return value;
}

// デシリアライズ処理
RDP_format deserialize_data(const std::vector<uint8_t>& buf) {
    RDP_format deserialized_rdp;
    std::size_t offset = 0;

    auto deserialize_string = [&buf, &offset]() {
        if (offset + 4 > buf.size()) throw std::runtime_error("Buffer underflow while reading string length");
        std::uint32_t len = 0;
        len |= buf[offset + 0] << 0;
        len |= buf[offset + 1] << 8;
        len |= buf[offset + 2] << 16;
        len |= buf[offset + 3] << 24;
        offset += 4;

        // 異常な長さを検出
        if (len > buf.size()) throw std::runtime_error("Invalid string length detected");

        if (offset + len > buf.size()) throw std::runtime_error("Buffer underflow while reading string data");
        std::string result(buf.begin() + offset, buf.begin() + offset + len);
        offset += len;
        return result;
    };

    deserialized_rdp.type = deserialize_string();
    deserialized_rdp.source_ip = deserialize_string();
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

    // 署名のデシリアライズ
    if (offset + 4 > buf.size()) throw std::runtime_error("Buffer underflow while reading signature length");
    std::uint32_t sig_len = 0;
    sig_len |= buf[offset + 0] << 0;
    sig_len |= buf[offset + 1] << 8;
    sig_len |= buf[offset + 2] << 16;
    sig_len |= buf[offset + 3] << 24;
    offset += 4;
    if (offset + sig_len > buf.size()) throw std::runtime_error("Buffer underflow while reading signature data");
    deserialized_rdp.signature = std::vector<unsigned char>(buf.begin() + offset, buf.begin() + offset + sig_len);
    offset += sig_len;

    return deserialized_rdp;
}

Forwarding_RDP_format deserialize_forwarding_data(const std::vector<uint8_t>& buf) {
    Forwarding_RDP_format deserialized_rdp;
    std::size_t offset = 0;

    auto deserialize_string = [&buf, &offset]() {
        if (offset + 4 > buf.size()) throw std::runtime_error("Buffer underflow while reading string length");
        std::uint32_t len = 0;
        len |= buf[offset + 0] << 0;
        len |= buf[offset + 1] << 8;
        len |= buf[offset + 2] << 16;
        len |= buf[offset + 3] << 24;
        offset += 4;

        // 異常な長さを検出
        if (len > buf.size()) throw std::runtime_error("Invalid string length detected");

        if (offset + len > buf.size()) throw std::runtime_error("Buffer underflow while reading string data");
        std::string result(buf.begin() + offset, buf.begin() + offset + len);
        offset += len;
        return result;
    };

    deserialized_rdp.type = deserialize_string();
    deserialized_rdp.source_ip = deserialize_string();
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

    // 署名のデシリアライズ
    if (offset + 4 > buf.size()) throw std::runtime_error("Buffer underflow while reading signature length");
    std::uint32_t sig_len = 0;
    sig_len |= buf[offset + 0] << 0;
    sig_len |= buf[offset + 1] << 8;
    sig_len |= buf[offset + 2] << 16;
    sig_len |= buf[offset + 3] << 24;
    offset += 4;
    if (offset + sig_len > buf.size()) throw std::runtime_error("Buffer underflow while reading signature data");
    deserialized_rdp.signature = std::vector<unsigned char>(buf.begin() + offset, buf.begin() + offset + sig_len);
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
    deserialized_rdp.receiver_signature = std::vector<unsigned char>(buf.begin() + offset, buf.begin() + offset + receiver_sig_len);
    offset += receiver_sig_len;

    // receiver_cert のデシリアライズ
    deserialized_rdp.receiver_cert.own_ip = deserialize_string();
    deserialized_rdp.receiver_cert.own_public_key = deserialize_string();
    deserialized_rdp.receiver_cert.t = deserialize_string();
    deserialized_rdp.receiver_cert.expires = deserialize_string();

    return deserialized_rdp;
}

std::string certificate_to_string(const Certificate_Format& cert) {
    std::ostringstream certStream;
    certStream << cert.own_ip << "|\n"
               << cert.own_public_key << "|\n"
               << cert.t << "|\n"
               << cert.expires << "|\n";
    return certStream.str();
}

// 署名付きメッセージをデシリアライズする関数
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
    messageStream << deserialized_rdp.type << "|\n"
                  << deserialized_rdp.dest_ip << "|\n" 
                  << certificate_to_string(deserialized_rdp.cert) << "|\n"
                  << deserialized_rdp.n << "|\n"
                  << deserialized_rdp.t << "|\n";

    return messageStream.str();
}


// メッセージを構築する関数
std::string construct_message_with_key(const Forwarding_RDP_format& deserialized_rdp, const std::string& public_key_str) {
    std::ostringstream messageStream;
    messageStream << deserialized_rdp.type << "|\n"
                  << deserialized_rdp.dest_ip << "|\n" 
                  << certificate_to_string(deserialized_rdp.cert) << "|\n"<< deserialized_rdp.n << "|\n"
                  << deserialized_rdp.t << "|\n"
                  << public_key_str  // 公開鍵を追加
                  << "Message-with-public-key-end\n"; 

    //std::cout << messageStream.str() << std::endl;
    
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

RDP_format Makes_RDP(std::string type, std::string source_ip, std::string dest_ip, Certificate_Format cert, std::uint32_t n, std::string t, std::vector<unsigned char> signature) {
    RDP_format rdp;
    rdp.type = type;
    rdp.source_ip = source_ip;
    rdp.dest_ip = dest_ip;
    rdp.cert = cert;
    rdp.n = n;
    rdp.t = t;
    rdp.signature = signature;
    return rdp;
}

Forwarding_REP_format Makes_REP(std::string type, std::string dest_ip, Certificate_Format cert, std::uint32_t n, std::string t, std::vector<unsigned char> signature, std::vector<unsigned char> receiver_signature, Certificate_Format receiver_cert) {
    Forwarding_REP_format rep;
    rep.type = type;
    rep.dest_ip = dest_ip;
    rep.cert = cert;
    rep.n = n;
    rep.t = t;
    rep.signature = signature;
    rep.receiver_signature = receiver_signature;
    rep.receiver_cert = receiver_cert;

    return rep;
}


Certificate_Format Makes_Certificate(std::string own_ip, std::string own_public_key, std::string t, std::string expires) {
    Certificate_Format Certificate;
    Certificate.own_ip = own_ip;
    Certificate.own_public_key = own_public_key;
    Certificate.t = t;
    Certificate.expires = expires;
    return Certificate;
}

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

std::tuple<std::string, std::string, std::uint32_t> get_time_nonce_address(std::string t, std::string sender_ip, std::uint32_t n) {
    std::string formattedTime = t;
    std::uint32_t nonce = n;
    std::string ip_address = sender_ip;

    return {formattedTime, ip_address, nonce};
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

int main() {
    // ブロードキャスト受信の設定
    int sock;
    struct sockaddr_in addr;
    char buf[2048];
    std::string own_ip_address = get_own_ip();
    std::string dest_ip = "";
    std::string next_ip = "";
    std::vector<uint8_t> send_buf;

    // タイムスタンプ,ノンスと受信ノードのIPアドレスを管理するリスト
    std::list<std::tuple<std::string, std::string, std::uint32_t>> received_messages;

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
        
        std::vector<uint8_t> recv_buf = receving_process(sock);

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
            // 送信元かどうかを確認
            std::string sender_ip = inet_ntoa(sender_addr.sin_addr);
            Forwarding_RDP_format deserialized_rdp = deserialize_forwarding_data(recv_buf);

            std::cout << "deserialize_rdp.type:" << deserialized_rdp.type << std::endl;
            
            //Forwarding RDP formatからtime stamp:tとnonce:nをタプルで取得
            std::tuple<std::string, std::string, std::uint32_t> time_and_nonce_and_ipaddress = get_time_nonce_address(deserialized_rdp.t, sender_ip, deserialized_rdp.n);
            std::cout << "Receving time_stamp:" << std::get<0>(time_and_nonce_and_ipaddress) << std::endl;
            std::cout << "Receving IP_address:"<< std::get<1>(time_and_nonce_and_ipaddress) << std::endl;
            std::cout << "Receving nonce:"<< std::get<2>(time_and_nonce_and_ipaddress) << std::endl;
            
            // 受信したメッセージのtime stamp:tとnonce:nが既に受信したものかどうかを確認する
            if(deserialized_rdp.type == "RDP") {
                
                auto it = std::find_if(received_messages.begin(), received_messages.end(),
                [&time_and_nonce_and_ipaddress](const std::tuple<std::string, std::string, std::uint32_t>& element) {
                    return  std::get<0>(element) == std::get<0>(time_and_nonce_and_ipaddress) &&
                            std::get<1>(element) == std::get<1>(time_and_nonce_and_ipaddress) &&
                            std::get<2>(element) == std::get<2>(time_and_nonce_and_ipaddress);
                });
                if (it != received_messages.end()) {
                    std::cout << "Received message is already received." << std::endl;
                    continue; // 既に受信したメッセージを破棄
                } else {
                    std::cout << "Received message is not received yet." << std::endl;
                    // 受信したtime stampとnonceと送信元IPを保存
                    received_messages.push_back(time_and_nonce_and_ipaddress);
                }

                // 署名の検証
                std::string message = construct_message(deserialized_rdp);
                if (!verifySignature(public_key, message, deserialized_rdp.signature)) {
                    std::cerr << "Signature verification failed!" << std::endl;
                    return 1;
                }
                std::cout << "Signature verification succeeded!" << std::endl;
            }
            // 宛先確認
            if (deserialized_rdp.dest_ip == own_ip_address) {
                std::cout << "This message is for me." << std::endl;
                //REPの作成
                //自身の証明書を作成
                Certificate_Format own_certificate = Makes_Certificate(get_own_ip(), get_PublicKey_As_String(public_key), get_time(), calculateExpirationTime(24, get_time()));
                //署名サイズを出力
                std::cout << "Signature size:" << deserialized_rdp.signature.size() << std::endl;   

                std::cout << "-------------------------------------Destination sends REP-------------------------------------" << std::endl;
                Forwarding_REP_format rep = Makes_REP("REP", deserialized_rdp.source_ip, own_certificate, deserialized_rdp.n, deserialized_rdp.t, deserialized_rdp.signature , {}, {});
                std::cout << "rep.type: "<< rep.type << std::endl;
                std::cout << "rep.dest_ip:" << rep.dest_ip << std::endl;
                std::cout << "rep.cert.own_ip" << rep.cert.own_ip << std::endl;
                std::cout << "rep.cert.own_public_key:"<< rep.cert.own_public_key << std::endl;
                std::cout << "rep.cert.t:"<< rep.cert.t << std::endl;
                std::cout << "rep.cert.expires" <<rep.cert.expires << std::endl;
                std::cout <<"rep.n" << rep.n << std::endl;
                std::cout << "rep.signature.size:"<< rep.signature.size() << std::endl;
                std::cout << "recp.receiver_singature:"<< rep.receiver_signature.size() << std::endl;
                std::cout << "rep.receiver_cert.own_ip:"<< rep.receiver_cert.own_ip << std::endl;
                std::cout << "rep.receiver_cert.own_public_key:"<< rep.receiver_cert.own_public_key << std::endl;
                std::cout << "rep.receiver_cert.t:"<< rep.receiver_cert.t << std::endl;
                std::cout << "rep.receiver_cert.expires" << rep.receiver_cert.expires << std::endl;

                
                // REPをシリアライズ
                std::vector<uint8_t> rep_buf;
                REP_serialize_data(rep, rep_buf);

                // REPを送信(宛先は一つ前の端末に向けて送信)
                struct sockaddr_in rep_addr;
                rep_addr.sin_family = AF_INET;
                rep_addr.sin_port = htons(12345);
                std::cout << "Send REP to : " << sender_ip.c_str() << std::endl;
                rep_addr.sin_addr.s_addr = inet_addr(sender_ip.c_str());

                int rep_sock = socket(AF_INET, SOCK_DGRAM, 0);
                if (rep_sock < 0) {
                    std::cerr << "Failed to create socket for REP" << std::endl;
                }

                if (sendto(rep_sock, rep_buf.data(), rep_buf.size(), 0, reinterpret_cast<struct sockaddr*>(&rep_addr), sizeof(rep_addr)) < 0) {
                    perror("sendto failed for REP");
                } else {
                    std::cout << "---------------------------REP sent successfully to " << deserialized_rdp.source_ip <<"------------------------------" << std::endl;
                }

                close(rep_sock);

            } else {
                std::cout << "This message is not for me. Forwarding..." << std::endl;

                // 受信したメッセージの中に転送端末の署名および証明書がないかを確認
                if (!deserialized_rdp.receiver_signature.empty() && !deserialized_rdp.receiver_cert.own_ip.empty()) {
                    std::cout << "Forwarder signature and certificate found. Removing them..." << std::endl;
                    // 転送端末の署名および証明書を取り除く
                    /*
                    std::cout << "Before removal:" << std::endl;
                    std::cout << "receiver_signature (hex):" << std::endl;
                    for (unsigned char c : deserialized_rdp.receiver_signature) {
                        std::cout << std::hex << (int)c << " ";
                    }
                    std::cout << std::dec << std::endl;
                    */
                    std::cout << "receiver_cert.own_ip:" << deserialized_rdp.receiver_cert.own_ip << std::endl;

                    // 転送端末の署名および証明書を取り除く
                    deserialized_rdp.receiver_signature.clear();
                    deserialized_rdp.receiver_cert = Certificate_Format();

                    // 転送端末の署名および証明書を取り除いた後のデバッグ出力
                    /*
                    std::cout << "After removal:" << std::endl;
                    std::cout << "receiver_signature (hex):" << std::endl;
                    for (unsigned char c : deserialized_rdp.receiver_signature) {
                        std::cout << std::hex << (int)c << " ";
                    }
                    std::cout << std::dec << std::endl;
                    */
                    //std::cout << "receiver_cert.own_ip:" << deserialized_rdp.receiver_cert.own_ip << std::endl;
                } else {
                    std::cout << "Forwarder signature and certificate not found." << std::endl;
                }

                //RDPか,REPで場合分け
                if (deserialized_rdp.type == "RDP") {
                    // 自身の署名と証明書を追加して送信
                    std::cout << "------------------------------------- Forwarding RDP-------------------------------------" << std::endl;
                    std::string signed_message = construct_message_with_key(deserialized_rdp, get_PublicKey_As_String(public_key));
                    std::vector<unsigned char> signature = sign_message(private_key, signed_message);
                    if (signature.empty()) {
                        std::cerr << "Failed to sign the message" << std::endl;
                        return 1;
                    }
                    deserialized_rdp.receiver_signature = signature;
                
                    // 転送端末の証明書を作成
                    Certificate_Format forwarder_certificate = Makes_Certificate(get_own_ip(), get_PublicKey_As_String(public_key), get_time(), calculateExpirationTime(24, get_time()));
                
                    deserialized_rdp.receiver_cert = forwarder_certificate;
                    // Forwarding_RDP_format をシリアライズ
                    serialize_data(deserialized_rdp, send_buf);

                    //RDPならブロードキャスト転送する。
                    broadcast_send_process(send_buf);
                
                } else if (deserialized_rdp.type == "REP") {
                    // 一つ前の端末に向けて送信する.
                    //REPの作成
                    std::cout << "-------------------------------------Forwarding REP-------------------------------------" << std::endl;
                    //time stampとnonceから対応するIPアドレスを取得
                    auto it = std::find_if(received_messages.begin(), received_messages.end(),
                        [&deserialized_rdp](const std::tuple<std::string, std::string, std::uint32_t>& element) {
                            return std::get<0>(element) == deserialized_rdp.t &&
                                   std::get<2>(element) == deserialized_rdp.n;
                        });

                    if (it != received_messages.end()) {
                        next_ip = std::get<1>(*it);
                        std::cout << "Next IP address found: " << next_ip << std::endl;
                    } else {
                        std::cerr << "Next IP address not found for the given timestamp and nonce" << std::endl;
                        continue;
                    }

                    // 受信したメッセージの中に転送端末の署名および証明書がないかを確認
                if (!deserialized_rdp.receiver_signature.empty() && !deserialized_rdp.receiver_cert.own_ip.empty()) {
                    std::cout << "Forwarder signature and certificate found. Removing them..." << std::endl;
                    std::cout << "receiver_cert.own_ip:" << deserialized_rdp.receiver_cert.own_ip << std::endl;

                    // 転送端末の署名および証明書を取り除く
                    deserialized_rdp.receiver_signature.clear();
                    deserialized_rdp.receiver_cert = Certificate_Format();
                }

                    std::string signed_message = construct_message_with_key(deserialized_rdp, get_PublicKey_As_String(public_key));
                    std::vector<unsigned char> signature = sign_message(private_key, signed_message);
                    if (signature.empty()) {
                        std::cerr << "Failed to sign the message" << std::endl;
                        return 1;
                    }
                    deserialized_rdp.receiver_signature = signature;
                
                    // 転送端末の証明書を作成
                    Certificate_Format forwarder_certificate = Makes_Certificate(get_own_ip(), get_PublicKey_As_String(public_key), get_time(), calculateExpirationTime(24, get_time()));
                
                    deserialized_rdp.receiver_cert = forwarder_certificate;
                    // Forwarding_RDP_format をシリアライズ
                    serialize_data(deserialized_rdp, send_buf);
                    //REPならユニキャスト転送する, next_ipは一つ前の端末のIPアドレスで設定する必要がある
                    unicast_send_process(send_buf, next_ip);
                }  
            }
        } catch (const std::exception& e) {
            std::cerr << "Error during deserialization: " << e.what() << std::endl;
        }
    }


    return 0;
}
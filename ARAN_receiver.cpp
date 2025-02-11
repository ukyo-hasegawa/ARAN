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
    std::cout << "Serialized data (hex): ";
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
std::string construct_message(const RDP_format& deserialized_rdp) {
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

RDP_format Makes_REP(std::string type, std::string source_ip, std::string dest_ip, Certificate_Format cert, std::uint32_t n, std::string t, std::vector<unsigned char> signature) {
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


Certificate_Format Makes_Certificate(std::string own_ip, std::string own_public_key, std::string t, std::string expires) {
    Certificate_Format Certificate;
    Certificate.own_ip = own_ip;
    Certificate.own_public_key = own_public_key;
    Certificate.t = t;
    Certificate.expires = expires;
    return Certificate;
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
    RDP_format rdp;
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

    std::cout << "Received data size: " << recv_buf.size() << " bytes" << std::endl;

    //デシリアライズ処理
    try {
        std::cout << "-------------------------------------Deserialization check-------------------------------------" << std::endl;
        RDP_format deserialized_rdp = deserialize_data(recv_buf);
        std::cout << "deserialize_rdp.type:" << deserialized_rdp.type << std::endl;
        std::cout << "deserialize_rdp.source_ip:" << deserialized_rdp.source_ip << std::endl;
        std::cout << "deserialize_rdp.dest_ip:" << deserialized_rdp.dest_ip << std::endl;
        std::cout << "deserialize_rdp.cert.own_ip:" << deserialized_rdp.cert.own_ip << std::endl;
        std::cout << "deserialize_rdp.cert.own_public_key:" << deserialized_rdp.cert.own_public_key << std::endl;
        std::cout << "deserialize_rdp.cert.t:" << deserialized_rdp.cert.t << std::endl;
        std::cout << "deserialize_rdp.cert.expires:" << deserialized_rdp.cert.expires << std::endl;
        std::cout << "deserialize_rdp.n:" << deserialized_rdp.n << std::endl;
        std::cout << "deserialize_rdp.t:" << deserialized_rdp.t << std::endl;
        std::cout << "deserialize_rdp.signature (hex):" << std::endl;
        for (unsigned char c : deserialized_rdp.signature) {
            std::cout << std::hex << (int)c << " ";
        }
        std::cout << std::dec << std::endl;
        std::cout << "-------------------------------------Deserialization check end-------------------------------------" << std::endl;
        

        std::string message = construct_message(deserialized_rdp);
        std::cout << "-------------------------------------Message-------------------------------------: " << std::endl;
        std::cout << message << std::endl;
        std::cout << "-------------------------------------Message-End-------------------------------------: " << std::endl;

        bool isValid = verifySignature(public_key, message, deserialized_rdp.signature);
        std::cout << "-------------------------------------Signature verification-------------------------------------: " << std::endl;
        std::cout << (isValid ? "success" : "false") << std::endl;

        std::cout << "-------------------------------------Signature-------------------------------------: " << std::endl;
        for (unsigned char c : deserialized_rdp.signature) {
            std::cout << std::hex << (int)c << " ";
        }
        std::cout << std::dec << std::endl;
        std::cout << "-------------------------------------Signature end-------------------------------------: " << std::endl;
        
        // 宛先IP を取得
        dest_ip = deserialized_rdp.dest_ip;
        std::cout << "Destination IP (deserialized_rdp.dest_ip): " << dest_ip << std::endl;

        // 宛先が自分自身か確認
        if (isValid) {
            if (dest_ip == ip_address) {
                std::cout << "This message is for this device!" << std::endl;
                //REP処理、信頼できるサーバによるメッセージの作成
                std::string rep_message = get_own_ip() + "|" + deserialized_rdp.t + "|" + deserialized_rdp.cert.expires;
                //メッセージに対する署名(証明書)の作成
                std::vector<unsigned char> rep_message_cert = signMessage(load_private_key("private_key.pem"), rep_message);
                //宛先が最初に生成するREPメッセージ
                RDP_format rep = Makes_REP("REP", get_own_ip(), deserialized_rdp.source_ip, deserialized_rdp.cert, deserialized_rdp.n, get_time(), signMessage(load_private_key("private_key.pem"), rep_message));
            } else {
                std::cout << "This message is for another device." << std::endl;
            }
        } else {
            std::cout << "isValid is false" << std::endl;
        }

        //送信元からのRDP処理→署名を全体に対して付与　後から関数化
        //転送端末の秘密鍵による署名の生成
        //送信元端末の公開鍵を含むmessageの生成
        //std::cout << "------------------------------check point 2------------------------------" << std::endl;
        std::string message_with_key = construct_message_with_key(deserialized_rdp, get_PublicKey_As_String(public_key));
        std::cout << "---------------------------Message with key--------------------------- "<< std::endl;
        std::cout << message_with_key << std::endl;
        std::cout << "---------------------------Message with key end--------------------------- "<< std::endl;
        //署名処理(受信端末による署名)
        std::vector<unsigned char> signature = signMessage(load_private_key("private_key.pem"), message_with_key);
        if (signature.empty()) return -1;

        // 署名を16進数文字列に変換してメッセージに追加
        std::ostringstream signature_hex_stream;
        for (unsigned char c : signature) {
            signature_hex_stream << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        }
        std::string signature_hex = signature_hex_stream.str();
        std::cout << "Signature hex length: " << signature_hex.length() << std::endl; // 追加
        std::string message_with_key_and_signature = message_with_key + signature_hex;

        // 署名を追加したメッセージを出力
        std::cout << "---------------------------Message with key and signature--------------------------- "<< std::endl;
        std::cout << message_with_key_and_signature << std::endl;
        std::cout << "---------------------------Message with key and signature end--------------------------- "<< std::endl;
        
        //受信端末の証明書の作成
        Certificate_Format receiver_certificate = Makes_Certificate(get_own_ip(), get_PublicKey_As_String(public_key), get_time(), calculateExpirationTime(24, get_time()));

        //受信した端末の証明書を作成して追加
        std::string receiver_certificate_string = certificate_to_string(receiver_certificate);
        std::string message_with_key_and_signature_and_certificate = message_with_key_and_signature + "receiver-signature-and-certificate" + receiver_certificate_string; ;

        // 署名を追加したメッセージを出力
        std::cout << "---------------------------Message with key and signature and certificate--------------------------- "<< std::endl;
        std::cout << message_with_key_and_signature_and_certificate << std::endl;
        std::cout << "---------------------------Message with key and signature and certificate end--------------------------- "<< std::endl;
        
        //転送端末からのRDPメッセージ受信時のRDPの作成
        //署名と共に受信したメッセージを分割
        auto [extracted_message, extracted_signature, extracted_certificate] = split_sign_message(message_with_key_and_signature_and_certificate);

        std::cout << "---------------------------Message without signature--------------------------------"<< std::endl;
        std::cout << extracted_message << std::endl;

        
        //rdp = Makes_RDP(deserialized_rdp.type, get_own_ip(), deserialized_rdp.dest_ip, cert_info, deserialized_rdp.n, deserialized_rdp.t, deserialized_rdp.cert.expires, signature);
        //serialize_data(rdp,recv_buf);

        //宛先でない場合、転送する。
        send_process(recv_buf);

    } catch (const std::exception& e) {
        std::cerr << "Error during deserialization: " << e.what() << std::endl;
    }

    return 0;
}
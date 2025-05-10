#include <string>
#include <array>
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
//#include "RSA/RSA.h"

enum class MessageType : uint8_t {
    RDP = 0x01,
    REP = 0x02
};

struct Certificate_Format {
    char own_ip[16]; //16byteのIPアドレス
    char own_public_key[256]; //256byteの公開鍵 ここはunsigned charにするか要検討
    char time_stamp[20]; //20byteのタイムスタンプ
    char expires[20]; //20byteの有効期限
    std::array<unsigned char,256> signature; //256byteの署名
};

struct RDP_format {
    MessageType type; //1バイト
    char dest_ip[16];
    Certificate_Format cert;
    std::uint32_t nonce; //4バイト
    char time_stamp[20];
    std::array<unsigned char, 256> signature;
};

struct Forwarding_RDP_format {
    RDP_format rdp;
    std::array<unsigned char,256> receiver_signature;
    Certificate_Format receiver_cert;
};

struct Forwarding_REP_format {
    MessageType type; //1バイト
    char dest_ip[16]; //16バイト
    Certificate_Format cert;
    std::uint32_t nonce; //4バイト
    char time_stamp[20];
    std::array<unsigned char, 256> signature;
    std::array<unsigned char, 256> receiver_signature;
    Certificate_Format receiver_cert;
};

Certificate_Format Makes_Certificate(const char* own_ip,const char* own_public_key,const char* t,const char* expires, std::array<unsigned char,256> signature) { //own_public_keyはunsigned charにするか要検討
    Certificate_Format Certificate = {};
    std::strncpy(Certificate.own_ip, own_ip, sizeof(Certificate.own_ip) - 1);
    Certificate.own_ip[sizeof(Certificate.own_ip) - 1] = '\0'; // Null-terminate

    std::strncpy(Certificate.own_public_key, own_public_key, sizeof(Certificate.own_public_key) - 1);
    Certificate.own_public_key[sizeof(Certificate.own_public_key) - 1] = '\0'; // Null-terminate

    std::strncpy(Certificate.time_stamp, t, sizeof(Certificate.time_stamp) - 1);
    Certificate.time_stamp[sizeof(Certificate.time_stamp) - 1] = '\0'; // Null-terminate

    std::strncpy(Certificate.expires, expires, sizeof(Certificate.expires) - 1);
    Certificate.expires[sizeof(Certificate.expires) - 1] = '\0'; // Null-terminate

    Certificate.signature = signature;

    return Certificate;
}

RDP_format Makes_RDP(MessageType type /*const char* source_ip*/, const char* dest_ip, Certificate_Format cert, std::uint32_t n, const char* t, std::array<unsigned char,256> signature) {
    RDP_format rdp;
    // type の設定
    rdp.type = type;

    // dest_ip の設定
    std::strncpy(rdp.dest_ip, dest_ip, sizeof(rdp.dest_ip) - 1);
    rdp.dest_ip[sizeof(rdp.dest_ip) - 1] = '\0'; // ヌル終端を保証

    // その他のフィールドの設定
    rdp.cert = cert;
    rdp.nonce = n;
    
    // time_stamp の設定
    std::strncpy(rdp.time_stamp, t, sizeof(rdp.time_stamp) - 1);
    rdp.time_stamp[sizeof(rdp.time_stamp) - 1] = '\0'; // ヌル終端を保証

    // signature の設定
    rdp.signature = signature;

    return rdp;
}

// 受信したRDP_formatを確認する関数
void check_RDP(const RDP_format& rdp) {
    //各要素の確認
    std::cout << "---------------------------RDP---------------------------" << std::endl;
    std::cout << "rdp.type: " << static_cast<int>(rdp.type) << std::endl;
    std::cout << "rdp.dest_ip: " << rdp.dest_ip << std::endl;

    std::cout << "rdp.cert.own_ip: " << rdp.cert.own_ip << std::endl;
    std::cout << "rdp.cert.own_public_key: " << rdp.cert.own_public_key << std::endl;
    std::cout << "rdp.cert.time_stamp: " << rdp.cert.time_stamp << std::endl;
    std::cout << "rdp.cert.expires: " << rdp.cert.expires << std::endl;
    std::cout << "rdp.cert.signature:" << std::endl;
    for(size_t i = 0; i<rdp.cert.signature.size(); i++) {
        std::cout << std::hex << static_cast<int>(rdp.cert.signature[i]) << " ";
    } 
    std::cout << std::dec << std::endl; // 10進数に戻す

    std::cout << "rdp.nonce: " << rdp.nonce << std::endl;
    std::cout << "rdp.time_stamp: " << rdp.time_stamp << std::endl;
    std::cout << "rdp.signature" << std::endl;
    for (size_t i =0; i< rdp.signature.size(); i++){
        std::cout << std::hex << static_cast<int>(rdp.signature[i]) << " ";
    }
    std::cout << std::dec<<std::endl; // 10進数に戻す
    std::cout << "---------------------------RDP---------------------------" << std::endl;
}

void Check_certificate(const Certificate_Format& cert) {
    // ここで証明書の中身の確認
    std::cout << "---------------------------Check_certificate---------------------------" << std::endl;
    std::cout << "Certificate.own_ip: " << cert.own_ip << std::endl;
    std::cout << "Certificate.own_public_key: " << cert.own_public_key << std::endl;
    std::cout << "Certificate.time_stamp: " << cert.time_stamp << std::endl;
    std::cout << "Certificate.expires: " << cert.expires << std::endl;
    std::cout << "rdp.cert.signature:" << std::endl;
    for(size_t i = 0; i<cert.signature.size(); i++) {
        std::cout << std::hex << static_cast<int>(cert.signature[i]) << " ";
    } 
    std::cout << std::dec << std::endl; // 10進数に戻す

    std::cout << "---------------------------Check_certificate---------------------------" << std::endl;
}

Forwarding_RDP_format Forwarding_RDP_makes(RDP_format RDP, std::array<unsigned char,256> receiver_signature, Certificate_Format receiver_cert) {
    Forwarding_RDP_format rdp;
    rdp.rdp = RDP;
    rdp.receiver_cert = receiver_cert;
    rdp.receiver_signature = receiver_signature;
    return rdp;
}
//シリアライズ、bufを動的に確保するバージョン。こちらも検討
std::vector<uint8_t> serialize(const RDP_format rdp) {
    size_t total_size = sizeof(uint8_t) + // type
        sizeof(rdp.dest_ip) +
        sizeof(rdp.cert.own_ip) +
        sizeof(rdp.cert.own_public_key) +
        sizeof(rdp.cert.time_stamp) +
        sizeof(rdp.cert.expires) +
        sizeof(rdp.cert.signature) + 
        sizeof(rdp.nonce) +
        sizeof(rdp.time_stamp) +
        rdp.signature.size();

    std::vector<uint8_t> buf(total_size);  // 必要なサイズで確保
    size_t offset = 0;

    buf[offset] = static_cast<uint8_t>(rdp.type);
    offset += sizeof(rdp.type);
    
    std::memcpy(buf.data() + offset, rdp.dest_ip, sizeof(rdp.dest_ip));
    offset += sizeof(rdp.dest_ip);
    
    std::memcpy(buf.data() + offset, rdp.cert.own_ip, sizeof(rdp.cert.own_ip));
    offset += sizeof(rdp.cert.own_ip);
    
    std::memcpy(buf.data() + offset, rdp.cert.own_public_key, sizeof(rdp.cert.own_public_key));
    offset += sizeof(rdp.cert.own_public_key);
    
    std::memcpy(buf.data() + offset, rdp.cert.time_stamp, sizeof(rdp.cert.time_stamp));
    offset += sizeof(rdp.cert.time_stamp);
    
    std::memcpy(buf.data() + offset, rdp.cert.expires, sizeof(rdp.cert.expires));
    offset += sizeof(rdp.cert.expires);

    std::memcpy(buf.data() + offset, rdp.cert.signature.data(), rdp.cert.signature.size());
    offset += sizeof(rdp.cert.signature);
    
    std::memcpy(buf.data() + offset, &rdp.nonce, sizeof(rdp.nonce));
    offset += sizeof(rdp.nonce);
    
    std::memcpy(buf.data() + offset, rdp.time_stamp, sizeof(rdp.time_stamp));
    offset += sizeof(rdp.time_stamp);

    std::memcpy(buf.data() + offset, rdp.signature.data(), rdp.signature.size());
    offset += rdp.signature.size();
    
    // 最終チェック（安全のため）
    if (offset != total_size) {
        throw std::runtime_error("Serialize error: size mismatch");
    }

    return buf;
}

// デシリアライズ処理(RDP)
RDP_format deserialize(std::vector<uint8_t> buf) {

    size_t offset = 0;
    RDP_format rdp = {};

    // type
    rdp.type = static_cast<MessageType>(buf[offset]);
    offset += sizeof(uint8_t);

    // Deserialize dest_ip
    std::memcpy(rdp.dest_ip, buf.data() + offset, sizeof(rdp.dest_ip));
    offset += sizeof(rdp.dest_ip);

    // Deserialize cert (own_ip, t, expires,signature)
    std::memcpy(rdp.cert.own_ip, buf.data() + offset, sizeof(rdp.cert.own_ip));
    offset += sizeof(rdp.cert.own_ip);
    
    // Deserialize own_public_key
    std::memcpy(rdp.cert.own_public_key, buf.data() + offset, sizeof(rdp.cert.own_public_key));
    offset += sizeof(rdp.cert.own_public_key);
    
    // Deserialize t
    std::memcpy(rdp.cert.time_stamp, buf.data() + offset, sizeof(rdp.cert.time_stamp));
    offset += sizeof(rdp.cert.time_stamp);


    // Deserialize expires
    std::memcpy(rdp.cert.expires, buf.data() + offset, sizeof(rdp.cert.expires));
    offset += sizeof(rdp.cert.expires);

    //deserialize signature
    std::memcpy(rdp.cert.signature.data(), buf.data(),rdp.cert.signature.size());
    offset += rdp.cert.signature.size();  //ここsizeofでなくていいか要確認
    
    // Deserialize nonce
    std::memcpy(&rdp.nonce, buf.data() + offset, sizeof(rdp.nonce));
    offset += sizeof(rdp.nonce);

    // Deserialize time_stamp
    std::memcpy(rdp.time_stamp, buf.data() + offset, sizeof(rdp.time_stamp));
    offset += sizeof(rdp.time_stamp);

    // Deserialize signature
    std::memcpy(rdp.signature.data(), buf.data() + offset, rdp.signature.size());

    return rdp;
}

// デシリアライズ処理(REP)
void deserialize(const std::vector<uint8_t>& buf, Forwarding_REP_format& rep) {
    size_t offset = 0;

    // Deserialize type
    rep.type = static_cast<MessageType>(buf[offset]);
    offset += sizeof(uint8_t);

    // Deserialize dest_ip
    std::memcpy(rep.dest_ip, buf.data() + offset, sizeof(rep.dest_ip));
    offset += sizeof(rep.dest_ip);

    // Deserialize cert (own_ip, t, expires)
    std::memcpy(rep.cert.own_ip, buf.data() + offset, sizeof(rep.cert.own_ip));
    offset += sizeof(rep.cert.own_ip);
    // Deserialize own_public_key
    std::memcpy(rep.cert.own_public_key, buf.data() + offset, sizeof(rep.cert.own_public_key));
    offset += sizeof(rep.cert.own_public_key);
    // Deserialize t
    std::memcpy(rep.cert.time_stamp, buf.data() + offset, sizeof(rep.cert.time_stamp));
    offset += sizeof(rep.cert.time_stamp);
    // Deserialize expires
    std::memcpy(rep.cert.expires, buf.data() + offset, sizeof(rep.cert.expires));
    offset += sizeof(rep.cert.expires);
    
    // Deserialize nonce
    std::memcpy(&rep.nonce, buf.data() + offset, sizeof(rep.nonce));
    offset += sizeof(rep.nonce);

    // Deserialize time_stamp
    std::memcpy(rep.time_stamp, buf.data() + offset, sizeof(rep.time_stamp));
    offset += sizeof(rep.time_stamp);

    // Deserialize signature
    std::memcpy(rep.signature.data(), buf.data() + offset, rep.signature.size());
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

    return {recv_buf, sender_ip};
}

//hex変換関数
std::string hex_encode(std::array<unsigned char,256> signature) {
    std::ostringstream oss;
    for (size_t i = 0; i < signature.size(); ++i) {
        oss << std::hex << static_cast<int>(signature[i]) << " ";
    }
    return oss.str();
}
//証明書を作成するための署名を生成するためのメッセージを作成
std::string signed_message(const Certificate_Format& cert) {
    std::ostringstream certStream;
    certStream << cert.own_ip << "|\n"
               << cert.own_public_key << "|\n"
               << cert.time_stamp << "|\n"
               << cert.expires << "|\n";

    return certStream.str();
}
//署名含む証明書を文字列にする
std::string certificate_to_string(const Certificate_Format& cert) {
    std::ostringstream certStream;
    certStream << cert.own_ip << "|\n"
               << cert.own_public_key << "|\n"
               << cert.time_stamp << "|\n"
               << cert.expires << "|\n";

    certStream << hex_encode(cert.signature);
    return certStream.str();
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
// 現在時刻の取得
std::string get_time() {
    auto now = std::chrono::system_clock::now();
    std::time_t currentTime = std::chrono::system_clock::to_time_t(now);
    std::tm* localTime = std::localtime(&currentTime);

    // 時刻をフォーマット
    std::ostringstream timeStream;
    timeStream << std::put_time(localTime, "%Y-%m-%d %H:%M:%S");

    // フォーマットされた時刻を std::string として返す
    return timeStream.str();
}

std::string calculateExpirationTime(int durationHours, const std::string formattedTime) {
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
std::string construct_message(const RDP_format& deserialized_rdp) {
    std::ostringstream messageStream;
    messageStream << static_cast<int>(deserialized_rdp.type) << "|\n"
                  << deserialized_rdp.dest_ip << "|\n" 
                  << certificate_to_string(deserialized_rdp.cert) << "|\n"
                  << deserialized_rdp.nonce << "|\n"
                  << deserialized_rdp.time_stamp << "|\n";

    //出来上がったメッセージを出力
    std::cout << "-------------------------Constructed message--------------------------- " << std::endl;
    std::cout << messageStream.str() << std::endl;
    std::cout << "-------------------------Constructed message--------------------------- " << std::endl;


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
//何をしてるのかはわからないが、256バイトの署名(固定)を生成している。
std::array<unsigned char,256> size256_signMessage(EVP_PKEY* private_key, const std::string& message) {
    std::array<unsigned char,256> signature = {0};
    size_t siglen = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, private_key) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestSignInit failed");
    }

    if (EVP_DigestSignUpdate(ctx, message.c_str(), message.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestSignUpdate failed");
    }

    if (EVP_DigestSignFinal(ctx, nullptr, &siglen) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestSignFinal (get length) failed");
    }

    if (siglen != 256) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Signature length is not 256 bytes (actual: " + std::to_string(siglen) + ")");
    }

    if (EVP_DigestSignFinal(ctx, signature.data(), &siglen) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestSignFinal (sign) failed");
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

//乱数生成関数 何をやっているのかはわからないが、32bitの乱数を生成している。
std::uint32_t generateRandom32bit() {
    std::random_device rd;  // 非決定的な乱数
    std::mt19937 gen(rd()); // 32bit メルセンヌツイスター
    std::uniform_int_distribution<std::uint32_t> dist(0, UINT32_MAX);
    return dist(gen);
}

int main() {
    RDP_format test_rdp1 = {}; //テスト用のRDP_format構造体
    Certificate_Format test_cert1 = {}; //テスト用のCertificate_Format構造体

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
    std::string Formatted_Time = get_time();
    
    // 有効期限の取得
    std::string expirationTime = calculateExpirationTime(24, Formatted_Time);

    char own_ip[16] = {};
    std::strncpy(own_ip, get_own_ip().c_str(), sizeof(own_ip) - 1);
    own_ip[sizeof(own_ip) - 1] = '\0'; // null-terminate
    //printf("own_ip: %s\n", own_ip);

    char own_public_key[256] = {};
    std::strncpy(own_public_key, get_PublicKey_As_String(public_key).c_str(), sizeof(own_public_key) - 1);
    own_public_key[sizeof(own_public_key) - 1] = '\0'; // null-terminate
    //printf("own_public_key:%s\n", own_public_key);

    char formatted_Time[20] = {};
    std::strncpy(formatted_Time, Formatted_Time.data(), sizeof(formatted_Time) - 1);
    formatted_Time[sizeof(formatted_Time) - 1] = '\0'; // null-terminate
    //printf("formatted_Time:%s\n", formatted_Time);

    char expiration_time[20] = {};
    std::strncpy(expiration_time, expirationTime.data(), sizeof(expiration_time) - 1);
    expiration_time[sizeof(expiration_time) - 1] = '\0'; // null-terminate
    //printf("expiration_time:%s\n", expiration_time);

    // 送信元の公開鍵を取得して証明書を作成
    test_cert1 = Makes_Certificate(own_ip, own_public_key, formatted_Time, expiration_time,{});

    // 署名対象メッセージを作成
    std::string message = signed_message(test_cert1);
    std::array<unsigned char,256> signature = {0};
    try {
        signature = size256_signMessage(private_key, message);
    } catch (const std::exception& e) {
        std::cerr << "Error signing message: " << e.what() << std::endl;
        EVP_PKEY_free(private_key);
        EVP_PKEY_free(public_key);
        close(sock);
        return 1;
    }

    // 送信元の公開鍵を取得して証明書を作成
    test_cert1 = Makes_Certificate(own_ip, own_public_key, formatted_Time, expiration_time,signature);

    //証明書の中身を確認
    Check_certificate(test_cert1);

    if (test_rdp1.signature.empty()) return -1;

    //乱数の生成
    std::uint32_t nonce = generateRandom32bit();

    //RDP用の署名を生成
    //RDPの署名対象メッセージを作成
    std::string message_certificate = certificate_to_string(test_cert1);
    signature = {0};
    try {
        signature = size256_signMessage(private_key, message_certificate);
    } catch (const std::exception& e) {
        std::cerr << "Error signing message: " << e.what() << std::endl;
        EVP_PKEY_free(private_key);
        EVP_PKEY_free(public_key);
        close(sock);
        return 1;
    }

    //RDPを作成
    test_rdp1 = Makes_RDP(MessageType::RDP,"10.0.0.4",test_cert1,nonce,formatted_Time,signature); //宛先は一旦手打ちで。
    check_RDP(test_rdp1);
    
    std::vector<uint8_t> serialized_data;    // シリアライズ処理
    try {
    serialized_data = serialize(test_rdp1);
    } catch (const std::exception& e) {
    std::cerr << "Failed serialize generation: " << e.what() << std::endl;
    }   

    // データ送信
    if (send_process(serialized_data)) {
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
            //std::cout << "Received packet_type:" << static_cast<int>(packet_type) << std::endl;
            
            if (packet_type == MessageType::REP) {
                // REP メッセージのデシリアライズ
                Forwarding_REP_format deserialized_rep = {};
                deserialize(recv_buf,deserialized_rep); 

                // REP メッセージの内容をログに出力
                std::cout << "Received REP:" << std::endl;
                std::cout << "  Type: " << static_cast<int>(deserialized_rep.type) << std::endl;
                std::cout << "  Destination IP: " << deserialized_rep.dest_ip << std::endl;
                std::cout << "  Certificate Own IP: " << deserialized_rep.cert.own_ip << std::endl;
                std::cout << "  Certificate Public Key: " << deserialized_rep.cert.own_public_key << std::endl;
                std::cout << "  Certificate Timestamp: " << deserialized_rep.cert.time_stamp << std::endl;
                std::cout << "  Certificate Expiration: " << deserialized_rep.cert.expires << std::endl;
                std::cout << "  Nonce: " << deserialized_rep.nonce << std::endl;
                std::cout << "  Timestamp: " << deserialized_rep.time_stamp << std::endl;
                std::cout << "  Signature Size: " << deserialized_rep.signature.size() << std::endl;
                std::cout << "  Receiver Signature Size: " << deserialized_rep.receiver_signature.size() << std::endl;
                std::cout << "  Receiver Certificate Own IP: " << deserialized_rep.receiver_cert.own_ip << std::endl;
                std::cout << "  Receiver Certificate Public Key: " << deserialized_rep.receiver_cert.own_public_key << std::endl;
                std::cout << "  Receiver Certificate Timestamp: " << deserialized_rep.receiver_cert.time_stamp << std::endl;
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
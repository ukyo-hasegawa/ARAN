#include <vector>
#include <string>
#include <sstream>
#include <ctime>
#include "RSA/RSA.h"

// RSA署名ヘルパー関数
std::string signData(const std::string& data, EVP_PKEY* privateKey) {
    return RSAKeyManager::signMessage(data, privateKey);
}

struct REP {
    std::string source_ip;
    std::string dest_ip;
    std::string signature; // 署名
    std::vector<std::string> reverse_path; // 逆経路
};

// RDPメッセージ生成関数
std::string createRDPMessage(const std::string& source_ip, const std::string& dest_ip, const std::string& cert_A, EVP_PKEY* privateKey) {
    std::ostringstream messageStream;

    // ランダム値生成
    uint32_t N_A = rand();

    // 現在時刻の取得
    std::time_t t = std::time(nullptr);

    // RDPメッセージ構築
    messageStream << "RDP"          // RDP識別子
                  << "," << dest_ip // 宛先IPアドレス(引数で指定する予定)
                  << "," << cert_A  // Aの証明書
                  << "," << N_A     // ランダム値
                  << "," << t;      // 現在時刻

    // データ全体を署名
    std::string unsignedMessage = messageStream.str();
    std::string signature = signData(unsignedMessage, privateKey);

    // 署名をメッセージに追加
    messageStream << "," << signature;

    return messageStream.str();
}


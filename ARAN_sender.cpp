#include <string>
#include <iostream>
#include <random>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdint.h>
#include "RSA.h"


struct RDP
{
    std::string type; //識別子
    std::string own_ip; //自身のIPアドレス
    std::string dest_ip; //宛先IPアドレス
    std::string cert; //証明書
    std::uint32_t n; //ランダムな値
    std::string t; //現在時刻
};

int main() {

    //証明書の取得を行う
    EVP_PKEY* pkey = createRSAKeyPair();
    if (!pkey) {
        return -1;
    }

    // 公開鍵の取得
    std::string publicKeyPEM = getPublicKey(pkey);
    std::cout << "\n公開鍵 (PEM形式):\n" << publicKeyPEM << std::endl;

    /* 署名の検証 受信ノードが行う
    bool isValid = verifySignature(pkey, message, signature);
    std::cout << "署名の検証結果: " << (isValid ? "成功" : "失敗") << std::endl;
    */

    std::random_device rnd;
    
    //RDPを生成するコード
    //RDP test_rdp1 = {"RDP","10.0.0.1","10.0.0.1","certification",rnd(),formattedTime}; //テスト用のため適当に設定

        //現在時刻の取得
    auto now = std::chrono::system_clock::now();

    //時刻をtime_tに変換
    std::time_t currentTime = std::chrono::system_clock::to_time_t(now);

    // ローカル時刻にフォーマット
    std::tm* localTime = std::localtime(&currentTime);

    // 文字列にフォーマット
    std::ostringstream timeStream;
    timeStream << std::put_time(localTime, "%Y-%m-%d %H:%M:%S");
    std::string formattedTime = timeStream.str();

    //証明書作成にあたり文字列の連結を行う(IP,pubkey,timestamp,certificate expires)
    std::string certificate = test_rdp1.own_ip+","+publicKeyPEM+","+formattedTime+","+

    std::string message;
    std::cout << "署名するメッセージを入力してください: ";
    std::getline(std::cin, message);
    
    // 署名の生成
    std::vector<unsigned char> signature = signMessage(pkey, message);
    if (signature.empty()) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    std::cout << "生成された署名 (バイナリデータ):" << std::endl;
    for (unsigned char c : signature) {
        printf("%02X", c);
    }
    std::cout << std::endl;


    // メモリの解放
    EVP_PKEY_free(pkey);



    std::cout << "before test_rdp1.type :" << test_rdp1.type << std::endl;
    std::cout << "before test_rdp1.dest_ip :" << test_rdp1.dest_ip << std::endl; 
    std::cout << "before test_rdp1.cert :" << test_rdp1.cert << std::endl;
    std::cout << "before test_rdp1.n :" << test_rdp1.n << std::endl;
    std::cout << "before test_rdp1.t :" << test_rdp1.t << std::endl;

    //シリアライズ
    std::vector<uint8_t> buf;
    auto serialize_string = [&buf](const std::string& str) {
        std::uint32_t len =str.size();
        buf.push_back((len >> 0) & 0xFF);
        buf.push_back((len >> 8) & 0xFF);
        buf.push_back((len >> 16) & 0xFF);
        buf.push_back((len >> 24) & 0xFF);
        buf.insert(buf.end(), str.begin(), str.end());
    };
    
    serialize_string(test_rdp1.type);
    serialize_string(test_rdp1.dest_ip);
    serialize_string(test_rdp1.cert);

    // n (整数) シリアライズ
    for (int i = 0; i < 4; i++) {
        buf.push_back((test_rdp1.n >> (8 * i)) & 0xFF);
    }

    // t (現在時刻) シリアライズ
    serialize_string(test_rdp1.t);

    // シリアライズされたデータを表示 (16進数表示)
    std::cout << "Serialized data (hex): ";
    for (uint8_t byte : buf) {
        std::cout << "%02x " << byte;
    }
    std::cout << std::endl;
    
    //ブロードキャストするコード
    //ソケットの作成
    int sock;
    struct sockaddr_in addr;
    int yes = 1;

    sock = socket(AF_INET,SOCK_DGRAM,0);
    if (sock < 0) {
        std::cerr << "Socket creation failed" << std::endl;
        return 1;
    }
    //ブロードキャストの設定
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);
    addr.sin_addr.s_addr = inet_addr("10.255.255.255");

    //ソケットオプションの設定
    if(setsockopt(sock,SOL_SOCKET,SO_BROADCAST,reinterpret_cast<const char*>(&yes),sizeof(yes)) < 0) {
        std::cerr << "Failed to set socket options" << std::endl;
        close(sock);
        return 1;
    }

    if (sendto(sock, buf.data(), buf.size(), 0, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "Failed to send message" << std::endl;
        close(sock);
        return 1;
    }

    close(sock);

}
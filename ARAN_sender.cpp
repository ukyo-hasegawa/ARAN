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


struct RDP
{
    std::string type; //識別子
    std::string dest_ip; //宛先IPアドレス
    std::string cert; //証明書
    std::int32_t n; //ランダムな値
    std::string t; //現在時刻
};


int main() {

    std::random_device rnd;

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
    
    //RDPを生成するコード
    RDP test_rdp1 = {"RDP","10.0.0.1","certification",rnd(),formattedTime}; //テスト用のため適当に設定
    
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

    if (sendto(sock, "HELLO", 5, 0, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "Failed to send message" << std::endl;
        close(sock);
        return 1;
    }

    close(sock);

}
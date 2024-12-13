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


struct RDP
{
    std::string type; //識別子
    std::string dest_ip; //宛先IPアドレス
    std::string cert; //証明書
    std::uint32_t n; //ランダムな値
    std::string t; //現在時刻
};


int main() {

    //証明書の取得を行う

    //


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


    //デシリアライズするコード
    try {
        RDP deserialized_rdp;
        std::size_t offset = 0;

        // ヘルパー関数: バッファから文字列をデシリアライズ
        auto deserialize_string = [&buf, &offset]() {
            if (offset + 4 > buf.size()) {
                throw std::runtime_error("Buffer underflow while reading string length");
            }

            // 長さを取得 (4バイト)
            std::uint32_t len = 0;
            len |= buf[offset + 0] << 0;
            len |= buf[offset + 1] << 8;
            len |= buf[offset + 2] << 16;
            len |= buf[offset + 3] << 24;
            offset += 4;

            // 文字列データを取得
            if (offset + len > buf.size()) {
                throw std::runtime_error("Buffer underflow while reading string data");
            }

            std::string result(buf.begin() + offset, buf.begin() + offset + len);
            offset += len;

            return result;
        };

        // ヘルパー関数: バッファから整数をデシリアライズ
        auto deserialize_int32 = [&buf, &offset]() {
            if (offset + 4 > buf.size()) {
                throw std::runtime_error("Buffer underflow while reading int32");
            }

            // 4バイトを整数に変換
            std::int32_t value = 0;
            value |= buf[offset + 0] << 0;
            value |= buf[offset + 1] << 8;
            value |= buf[offset + 2] << 16;
            value |= buf[offset + 3] << 24;
            offset += 4;

            return value;
        };

        // デシリアライズ処理
        deserialized_rdp.type = deserialize_string();
        deserialized_rdp.dest_ip = deserialize_string();
        deserialized_rdp.cert = deserialize_string();
        deserialized_rdp.n = deserialize_int32();
        deserialized_rdp.t = deserialize_string();

        // 結果を表示
        std::cout << "Deserialized RDP:" << std::endl;
        std::cout << "Type: " << deserialized_rdp.type << std::endl;
        std::cout << "Destination IP: " << deserialized_rdp.dest_ip << std::endl;
        std::cout << "Certificate: " << deserialized_rdp.cert << std::endl;
        std::cout << "Random Number: " << deserialized_rdp.n << std::endl;
        std::cout << "Timestamp: " << deserialized_rdp.t << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error during deserialization: " << e.what() << std::endl;
    }

    
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
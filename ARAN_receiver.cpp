#include <netinet/in.h>
#include <string>
#include <cstring>
#include <vector>
#include <iostream>

struct RDP
{
    std::string type; //識別子
    std::string dest_ip; //宛先IPアドレス
    std::string cert; //証明書
    std::uint32_t n; //ランダムな値
    std::string t; //現在時刻
};


int main(){
    //ブロードキャストを受信するコード
    int sock;
    struct  sockaddr_in addr;

    char buf[2048];

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);
    addr.sin_addr.s_addr = INADDR_ANY;

    // バインド
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        std::cerr << "Failed to bind socket" << std::endl;
        return 1;
    } else {
        std::cout << "bind sucess" << std::endl;
    }

    // 受信
    memset(buf, 0, sizeof(buf));
    ssize_t received_bytes = recv(sock, buf, sizeof(buf), 0);
    if (received_bytes < 0) {
        std::cerr << "Failed to receive data" << std::endl;
        return 1;
    } else
    {
        std::cout << "receive sucess" << std::endl;
    }

    // バッファを std::vector<uint8_t> に変換
    std::vector<uint8_t> recv_buf(buf, buf + received_bytes);

    // デシリアライズするコード
    try {
        RDP deserialized_rdp;
        std::size_t offset = 0;

        // ヘルパー関数: バッファから文字列をデシリアライズ
        auto deserialize_string = [&recv_buf, &offset]() {
            if (offset + 4 > recv_buf.size()) {
                throw std::runtime_error("Buffer underflow while reading string length");
            }

            // 長さを取得 (4バイト)
            std::uint32_t len = 0;
            len |= recv_buf[offset + 0] << 0;
            len |= recv_buf[offset + 1] << 8;
            len |= recv_buf[offset + 2] << 16;
            len |= recv_buf[offset + 3] << 24;
            offset += 4;

            // 文字列データを取得
            if (offset + len > recv_buf.size()) {
                throw std::runtime_error("Buffer underflow while reading string data");
            }

            std::string result(recv_buf.begin() + offset, recv_buf.begin() + offset + len);
            offset += len;

            return result;
        };

        // ヘルパー関数: バッファから整数をデシリアライズ
        auto deserialize_int32 = [&recv_buf, &offset]() {
            if (offset + 4 > recv_buf.size()) {
                throw std::runtime_error("Buffer underflow while reading int32");
            }

            // 4バイトを整数に変換
            std::int32_t value = 0;
            value |= recv_buf[offset + 0] << 0;
            value |= recv_buf[offset + 1] << 8;
            value |= recv_buf[offset + 2] << 16;
            value |= recv_buf[offset + 3] << 24;
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

    return 0;

//証明書を検証するコード
}
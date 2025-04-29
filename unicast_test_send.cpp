#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

int main() {
    // 宛先IPアドレスとポート番号
    const char* destination_ip = "10.0.0.1";
    const int destination_port = 12345;

    // 送信データ
    const char* message = "Hello, this is a unicast test message!";
    size_t message_length = strlen(message);

    // ソケット作成
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Failed to create socket");
        return 1;
    }

    // 宛先アドレス構造体の設定
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(destination_port);
    if (inet_pton(AF_INET, destination_ip, &dest_addr.sin_addr) <= 0) {
        perror("Invalid destination IP address");
        close(sock);
        return 1;
    }

    // データ送信
    ssize_t sent_bytes = sendto(sock, message, message_length, 0,
                                reinterpret_cast<struct sockaddr*>(&dest_addr), sizeof(dest_addr));
    if (sent_bytes < 0) {
        perror("Failed to send message");
        close(sock);
        return 1;
    }

    std::cout << "Message sent successfully to " << destination_ip << ":" << destination_port << std::endl;

    // ソケットを閉じる
    close(sock);
    return 0;
}
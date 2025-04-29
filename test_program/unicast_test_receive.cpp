#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 12345 // 受信するポート番号
#define BUFFER_SIZE 1024

int main() {
    int sockfd;
    struct sockaddr_in serverAddr, clientAddr;
    char buffer[BUFFER_SIZE];
    socklen_t addrLen = sizeof(clientAddr);

    // ソケットの作成
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // サーバーアドレス構造体の設定
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY; // 任意のアドレスから受信
    serverAddr.sin_port = htons(PORT);

    // ソケットにアドレスをバインド
    if (bind(sockfd, (const struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        return -1;
    }

    std::cout << "Waiting for data on port " << PORT << "..." << std::endl;

    // データの受信
    while (true) {
        memset(buffer, 0, BUFFER_SIZE);
        int n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&clientAddr, &addrLen);
        if (n < 0) {
            perror("Receive failed");
            break;
        }

        std::cout << "Received message: " << buffer << std::endl;
    }

    // ソケットを閉じる
    close(sockfd);
    return 0;
}
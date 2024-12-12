#include "RSA/RSA.h"
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>

void intermediaryNode(const std::string& dest_ip, const std::string& next_hop_ip) {
    RSA* intermediaryKey = RSAKeyManager::generateKeyPair();

    // ソケット作成
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in localAddr{};
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = htons(5000);
    localAddr.sin_addr.s_addr = INADDR_ANY;
    bind(sock, (sockaddr*)&localAddr, sizeof(localAddr));

    char buffer[1024];
    sockaddr_in senderAddr{};
    socklen_t addrLen = sizeof(senderAddr);

    recvfrom(sock, buffer, sizeof(buffer), 0, (sockaddr*)&senderAddr, &addrLen);
    std::cout << "Intermediary received RDP: " << buffer << std::endl;

    // 署名と転送
    sockaddr_in destAddr{};
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = htons(5001);
    inet_pton(AF_INET, next_hop_ip.c_str(), &destAddr.sin_addr);

    sendto(sock, buffer, strlen(buffer), 0, (sockaddr*)&destAddr, sizeof(destAddr));

    close(sock);
    RSA_free(intermediaryKey);
}
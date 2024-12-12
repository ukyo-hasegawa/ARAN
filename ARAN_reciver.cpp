#include "RSA/RSA.h"
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

void receiverNode() {
    RSA* receiverKey = RSAKeyManager::generateKeyPair();

    // ソケット作成
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in localAddr{};
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = htons(5001);
    localAddr.sin_addr.s_addr = INADDR_ANY;
    bind(sock, (sockaddr*)&localAddr, sizeof(localAddr));

    char buffer[1024];
    sockaddr_in senderAddr{};
    socklen_t addrLen = sizeof(senderAddr);

    recvfrom(sock, buffer, sizeof(buffer), 0, (sockaddr*)&senderAddr, &addrLen);
    std::cout << "Receiver received RDP: " << buffer << std::endl;

    close(sock);
    RSA_free(receiverKey);
}
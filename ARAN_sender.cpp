#include "RSA/RSA.h"
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>

//送信元のコード
void senderNode(const std::string& dest_ip, const std::string& intermediary_ip) {
    RSA* senderKey = RSAKeyManager::generateKeyPair();
    
    // ソケット作成
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in intermediaryAddr{};
    intermediaryAddr.sin_family = AF_INET;
    intermediaryAddr.sin_port = htons(5000);
    inet_pton(AF_INET, intermediary_ip.c_str(), &intermediaryAddr.sin_addr);

    // RDP生成
    RDP rdp;
    rdp.source_ip = "10.0.0.1";
    rdp.dest_ip = dest_ip;
    rdp.signature = RSAKeyManager::signMessage(rdp.source_ip + rdp.dest_ip, senderKey);

    // 送信
    std::string message = rdp.source_ip + "," + rdp.dest_ip + "," + rdp.signature;
    sendto(sock, message.c_str(), message.size(), 0, (sockaddr*)&intermediaryAddr, sizeof(intermediaryAddr));

    close(sock);
    RSA_free(senderKey);
}


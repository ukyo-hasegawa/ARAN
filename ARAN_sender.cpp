#include "RSA/RSA.h"
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "data_struct.h"

//送信ノードの動作
void senderNode(const std::string& dest_ip,const std::string& broadcast_ip,const std::string& cert_A) {
    EVP_PKEY* senderKey = RSAKeyManager::generateKeyPair();
    
    // ソケット作成
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return;
    }

    //ブロードキャストアドレスの設定
    int broadcastEnable = 1;
    setsockopt(sock,SOL_SOCKET,SO_BROADCAST,&broadcastEnable,sizeof(broadcastEnable));

    sockaddr_in broadcastAddr{};
    broadcastAddr.sin_family = AF_INET;
    broadcastAddr.sin_port = htons(5000);
    inet_pton(AF_INET,broadcast_ip.c_str(),&broadcastAddr.sin_addr);

    // RDPメッセージ生成
    std::string rdpMessage = createRDPMessage("10.0.0.1", dest_ip, cert_A, senderKey);

    // メッセージのブロードキャスト
    ssize_t sentBytes = sendto(sock, rdpMessage.c_str(), rdpMessage.size(), 0,
                               (sockaddr*)&broadcastAddr, sizeof(broadcastAddr));

    if (sentBytes < 0) {
        perror("Failed to broadcast RDP");
    } else {
        std::cout << "Broadcasted RDP: " << rdpMessage << std::endl;
    }

    close(sock);
    EVP_PKEY_free(senderKey);
}


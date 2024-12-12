#include "RSA/RSA.h"
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "data_struct.h"

// 受信ノードの動作
void receiverNode(const std::string& self_ip, RSA* senderPublicKey, RSA* receiverPrivateKey) {
    RSA* receiverKey = RSAKeyManager::generateKeyPair();

    // ソケット作成
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return;
    }

    sockaddr_in localAddr{};
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = htons(5001);
    localAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (sockaddr*)&localAddr, sizeof(localAddr)) < 0) {
        perror("Bind failed");
        close(sock);
        return;
    }

    char buffer[1024];
    sockaddr_in senderAddr{};
    socklen_t addrLen = sizeof(senderAddr);

    // RDPを受信
    ssize_t recvLen = recvfrom(sock, buffer, sizeof(buffer), 0, (sockaddr*)&senderAddr, &addrLen);
    if (recvLen < 0) {
        perror("Receive failed");
        close(sock);
        RSA_free(receiverKey);
        return;
    }

    buffer[recvLen] = '\0'; // 受信データを文字列として処理
    std::string receivedMessage(buffer);
    std::cout << "Receiver received RDP: " << receivedMessage << std::endl;

    // RDPメッセージを解析
    std::istringstream messageStream(receivedMessage);
    std::string rdpType, dest_ip, cert, signature;
    uint32_t randomValue;
    std::time_t timestamp;

    std::getline(messageStream, rdpType, ',');
    std::getline(messageStream, dest_ip, ',');
    std::getline(messageStream, cert, ',');
    messageStream >> randomValue;
    messageStream.ignore(1, ','); // ','をスキップ
    messageStream >> timestamp;
    messageStream.ignore(1, ','); // ','をスキップ
    std::getline(messageStream, signature);

    // **1. 署名の検証**
    std::string unsignedMessage = rdpType + "," + dest_ip + "," + cert + "," +
                                   std::to_string(randomValue) + "," + std::to_string(timestamp);

    if (RSAKeyManager::verifyMessage(unsignedMessage, signature, senderPublicKey)) {
        std::cout << "Signature verified successfully." << std::endl;
    } else {
        std::cerr << "Signature verification failed!" << std::endl;
        close(sock);
        RSA_free(receiverKey);
        return;
    }

    // **2. 宛先確認**
    if (dest_ip == self_ip) {
        std::cout << "This RDP is intended for this node (" << self_ip << ")." << std::endl;

        // **REPの生成**
        std::ostringstream repStream;
        repStream << "REP," << dest_ip << "," << self_ip << "," << randomValue << "," << timestamp;
        std::string unsignedRepMessage = repStream.str();

        // REPに署名を付与
        std::string repSignature = RSAKeyManager::signMessage(unsignedRepMessage, receiverPrivateKey);
        repStream << "," << repSignature;

        // 宛先（送信元）にREPを送信
        sockaddr_in senderSockAddr{};
        senderSockAddr.sin_family = AF_INET;
        senderSockAddr.sin_port = htons(5000);
        inet_pton(AF_INET, cert.c_str(), &senderSockAddr.sin_addr); // 送信元のIP（証明書から取得）

        ssize_t sentBytes = sendto(sock, repStream.str().c_str(), repStream.str().size(), 0,
                                   (sockaddr*)&senderSockAddr, sizeof(senderSockAddr));

        if (sentBytes < 0) {
            perror("Failed to send REP");
        } else {
            std::cout << "Sent REP: " << repStream.str() << std::endl;
        }
    } else {
        std::cout << "This RDP is not intended for this node (" << self_ip << ")." << std::endl;


        //ここに中継ノードの証明書がRDPに付与されていないか確認するコードを書いて
        // **中継ノードの証明書確認**
        if (!cert.empty()) {
            std::cout << "Existing certificate found. Replacing with intermediate node's certificate." << std::endl;
            
        }
        // **中継ノード処理**
        std::ostringstream forwardedRdpStream;
        forwardedRdpStream << rdpType << "," << dest_ip << "," << cert << "," << randomValue << "," << timestamp;

        // 中継ノードの署名を追加
        std::string newSignature = RSAKeyManager::signMessage(forwardedRdpStream.str(), receiverPrivateKey);
        forwardedRdpStream << "," << newSignature;

        // RDPをブロードキャスト
        sockaddr_in broadcastAddr{};
        broadcastAddr.sin_family = AF_INET;
        broadcastAddr.sin_port = htons(5000);
        broadcastAddr.sin_addr.s_addr = INADDR_BROADCAST;

        ssize_t sentBytes = sendto(sock, forwardedRdpStream.str().c_str(), forwardedRdpStream.str().size(), 0,
                                   (sockaddr*)&broadcastAddr, sizeof(broadcastAddr));

        if (sentBytes < 0) {
            perror("Failed to forward RDP");
        } else {
            std::cout << "Forwarded RDP: " << forwardedRdpStream.str() << std::endl;
        }
    }

    close(sock);
    RSA_free(receiverKey);
}
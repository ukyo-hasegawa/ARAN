#include <netinet/in.h>
#include <string>
#include <cstring>
#include <vector>
#include <iostream>

int main(){
    //ブロードキャストを受信するコード
    int sock;
    struct  sockaddr_in addr;

    char buf[2048];

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(sock, (struct sockaddr *)&addr, sizeof(addr) );

    memset(buf,0,sizeof(buf));
    recv(sock,buf,sizeof(buf),0);

    std::cout << "%s" << buf << std::endl;

    return 0;



   
    



//証明書を検証するコード
}
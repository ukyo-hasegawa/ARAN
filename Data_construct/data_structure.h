#include <cstdint>
#include <array>

using namespace std;

enum class MessageType : uint8_t {
    RDP = 0x01,
    REP = 0x02
};

struct Certificate_Format {
    char own_ip[16]; //16byteのIPアドレス
    char own_public_key[256]; //256byteの公開鍵 ここはunsigned charにするか要検討
    char time_stamp[20]; //20byteのタイムスタンプ
    char expires[20]; //20byteの有効期限
};

struct RDP_format {
    MessageType type; //1バイト
    char source_ip[16]; //16バイト
    char dest_ip[16];
    Certificate_Format cert;
    std::uint32_t nonce; //4バイト
    char time_stamp[20];
    array<unsigned char, 256> signature;
};

struct Forwarding_RDP_format {
    RDP_format rdp;
    array<unsigned char,256> receiver_signature;
    Certificate_Format receiver_cert;
};

struct Forwarding_REP_format {
    MessageType type; //1バイト
    char dest_ip[16]; //16バイト
    Certificate_Format cert;
    std::uint32_t nonce; //4バイト
    char time_stamp[20];
    array<unsigned char, 256> signature;
    array<unsigned char, 256> receiver_signature;
    Certificate_Format receiver_cert;
};
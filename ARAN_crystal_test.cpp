#include <iostream>
#include <vector>
#include <cassert>
#include "ARAN_crystal.cpp"

// テスト用のデータを作成
data_format create_test_data() {
    data_format test_rdp1 = {
        "RDP",
        "10.0.0.1",
        "10.0.0.3",
        "test_cert",
        12345,
        "2025-02-07 12:00:00",
        "2025-02-08 12:00:00",
        {}
    };
    return test_rdp1;
}

// 署名の生成と検証のテスト
void test_sign_and_verify() {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    assert(sig != nullptr);

    std::vector<unsigned char> public_key(sig->length_public_key);
    std::vector<unsigned char> private_key(sig->length_secret_key);
    assert(OQS_SIG_keypair(sig, public_key.data(), private_key.data()) == OQS_SUCCESS);

    data_format test_rdp1 = create_test_data();

    // 署名対象メッセージを作成
    std::ostringstream messageStream;
    messageStream << test_rdp1.type << "|"
                  << test_rdp1.dest_ip << "|"
                  << test_rdp1.cert << "|"
                  << test_rdp1.n << "|"
                  << test_rdp1.t;
    std::string message = messageStream.str();

    // 署名の生成
    test_rdp1.signature = signMessage(message, private_key);
    assert(!test_rdp1.signature.empty());

    // 署名の検証
    bool isValid = verifySignature(message, test_rdp1.signature, public_key);
    assert(isValid);

    OQS_SIG_free(sig);
}

// シリアライズとデシリアライズのテスト
void test_serialize_and_deserialize() {
    data_format test_rdp1 = create_test_data();

    // シリアライズ処理
    std::vector<uint8_t> buf;
    serialize_data(test_rdp1, buf);

    // デシリアライズ処理
    data_format deserialized_rdp = deserialize_data(buf);

    // データの一致を確認
    assert(test_rdp1.type == deserialized_rdp.type);
    assert(test_rdp1.own_ip == deserialized_rdp.own_ip);
    assert(test_rdp1.dest_ip == deserialized_rdp.dest_ip);
    assert(test_rdp1.cert == deserialized_rdp.cert);
    assert(test_rdp1.n == deserialized_rdp.n);
    assert(test_rdp1.t == deserialized_rdp.t);
    assert(test_rdp1.expires == deserialized_rdp.expires);
    assert(test_rdp1.signature == deserialized_rdp.signature);
}

// 送信プロセスのテスト
void test_send_process() {
    data_format test_rdp1 = create_test_data();

    // シリアライズ処理
    std::vector<uint8_t> buf;
    serialize_data(test_rdp1, buf);

    // 送信プロセスのテスト
    int result = send_process(buf);
    assert(result == 1);
}

int main() {
    test_sign_and_verify();
    std::cout << "test_sign_and_verify passed" << std::endl;

    test_serialize_and_deserialize();
    std::cout << "test_serialize_and_deserialize passed" << std::endl;

    test_send_process();
    std::cout << "test_send_process passed" << std::endl;

    return 0;
}
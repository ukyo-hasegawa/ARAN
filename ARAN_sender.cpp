#include <string>
#include <iostream>
#include <random>
#include <chrono>
#include <ctime>
#include <iomanip>


struct RDP
{
    std::string type; //識別子
    std::string dest_ip; //宛先IPアドレス
    std::string cert; //証明書
    std::int32_t n; //ランダムな値
    std::string t; //現在時刻
};


int main() {

    std::random_device rnd;

    //現在時刻の取得
    auto now = std::chrono::system_clock::now();

    //時刻をtime_tに変換
    std::time_t currentTime = std::chrono::system_clock::to_time_t(now);


    // ローカル時刻にフォーマット
    std::tm* localTime = std::localtime(&currentTime);

    // 文字列にフォーマット
    std::ostringstream timeStream;
    timeStream << std::put_time(localTime, "%Y-%m-%d %H:%M:%S");
    std::string formattedTime = timeStream.str();
    
    //RDPを生成するコード
    RDP test_rdp1 = {"RDP","10.0.0.1","certification",rnd(),formattedTime}; //テスト用のため適当に設定
    std::string IP = "10.0.0.1"; //sta1のIPアドレス
    std::cout << "IP=" << IP << std::endl;

}



//ブロードキャストするコード
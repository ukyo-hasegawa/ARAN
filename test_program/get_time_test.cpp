#include <ctime>
#include <iostream>
#include <string>
#include <chrono>

std::string get_time(bool forceError = false) {
    if (forceError) {
        std::cerr << "Forced error: Failed to get local time" << std::endl;
        return std::string(20, '\0'); // エラー時は20バイトのヌル文字列を返す
    }

    auto now = std::chrono::system_clock::now();
    std::time_t currentTime = std::chrono::system_clock::to_time_t(now);
    std::tm* localTime = std::localtime(&currentTime);

    // 時刻をフォーマット
    char formattedTime[20] = {};
    if (localTime) {
        std::strftime(formattedTime, sizeof(formattedTime), "%Y-%m-%d %H:%M:%S", localTime);
    } else {
        std::cerr << "Failed to get local time" << std::endl;
        return std::string(20, '\0'); // エラー時は20バイトのヌル文字列を返す
    }

    return std::string(formattedTime); // std::string に変換して返す
}

int main() {
    // 正常な動作
    std::cout << "Normal case: " << get_time() << std::endl;

    // エラーを強制
    std::cout << "Error case: " << get_time(true) << std::endl;

    return 0;
}
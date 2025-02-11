std::pair<std::string, std::vector<unsigned char>> split_sign_message(const std::string& signed_message) {
    std::string delimiter = "Message-with-public-key-end";
    size_t pos = signed_message.find(delimiter);
    if (pos == std::string::npos) {
        throw std::runtime_error("Delimiter not found in signed message");
    }

    // メッセージ部分と署名部分を分割
    std::string message = signed_message.substr(0, pos + delimiter.length());
    std::string signature_and_ip = signed_message.substr(pos + delimiter.length());

    // 署名部分とIPアドレス部分を分割
    size_t ip_pos = signature_and_ip.find('|');
    if (ip_pos == std::string::npos) {
        throw std::runtime_error("IP address delimiter not found in signature and IP part");
    }
    std::string signature_hex = signature_and_ip.substr(0, ip_pos);
    std::string ip_address = signature_and_ip.substr(ip_pos + 1);

    std::cout << "--------------------------Splited message-------------------------\n" << message << std::endl;
    std::cout << "Signature hex: " << signature_hex << std::endl;
    std::cout << "IP address: " << ip_address << std::endl;

    // 署名部分をバイト列に変換
    std::vector<unsigned char> signature;
    std::cout << "Signature hex length: " << signature_hex.length() << std::endl;

    if (signature_hex.empty()) {
        std::cerr << "Error: signature_hex is empty" << std::endl;
        throw std::runtime_error("signature_hex is empty");
    }

    for (size_t i = 0; i < signature_hex.length(); i += 2) {
        std::string byteString = signature_hex.substr(i, 2);
        std::cout << "Processing byteString: " << byteString << std::endl;
        if (byteString.empty()) {
            std::cerr << "Error: byteString is empty" << std::endl;
            continue;
        }
        try {
            unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
            signature.push_back(byte);
        } catch (const std::exception& e) {
            std::cerr << "Error converting hex to byte: " << e.what() << std::endl;
            throw;
        }
    }

    // 署名部分を出力
    std::cout << "---------------------------ORIGINAL_SIGNATURE------------------------\n";
    for (unsigned char c : signature) {
        std::cout << std::hex << (int)c << " ";
    }
    std::cout << std::dec << std::endl;

    return {message, signature};
}
/*
RDPのシリアライズ処理を行う関数等をここに記述します。
*/

void serialize(const RDP_format& rdp, unsigned char* buf) {
    size_t offset = 0;

    //type
    buf[offset] = static_cast<uint8_t>(rdp.type);
    offset += sizeof(uint8_t);

    //source_ip
    std::memcpy(buf + offset, rdp.source_ip, sizeof(rdp.source_ip));
    offset += sizeof(rdp.source_ip);

    //dest_ip
    std::memcpy(buf + offset, rdp.dest_ip, sizeof(rdp.dest_ip));
    offset += sizeof(rdp.dest_ip);

    //cert own_ip
    std::memcpy(buf + offset, rdp.cert.own_ip, sizeof(rdp.cert.own_ip));
    offset += sizeof(rdp.cert.own_ip);
    //cert own_public_key
    std::memcpy(buf + offset, rdp.cert.own_public_key, sizeof(rdp.cert.own_public_key));
    offset += sizeof(rdp.cert.own_public_key);

    //cert time_stamp
    std::memcpy(buf + offset, rdp.cert.time_stamp, sizeof(rdp.cert.time_stamp));
    offset += sizeof(rdp.cert.time_stamp);

    //cert expires
    std::memcpy(buf + offset, rdp.cert.expires, sizeof(rdp.cert.expires));
    offset += sizeof(rdp.cert.expires);


    // nonce
    std::memcpy(buf + offset, &rdp.nonce, sizeof(rdp.nonce));
    offset += sizeof(rdp.nonce);

    // time_stamp
    std::memcpy(buf + offset, rdp.time_stamp, sizeof(rdp.time_stamp));
    offset += sizeof(rdp.time_stamp);

    // signature
    std::memcpy(buf + offset, rdp.signature.data(), rdp.signature.size());
    offset += rdp.signature.size();
    
}
#pragma once

#include <fstream>
#include "heiFIPPacketImage.cpp"

std::vector<std::shared_ptr<heiFIPPacketImage>> read_pcap(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    std::vector<std::shared_ptr<heiFIPPacketImage>> packets;
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file " << filename << std::endl;
        return packets;
    }

    PcapGlobalHeader globalHeader;
    file.read(reinterpret_cast<char*>(&globalHeader), sizeof(globalHeader));

    while (file.peek() != EOF) {
        PcapPacketHeader packetHeader;
        file.read(reinterpret_cast<char*>(&packetHeader), sizeof(packetHeader));

        if (file.eof()) break;

        std::vector<uint8_t> packet_data(packetHeader.caplen);
        file.read(reinterpret_cast<char*>(packet_data.data()), packetHeader.caplen);


        heiFIPPacketImage packet = heiFIPPacketImage(packet_data, packetHeader.caplen );
        packets.push_back(std::make_shared<heiFIPPacketImage>(packet));
    }
    file.close();
    return packets;
}
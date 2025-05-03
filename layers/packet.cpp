#pragma once

#include <iostream>
#include <pcap.h>
#include <PcapFileDevice.h>
#include <Packet.h>
#include <EthLayer.h>
#include <unordered_map>
#include <string>
#include <sstream>
#include <iomanip>
#include <openssl/md5.h>
#include <cstdlib>
#include <ctime>

// Base class FIPPacket
class FIPPacket {
protected:
    pcpp::Packet packet;
    std::unordered_map<std::string, std::string> address_mapping;
    std::unordered_map<std::string, bool> layer_map;
    std::string hash;

    std::string generate_md5(const pcpp::Packet& pkt) {
        std::ostringstream raw_stream;

        pcpp::Layer* currentLayer = pkt.getFirstLayer();
        while (currentLayer != nullptr) {
            raw_stream.write((const char*)currentLayer->getData(), currentLayer->getDataLen());
            currentLayer = currentLayer->getNextLayer();
        }

        std::string raw_data = raw_stream.str();
        unsigned char digest[MD5_DIGEST_LENGTH];
        MD5((unsigned char*)raw_data.c_str(), raw_data.length(), digest);

        std::ostringstream md5stream;
        for (int i = 0; i < MD5_DIGEST_LENGTH; ++i)
            md5stream << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];

        return md5stream.str();
    }

    void extract_layers() {
        layer_map.clear();
        pcpp::Layer* layer = packet.getFirstLayer();
        while (layer != nullptr) {
            std::string layerName = getProtocolTypeAsString(layer->getProtocol());
            layer = layer->getNextLayer();
        }
    }

    std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType)
    {
        switch (protocolType)
        {
        case pcpp::Ethernet:
            return "Ethernet";
        case pcpp::IPv4:
            return "IPv4";
        case pcpp::TCP:
            return "TCP";
        case pcpp::HTTPRequest:
            return "HTTPRequest";
        case pcpp::HTTPResponse:
            return "HTTPResponse";
        case pcpp::DNS:
            return "DNS";
        default:
            return "Unknown";
        }
    }

public:
    // Constructor
    FIPPacket(const pcpp::Packet& pkt,
              const std::unordered_map<std::string, std::string>& addr_map = {},
              const std::unordered_map<std::string, bool>& lmap = {})
        : packet(pkt), address_mapping(addr_map) {

        hash = generate_md5(packet);

        if (lmap.empty()) {
            extract_layers();
        } else {
            layer_map = lmap;
        }
    }

    // Virtual function for header preprocessing
    virtual void header_preprocessing() {
        // This is a placeholder; you can define specific header handling logic
        std::cout << "Base header preprocessing" << std::endl;
    }

    // Method to retrieve the MD5 hash
    const std::string& getHash() const { return hash; }

    // Method to retrieve the layer map
    const std::unordered_map<std::string, bool>& getLayerMap() const { return layer_map; }

    // Method to retrieve the layer map
    const std::unordered_map<std::string, std::string>& getAdressMapping() const { return address_mapping; }

    const pcpp::Packet* getPacket() const { return &packet;};
};

// Derived class UnknownPacket
class UnknownPacket : public FIPPacket {
public:
    // Constructor: Initializes FIPPacket with the same parameters
    UnknownPacket(const pcpp::Packet& pkt,
                  const std::unordered_map<std::string, std::string>& addr_map = {},
                  const std::unordered_map<std::string, bool>& lmap = {})
        : FIPPacket(pkt, addr_map, lmap) {}

    // Override header preprocessing
    void header_preprocessing() override {
        // Call base class header preprocessing
        FIPPacket::header_preprocessing();

        // Add specific preprocessing logic for UnknownPacket
        std::cout << "UnknownPacket header preprocessing" << std::endl;
    }
};

// Utility function to generate random MAC address
std::string generate_random_mac() {
    std::stringstream mac;
    mac << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (rand() % 256);
    for (int i = 0; i < 5; ++i) {
        mac << ":" << std::setw(2) << std::setfill('0') << (rand() % 256);
    }
    return mac.str();
}

// Derived class EtherPacket
class EtherPacket : public FIPPacket {
public:
    // Constructor: Initializes FIPPacket and processes the Ethernet layer
    EtherPacket(const pcpp::Packet& pkt,
                const std::unordered_map<std::string, std::string>& addr_map = {},
                const std::unordered_map<std::string, bool>& lmap = {})
        : FIPPacket(pkt, addr_map, lmap) {

        if (layer_map.find("Ethernet") != layer_map.end()) {
            __filter();
        }
    }

    // Function to filter and modify MAC addresses
    void __filter() {
        pcpp::EthLayer* ethLayer = packet.getLayerOfType<pcpp::EthLayer>();
        if (ethLayer == nullptr) return;

        std::string previous_src = ethLayer->getSourceMac().toString();
        std::string previous_dst = ethLayer->getDestMac().toString();

        std::string new_src, new_dst;

        // Modify source MAC
        if (address_mapping.find(previous_src) != address_mapping.end()) {
            new_src = address_mapping[previous_src];
        } else {
            new_src = generate_random_mac();
            address_mapping[previous_src] = new_src;
        }

        // Modify destination MAC
        if (address_mapping.find(previous_dst) != address_mapping.end()) {
            new_dst = address_mapping[previous_dst];
        } else {
            new_dst = generate_random_mac();
            address_mapping[previous_dst] = new_dst;
        }

        // Set new MAC addresses
        ethLayer->setSourceMac(pcpp::MacAddress(new_src));
        ethLayer->setDestMac(pcpp::MacAddress(new_dst));
    }

    // Override header preprocessing
    void header_preprocessing() override {
        // Call base class header preprocessing
        FIPPacket::header_preprocessing();

        // Add specific preprocessing logic for EtherPacket
        std::cout << "EtherPacket header preprocessing" << std::endl;
    }
};
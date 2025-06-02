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
#include <openssl/sha.h>   // instead of md5.h
#include <cstdlib>
#include <ctime>

// Base class FIPPacket
class FIPPacket {
    private:
        std::unique_ptr<pcpp::RawPacket> rawPtr;

    protected:
        pcpp::Packet Packet;
        std::unordered_map<std::string, std::string> address_mapping;
        std::unordered_map<std::string, bool> layer_map;
        std::string hash;

        std::string generate_sha256() {
            // 1) gather all layer-bytes into one buffer
            std::ostringstream raw_stream;
            for (pcpp::Layer* layer = Packet.getFirstLayer(); layer; layer = layer->getNextLayer()) {
                raw_stream.write(reinterpret_cast<const char*>(layer->getData()),
                                layer->getDataLen());
            }
            std::string data = raw_stream.str();

            // 2) compute SHA-256
            unsigned char digest[SHA256_DIGEST_LENGTH];
            SHA256(reinterpret_cast<const unsigned char*>(data.data()),
                data.size(),
                digest);

            // 3) hex-encode
            std::ostringstream hash_stream;
            hash_stream << std::hex << std::setfill('0');
            for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                hash_stream << std::setw(2) << static_cast<int>(digest[i]);
            }
            return hash_stream.str();
        }

        void extract_layers() {
            layer_map.clear();
            pcpp::Layer* layer = Packet.getFirstLayer();
            while (layer != nullptr) {
                std::string layerName = getProtocolTypeAsString(layer->getProtocol());
                layer_map.insert({layerName, true});
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
            case pcpp::IPv6:
                return "IPv6";
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
        FIPPacket(std::unique_ptr<pcpp::RawPacket> rawPacketPointer, const std::unordered_map<std::string, std::string>& addr_map = {},
            const std::unordered_map<std::string, bool>& lmap = {}) : address_mapping(addr_map), rawPtr(std::move(rawPacketPointer)) {

            // Create a new RawPacket with the copied buffer
            Packet = pcpp::Packet(rawPtr.get());

            if (lmap.empty()) {
                extract_layers();
            } else {
                layer_map = lmap;
            }

            hash = generate_sha256();
        }

        virtual ~FIPPacket() = default;

        // Virtual function for header preprocessing
        virtual void header_preprocessing() {
            // This is a placeholder; you can define specific header handling logic
        }
    
        // Method to retrieve the MD5 hash
        const std::string& getHash() const { return hash; }

        // Method to retrieve the layer map
        const std::unordered_map<std::string, bool>& getLayerMap() const { return layer_map; }

        // Method to retrieve the layer map
        const std::unordered_map<std::string, std::string>& getAdressMapping() const { return address_mapping; }

        pcpp::RawPacket* getRawPacket() {
            return rawPtr.get();
        }

        // Const overload: returns a const pointer to the RawPacket
        const pcpp::RawPacket* getRawPacket() const {
            return rawPtr.get();
        }
};

// Derived class UnknownPacket
class UnknownPacket : public FIPPacket {
public:
    // Constructor: Initializes FIPPacket with the same parameters
    UnknownPacket(std::unique_ptr<pcpp::RawPacket> rawPacketPointer,
                  const std::unordered_map<std::string, std::string>& addr_map = {},
                  const std::unordered_map<std::string, bool>& lmap = {})
        : FIPPacket(std::move(rawPacketPointer), addr_map, lmap) {}

    // Override header preprocessing
    void header_preprocessing() override {
        // Call base class header preprocessing
        FIPPacket::header_preprocessing();
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
    EtherPacket(std::unique_ptr<pcpp::RawPacket> rawPacketPointer,
                const std::unordered_map<std::string, std::string>& addr_map = {},
                const std::unordered_map<std::string, bool>& lmap = {})
        : FIPPacket(std::move(rawPacketPointer), addr_map, lmap) {

        if (layer_map.find("Ethernet") != layer_map.end()) {
            __filter();
        }
    }

    // Function to filter and modify MAC addresses
    void __filter() {
        pcpp::EthLayer* ethLayer = Packet.getLayerOfType<pcpp::EthLayer>();
        if (ethLayer == nullptr) return;

        std::string previous_src = ethLayer->getSourceMac().toString();
        std::string previous_dst = ethLayer->getDestMac().toString();

        std::string new_src, new_dst;

        // Modify source MAC
        if (address_mapping.count(previous_src) > 0) {
            new_src = address_mapping[previous_src];
        } else {
            new_src = generate_random_mac();
            address_mapping[previous_src] = new_src;
        }

        // Modify destination MAC
        if (address_mapping.count(previous_dst) > 0) {
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
    }
};
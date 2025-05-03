#pragma once

#include "Packet.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "PayloadLayer.h"
#include "PcapFileDevice.h"
#include "IpAddress.h"
#include "packet.cpp"
#include "header.cpp"

#include <openssl/md5.h>
#include <unordered_map>
#include <string>
#include <sstream>
#include <iomanip>

class IPPacket : public EtherPacket {
public:
    IPPacket(pcpp::Packet& packet,
             std::unordered_map<std::string, std::string> addressMapping = {},
             std::unordered_map<std::string, bool> layerMap = {})
        : EtherPacket(packet, addressMapping, layerMap)
    {
        if (layerMap.count("IPv4")) {
            filterIPv4();
            auto ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
            std::string hashInput = std::to_string(ipLayer->getIPv4Header()->ipVersion) + "," +
                                    std::to_string(ipLayer->getIPv4Header()->fragmentOffset) + "," +
                                    std::to_string(ipLayer->getIPv4Header()->protocol);
            computeHash(hashInput);

            if (layerMap.count("TLS") && !(layerMap.count("TCP") || layerMap.count("UDP")))
                ipLayer->getLayerPayload()[0] = '\0'; // Remove payload (example)

            if (layerMap.count("Raw") && !(layerMap.count("TCP") || layerMap.count("UDP") || layerMap.count("HTTP")))
                ipLayer->getLayerPayload()[0] = '\0';
        }
        else if (layerMap.count("IPv6")) {
            filterIPv6();
            auto ip6Layer = packet.getLayerOfType<pcpp::IPv6Layer>();
            std::string hashInput = std::to_string(ip6Layer->getIPv6Header()->ipVersion) + "," +
                                    std::to_string(ip6Layer->getIPv6Header()->trafficClass) + "," +
                                    std::to_string(ip6Layer->getIPv6Header()->hopLimit);
            computeHash(hashInput);

            if (layerMap.count("TLS") && !(layerMap.count("TCP") || layerMap.count("UDP")))
                ip6Layer->getLayerPayload()[0] = '\0';

            if (layerMap.count("Raw") && !(layerMap.count("TCP") || layerMap.count("UDP") || layerMap.count("HTTP")))
                ip6Layer->getLayerPayload()[0] = '\0';
        }
    }

    void header_preprocessing() override {
        if (layer_map.count("IPv4")) {
            pcpp::IPv4Layer* ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
            if (ipLayer == nullptr)
                return;  // nothing to do

            // 2) Build our custom header
            CustomIPLayer* customLayer = header_preprocessing_ipv4(ipLayer);

            // 3) Extract original payload (if any)
            size_t payloadLen = ipLayer->getLayerPayloadSize();
            const uint8_t* payload = ipLayer->getLayerPayload();

            // 4) Remove the old IPv4 layer
            packet.removeLayer(pcpp::IPv4);

            // 5) Insert custom header 
            packet.insertLayer(getLayerBeforeIPv4(packet), customLayer);

            // 6) Re-attach original payload
            if (payloadLen > 0) {
                pcpp::PayloadLayer* payloadLayer = new pcpp::PayloadLayer(payload, payloadLen);
                packet.insertLayer(packet.getLayerOfType<pcpp::IPv4Layer>(), payloadLayer);
            }

            // 7) Recompute lengths and checksums downstream
            packet.computeCalculateFields();
        }
    
        if (layer_map.count("IPv6")) {
            pcpp::IPv6Layer* ipLayer = packet.getLayerOfType<pcpp::IPv6Layer>();
            if (ipLayer == nullptr)
                return;  // nothing to do

            // 2) Build our custom header
            CustomIPv6Layer* customLayer = header_preprocessing_ipv6(ipLayer);

            // 3) Extract original payload (if any)
            size_t payloadLen = ipLayer->getLayerPayloadSize();
            const uint8_t* payload = ipLayer->getLayerPayload();

            // 4) Remove the old IPv4 layer
            packet.removeLayer(pcpp::IPv6);

            // 5) Insert custom header 
            packet.insertLayer(getLayerBeforeIPv6(packet), customLayer);

            // 6) Re-attach original payload
            if (payloadLen > 0) {
                pcpp::PayloadLayer* payloadLayer = new pcpp::PayloadLayer(payload, payloadLen);
                packet.insertLayer(packet.getLayerOfType<pcpp::IPv6Layer>(), payloadLayer);
            }

            // 7) Recompute lengths and checksums downstream
            packet.computeCalculateFields();
        }
    
        // Call base class preprocessing
        EtherPacket::header_preprocessing();
    }

    // Functio to find the layer immediately preceding the IPv4 layer
    pcpp::Layer* getLayerBeforeIPv4(const pcpp::Packet& packet) {
        pcpp::Layer* previous = nullptr;
        for (pcpp::Layer* layer = packet.getFirstLayer(); layer != nullptr; layer = layer->getNextLayer()) {
            if (layer->getProtocol() == pcpp::IPv4) {
                return previous;
            }
            previous = layer;
        }
        return nullptr;
    };

    CustomIPLayer* header_preprocessing_ipv4(pcpp::IPv4Layer* ipLayer) {
        auto hdr = ipLayer->getIPv4Header();
        uint8_t version = hdr->ipVersion;
        uint16_t fragOffset = ntohs(hdr->fragmentOffset);
        uint8_t flags = static_cast<uint8_t>((fragOffset >> 13) & 0x07);
        return new CustomIPLayer(version,
                                       flags,
                                       hdr->typeOfService,
                                       hdr->timeToLive,
                                       hdr->protocol);
    }

    // Function to find the layer immediately preceding the IPv6 layer
    pcpp::Layer* getLayerBeforeIPv6(const pcpp::Packet& packet) {
        pcpp::Layer* previous = nullptr;
        for (pcpp::Layer* layer = packet.getFirstLayer(); layer != nullptr; layer = layer->getNextLayer()) {
            if (layer->getProtocol() == pcpp::IPv6) {
                return previous;
            }
            previous = layer;
        }
        return nullptr;
    };

    CustomIPv6Layer* header_preprocessing_ipv6(pcpp::IPv6Layer* ipv6Layer) {
        return new CustomIPv6Layer(
            ipv6Layer->getIPv6Header()->ipVersion,
            ipv6Layer->getIPv6Header()->trafficClass,
            ipv6Layer->getIPv6Header()->nextHeader,
            ipv6Layer->getIPv6Header()->hopLimit
        );
    }


private:
    void computeHash(const std::string& input) {
        unsigned char result[MD5_DIGEST_LENGTH];
        MD5(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result);

        std::ostringstream oss;
        for (int i = 0; i < MD5_DIGEST_LENGTH; ++i)
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)result[i];

        hash = oss.str();
    }

    void filterIPv4() {
        auto ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
        std::string src = ipLayer->getSrcIPAddress().toString();
        std::string dst = ipLayer->getDstIPAddress().toString();

        std::string newSrc = mapAddress(src, true);
        std::string newDst = mapAddress(dst, false);

        ipLayer->setSrcIPv4Address(pcpp::IPv4Address(newSrc));
        ipLayer->setDstIPv4Address(pcpp::IPv4Address(newDst));
    }

    void filterIPv6() {
        auto ip6Layer = packet.getLayerOfType<pcpp::IPv6Layer>();
        std::string src = ip6Layer->getSrcIPAddress().toString();
        std::string dst = ip6Layer->getDstIPAddress().toString();

        std::string newSrc = mapAddress(src, true, true);
        std::string newDst = mapAddress(dst, false, true);

        ip6Layer->setSrcIPv6Address(pcpp::IPv6Address(newSrc));
        ip6Layer->setDstIPv6Address(pcpp::IPv6Address(newDst));
    }

    std::string mapAddress(const std::string& oldAddr, bool isSrc, bool isIPv6 = false) {
        if (address_mapping.count(oldAddr))
            return address_mapping[oldAddr];

        std::string newAddr = isIPv6 ? generateRandomIPv6() : generateRandomIPv4();
        address_mapping[oldAddr] = newAddr;
        return newAddr;
    }

    std::string generateRandomIPv4() {
        std::srand(static_cast<unsigned int>(std::time(nullptr))); // Seed the random number generator
    
        std::string ip;
        for (int i = 0; i < 4; ++i) {
            int octet = std::rand() % 256; // Generates a number between 0 and 255
            ip += std::to_string(octet);
            if (i < 3) ip += ".";
        }
        return ip;
    }

    std::string generateRandomIPv6() {
        std::srand(static_cast<unsigned int>(std::time(nullptr))); // Seed RNG
    
        std::ostringstream oss;
        for (int i = 0; i < 8; ++i) {
            int block = std::rand() % 0x10000; // Generate a 16-bit block (0–65535)
            oss << std::hex << std::setw(4) << std::setfill('0') << block;
            if (i < 7) oss << ":";
        }
    
        return oss.str();
    }

    std::string hash;
};
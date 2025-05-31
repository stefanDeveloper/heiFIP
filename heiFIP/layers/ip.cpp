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

#include <iostream>
#include <unordered_map>
#include <string>
#include <sstream>
#include <iomanip>

class IPPacket : public EtherPacket {
public:
    IPPacket(const pcpp::RawPacket& packet,
             std::unordered_map<std::string, std::string> addressMapping = {},
             std::unordered_map<std::string, bool> layerMap = {})
        : EtherPacket(packet, addressMapping, layerMap)
    {
        if (layerMap.count("IPv4")) {
            filterIPv4();
            pcpp::Packet temporaryPacket = pcpp::Packet(getRawPacket().get());
            auto ipLayer = temporaryPacket.getLayerOfType<pcpp::IPv4Layer>();
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
            pcpp::Packet temporaryPacket = pcpp::Packet(getRawPacket().get());
            auto ip6Layer = temporaryPacket.getLayerOfType<pcpp::IPv6Layer>();
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
            // 1) Find the TCP layer you want to replace
            pcpp::Packet temporaryPacket = pcpp::Packet(getRawPacket().get());
            pcpp::IPv4Layer* oldIp = temporaryPacket.getLayerOfType<pcpp::IPv4Layer>();
            if (!oldIp) return;  

            pcpp::Layer* prev = oldIp->getPrevLayer();
            
            // 4) Now safely remove the old TCP layer object
            temporaryPacket.detachLayer(oldIp);

            // 2) Create your replacement CustomTCPLayer* customTcp = header_preprocessing_tcp(oldTcp);
            CustomIPLayer* customLayer = header_preprocessing_ipv4(oldIp);
            delete oldIp;

            // 3) Insert your custom TCP layer right after whatever came before the old one
            temporaryPacket.insertLayer(prev, customLayer, true);

            // 5) If your new layer changed any length/checksum fields upstream,
            //    recompute them on the packet
            temporaryPacket.computeCalculateFields();
            const uint8_t* modifiedData = temporaryPacket.getRawPacket()->getRawData();
            int modifiedDataLen = temporaryPacket.getRawPacket()->getRawDataLen();
            timespec ts = temporaryPacket.getRawPacket()->getPacketTimeStamp();
            pcpp::LinkLayerType linkType = temporaryPacket.getRawPacket()->getLinkLayerType();

            uint8_t* dataCopy = new uint8_t[modifiedDataLen];
            std::memcpy(dataCopy, modifiedData, modifiedDataLen);

            // 6) Replace the RawPacket in FIPPacket
            setRawPacket(std::make_unique<pcpp::RawPacket>(dataCopy, modifiedDataLen, ts, false, linkType));
        }
    
        if (layer_map.count("IPv6")) {
            // 1) Find the TCP layer you want to replace
            pcpp::Packet temporaryPacket = pcpp::Packet(getRawPacket().get());
            pcpp::IPv6Layer* oldIp = temporaryPacket.getLayerOfType<pcpp::IPv6Layer>();
            if (!oldIp) return;  

            // 2) Create your replacement CustomTCPLayer* customTcp = header_preprocessing_tcp(oldTcp);
            CustomIPv6Layer* customLayer = header_preprocessing_ipv6(oldIp);

            // 3) Insert your custom TCP layer right after whatever came before the old one
            pcpp::Layer* prev = oldIp->getPrevLayer();  
            temporaryPacket.insertLayer(prev, customLayer);

            // 4) Now safely remove the old TCP layer object
            temporaryPacket.detachLayer(oldIp);
            delete oldIp;

            // 5) If your new layer changed any length/checksum fields upstream,
            //    recompute them on the packet
            temporaryPacket.computeCalculateFields();
            const uint8_t* modifiedData = temporaryPacket.getRawPacket()->getRawData();
            int modifiedDataLen = temporaryPacket.getRawPacket()->getRawDataLen();
            timespec ts = temporaryPacket.getRawPacket()->getPacketTimeStamp();
            pcpp::LinkLayerType linkType = temporaryPacket.getRawPacket()->getLinkLayerType();

            uint8_t* dataCopy = new uint8_t[modifiedDataLen];
            std::memcpy(dataCopy, modifiedData, modifiedDataLen);

            // 6) Replace the RawPacket in FIPPacket
            setRawPacket(std::make_unique<pcpp::RawPacket>(dataCopy, modifiedDataLen, ts, false, linkType));
        }
    
        // Call base class preprocessing
        EtherPacket::header_preprocessing();
    }

    // Functio to find the layer immediately preceding the IPv4 layer
    pcpp::Layer* getLayerBeforeIPv4(const pcpp::Packet& packet) {
        pcpp::Layer* previous = nullptr;
        for (pcpp::Layer* layer = packet.getFirstLayer(); layer != nullptr; layer = layer->getNextLayer()) {
            std::cout << "Layer: " << layer->toString();
            if (layer->getProtocol() == pcpp::IPv4) {
                return previous;
            }
            previous = layer;
        }
        return nullptr;
    };

    CustomIPLayer* header_preprocessing_ipv4(pcpp::IPv4Layer* ipLayer) {
        pcpp::iphdr* hdr = ipLayer->getIPv4Header();
        uint8_t version = hdr->ipVersion;
        uint16_t fragOffset = ntohs(hdr->fragmentOffset);
        uint8_t flags = static_cast<uint8_t>((fragOffset >> 13) & 0x07);
        return new CustomIPLayer(version, flags, hdr->typeOfService, hdr->timeToLive, hdr->protocol);
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
        unsigned char result[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result);

        std::ostringstream oss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)result[i];

        hash = oss.str();
    }

    void filterIPv4() {
        pcpp::Packet temporaryPacket = pcpp::Packet(getRawPacket().get());
        auto ipLayer = temporaryPacket.getLayerOfType<pcpp::IPv4Layer>();
        std::string src = ipLayer->getSrcIPAddress().toString();
        std::string dst = ipLayer->getDstIPAddress().toString();

        std::string newSrc = mapAddress(src);
        std::string newDst = mapAddress(dst);

        ipLayer->setSrcIPv4Address(pcpp::IPv4Address(newSrc));
        ipLayer->setDstIPv4Address(pcpp::IPv4Address(newDst));
    }

    void filterIPv6() {
        pcpp::Packet temporaryPacket = pcpp::Packet(getRawPacket().get());
        auto ip6Layer = temporaryPacket.getLayerOfType<pcpp::IPv6Layer>();
        std::string src = ip6Layer->getSrcIPAddress().toString();
        std::string dst = ip6Layer->getDstIPAddress().toString();

        std::string newSrc = mapAddress(src, true);
        std::string newDst = mapAddress(dst, true);

        ip6Layer->setSrcIPv6Address(pcpp::IPv6Address(newSrc));
        ip6Layer->setDstIPv6Address(pcpp::IPv6Address(newDst));
    }

    std::string mapAddress(const std::string& oldAddr, bool isIPv6 = false) {
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
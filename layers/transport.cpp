#pragma once

#include "Packet.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "PayloadLayer.h"
#include "IPv4Layer.h"
#include "HttpLayer.h"

#include "header.cpp"
#include "ip.cpp"
#include "packet.cpp"

#include <openssl/md5.h>
#include <sstream>
#include <iomanip>

class TransportPacket : public IPPacket {

    public:
    std::string hash;

    TransportPacket(pcpp::Packet& packet,
        std::unordered_map<std::string, std::string> addressMapping = {},
        std::unordered_map<std::string, bool> layerMap = {})
        : IPPacket(packet, addressMapping, layerMap)
        {
        if (layerMap["TCP"]) {
            // Get the TCP layer
            pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
            if (tcpLayer != nullptr) {
                // Compute hash using TCP flags and options count
                pcpp::tcphdr* tcpHeader = tcpLayer->getTcpHeader();
                uint8_t flags = 0;
                if (tcpHeader->synFlag) flags |= 0x02;
                if (tcpHeader->ackFlag) flags |= 0x10;
                if (tcpHeader->finFlag) flags |= 0x01;
                if (tcpHeader->rstFlag) flags |= 0x04;
                if (tcpHeader->pshFlag) flags |= 0x08;
                if (tcpHeader->urgFlag) flags |= 0x20;
                if (tcpHeader->eceFlag) flags |= 0x40;
                if (tcpHeader->cwrFlag) flags |= 0x80;

                int optionsCount = tcpLayer->getTcpOptionCount();

                // Create hash
                std::ostringstream oss;
                oss << static_cast<int>(flags) << "," << optionsCount;
                std::string hashInput = oss.str();

                // Hash it using OpenSSL MD5
                unsigned char digest[MD5_DIGEST_LENGTH];
                MD5(reinterpret_cast<const unsigned char*>(hashInput.c_str()), hashInput.length(), digest);

                std::ostringstream hashStream;
                for (int i = 0; i < MD5_DIGEST_LENGTH; ++i)
                    hashStream << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
                hash = hashStream.str();

                // Remove the payload if certain layers are present
                if (layerMap["TLS"] || (layerMap["Raw"] && !layerMap["HTTP"])) {

                        pcpp::TcpLayer newTcpLayer = pcpp::TcpLayer(*packet.getLayerOfType<pcpp::TcpLayer>());
                        // Reconstruct the packet with the new TCP header

                        packet.removeLayer(pcpp::TCP);
                        packet.addLayer(&newTcpLayer);
                        packet.computeCalculateFields();
                }
            }
        } else if (layerMap["UDP"]) {
            pcpp::UdpLayer* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
            if (udpLayer != nullptr) {
                std::string layerName = "UDP";
                hash = md5Hash(layerName);

                if (layerMap["TLS"] || (layerMap["Raw"] && !layerMap["HTTP"])) {
                    pcpp::UdpLayer newTcpLayer = pcpp::UdpLayer(*packet.getLayerOfType<pcpp::UdpLayer>());
                    // Reconstruct the packet with the new TCP header

                    packet.removeLayer(pcpp::UDP);
                    packet.addLayer(&newTcpLayer);
                    packet.computeCalculateFields();
                }
            }
        }
    }

    std::function<pcpp::Layer*(const pcpp::Packet&)> getLayerBeforeTCP = [](const pcpp::Packet& packet) {
        pcpp::Layer* prev = nullptr;
        for (pcpp::Layer* lyr = packet.getFirstLayer(); lyr; lyr = lyr->getNextLayer()) {
            if (lyr->getProtocol() == pcpp::TCP)
                return prev;
            prev = lyr;
        }
        return (pcpp::Layer*)nullptr;
    };

    std::function<pcpp::Layer*(const pcpp::Packet&)> getLayerBeforeUDP = [](const pcpp::Packet& packet) {
        pcpp::Layer* prev = nullptr;
        for (pcpp::Layer* lyr = packet.getFirstLayer(); lyr; lyr = lyr->getNextLayer()) {
            if (lyr->getProtocol() == pcpp::UDP)
                return prev;
            prev = lyr;
        }
        return (pcpp::Layer*)nullptr;
    };
    

    void header_preprocessing()
    {
        // Process the TCP layer if it exists
        if (layer_map["TCP"]) {
            pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
            if (tcpLayer == nullptr)
                return;  // nothing to do

            // 2) Build our custom header
            CustomTCPLayer* customLayer = header_preprocessing_tcp(tcpLayer);

            // 3) Extract original payload (if any)
            size_t payloadLen = tcpLayer->getLayerPayloadSize();
            const uint8_t* payload = tcpLayer->getLayerPayload();

            // 4) Remove the old IPv4 layer
            packet.removeLayer(pcpp::TCP);

            // 5) Insert custom header 
            packet.insertLayer(getLayerBeforeTCP(packet), customLayer);

            // 6) Re-attach original payload
            if (payloadLen > 0) {
                pcpp::PayloadLayer* payloadLayer = new pcpp::PayloadLayer(payload, payloadLen);
                packet.insertLayer(packet.getLayerOfType<pcpp::TcpLayer>(), payloadLayer);
            }

            // 7) Recompute lengths and checksums downstream
            packet.computeCalculateFields();
        }
    
        // Process the UDP layer if it exists
        if (layer_map["UDP"]) {
            pcpp::UdpLayer* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
            if (udpLayer == nullptr)
                return;  // nothing to do

            // 2) Build our custom header
            CustomUDPLayer* customLayer = header_preprocessing_udp(udpLayer);

            // 3) Extract original payload (if any)
            size_t payloadLen = udpLayer->getLayerPayloadSize();
            const uint8_t* payload = udpLayer->getLayerPayload();

            // 4) Remove the old IPv4 layer
            packet.removeLayer(pcpp::UDP);

            // 5) Insert custom header 
            packet.insertLayer(getLayerBeforeUDP(packet), customLayer);

            // 6) Re-attach original payload
            if (payloadLen > 0) {
                pcpp::PayloadLayer* payloadLayer = new pcpp::PayloadLayer(payload, payloadLen);
                packet.insertLayer(packet.getLayerOfType<pcpp::TcpLayer>(), payloadLayer);
            }

            // 7) Recompute lengths and checksums downstream
            packet.computeCalculateFields();
        }
    
        // Call the base class's header_preprocessing method
        IPPacket::header_preprocessing();  // Assuming this is your parent class
    }
    
    CustomTCPLayer* header_preprocessing_tcp(pcpp::TcpLayer* tcpLayer) {
        auto hdr = tcpLayer->getTcpHeader();
        // Manually extract TCP flags from individual bit fields
        uint16_t flags = 0;
        if (hdr->finFlag) flags |= 0x01;
        if (hdr->synFlag) flags |= 0x02;
        if (hdr->rstFlag) flags |= 0x04;
        if (hdr->pshFlag) flags |= 0x08;
        if (hdr->ackFlag) flags |= 0x10;
        if (hdr->urgFlag) flags |= 0x20;
        if (hdr->eceFlag) flags |= 0x40;
        if (hdr->cwrFlag) flags |= 0x80;
        // Extract raw options bytes (if any)
        size_t optLen = tcpLayer->getHeaderLen() - sizeof(*hdr);
        const uint8_t* optPtr = reinterpret_cast<const uint8_t*>(hdr) + sizeof(*hdr);
        std::vector<uint8_t> options(optPtr, optPtr + optLen);
        return new CustomTCPLayer(flags, options);
    }

    CustomUDPLayer* header_preprocessing_udp(pcpp::UdpLayer* udpLayer) {
        return new CustomUDPLayer();
    }

    private:
        std::string md5Hash(const std::string& input) {
            unsigned char digest[MD5_DIGEST_LENGTH];
            MD5(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), digest);

            std::ostringstream oss;
            for (int i = 0; i < MD5_DIGEST_LENGTH; ++i)
                oss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
            return oss.str();
        }
};
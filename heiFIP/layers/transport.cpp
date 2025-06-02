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

#include <sstream>
#include <iomanip>

class TransportPacket : public IPPacket {

    public:
    std::string hash;

    TransportPacket(std::unique_ptr<pcpp::RawPacket> rawPacketPointer,
        std::unordered_map<std::string, std::string> addressMapping = {},
        std::unordered_map<std::string, bool> layerMap = {})
        : IPPacket(std::move(rawPacketPointer), addressMapping, layerMap)
        {
        if (layerMap["TCP"]) {
            // Get the TCP layer
            pcpp::TcpLayer* tcpLayer = Packet.getLayerOfType<pcpp::TcpLayer>();
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
                unsigned char digest[SHA256_DIGEST_LENGTH];
                SHA256(reinterpret_cast<const unsigned char*>(hashInput.c_str()), hashInput.length(), digest);

                std::ostringstream hashStream;
                for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
                    hashStream << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
                hash = hashStream.str();

                // Remove the payload if certain layers are present
                if (layerMap["TLS"] || (layerMap["Raw"] && !layerMap["HTTP"])) {
                    pcpp::TcpLayer* tcpLayer = Packet.getLayerOfType<pcpp::TcpLayer>();
                    if (!tcpLayer) return;  // no TCP → nothing to strip

                    // 2) Walk ahead from tcpLayer->getNextLayer(), 
                    //    detaching & deleting until the end of the chain.
                    pcpp::Layer* next = tcpLayer->getNextLayer();
                    while (next) {
                        pcpp::Layer* toRemove = next;
                        next = next->getNextLayer();   // advance first

                        // Detach + delete the layer
                        Packet.detachLayer(toRemove);
                        delete toRemove;
                    }

                    // 3) Now that all downstream layers are gone, 
                    //    we should recompute lengths/checksums on the remaining headers:
                    Packet.computeCalculateFields();
                }
            }
        } else if (layerMap["UDP"]) {
            pcpp::UdpLayer* udpLayer = Packet.getLayerOfType<pcpp::UdpLayer>();
            if (udpLayer != nullptr) {
                std::string layerName = "UDP";
                hash = md5Hash(layerName);

                if (layerMap["TLS"] || (layerMap["Raw"] && !layerMap["HTTP"])) {
                    pcpp::UdpLayer* udpLayer = Packet.getLayerOfType<pcpp::UdpLayer>();
                    if (!udpLayer) return;  // no TCP → nothing to strip

                    // 2) Walk ahead from tcpLayer->getNextLayer(), 
                    //    detaching & deleting until the end of the chain.
                    pcpp::Layer* next = udpLayer->getNextLayer();
                    while (next) {
                        pcpp::Layer* toRemove = next;
                        next = next->getNextLayer();   // advance first

                        // Detach + delete the layer
                        Packet.detachLayer(toRemove);
                        delete toRemove;
                    }

                    // 3) Now that all downstream layers are gone, 
                    //    we should recompute lengths/checksums on the remaining headers:
                    Packet.computeCalculateFields();
                }
            }
        }
    }

    pcpp::Layer* getLayerBeforeTCP(const pcpp::Packet& packet) {
        pcpp::Layer* prev = nullptr;
        for (pcpp::Layer* lyr = packet.getFirstLayer(); lyr; lyr = lyr->getNextLayer()) {
            if (lyr->getProtocol() == pcpp::TCP) {
                return prev;
            }
            prev = lyr;
        }
        return (pcpp::Layer*)nullptr;
    };

    pcpp::Layer* getLayerBeforeUDP(const pcpp::Packet& packet) {
        pcpp::Layer* prev = nullptr;
        for (pcpp::Layer* lyr = packet.getFirstLayer(); lyr; lyr = lyr->getNextLayer()) {
            if (lyr->getProtocol() == pcpp::UDP) {
                return prev;
            }
            prev = lyr;
        }
        return (pcpp::Layer*)nullptr;
    };
    

    void header_preprocessing()
    {
        // Process the TCP layer if it exists
        if (layer_map["TCP"]) {
            // 1) Find the TCP layer you want to replace
            pcpp::TcpLayer* oldTcp = Packet.getLayerOfType<pcpp::TcpLayer>();
            if (!oldTcp) { 
                return;  
            }

            // 2) Create your replacement CustomTCPLayer* customTcp = header_preprocessing_tcp(oldTcp);
            std::unique_ptr<CustomTCPLayer> customLayer = header_preprocessing_tcp(oldTcp);

            // 3) Insert your custom TCP layer right after whatever came before the old one
            pcpp::Layer* prev = oldTcp->getPrevLayer();  
            Packet.insertLayer(prev, customLayer.release());

            // 4) Now safely remove the old TCP layer object
            Packet.detachLayer(oldTcp);
            delete oldTcp;

            // 5) If your new layer changed any length/checksum fields upstream,
            //    recompute them on the packet
            Packet.computeCalculateFields();
        }
    
        // Process the UDP layer if it exists
        if (layer_map["UDP"]) {
            // 1) Find the TCP layer you want to replace
            pcpp::UdpLayer* oldUdp = Packet.getLayerOfType<pcpp::UdpLayer>();
            if (!oldUdp) return;  

            // 2) Create your replacement CustomTCPLayer* customTcp = header_preprocessing_tcp(oldTcp);
            std::unique_ptr<CustomUDPLayer> customLayer = header_preprocessing_udp(oldUdp);

            // 3) Insert your custom TCP layer right after whatever came before the old one
            pcpp::Layer* prev = oldUdp->getPrevLayer();  
            Packet.insertLayer(prev, customLayer.release());

            // 4) Now safely remove the old TCP layer object
            Packet.detachLayer(oldUdp);
            delete oldUdp;

            // 5) If your new layer changed any length/checksum fields upstream,
            //    recompute them on the packet
            Packet.computeCalculateFields();
        }
    
        // Call the base class's header_preprocessing method
        IPPacket::header_preprocessing();  // Assuming this is your parent class
    }
    
    std::unique_ptr<CustomTCPLayer> header_preprocessing_tcp(pcpp::TcpLayer* tcpLayer) {
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
        return std::make_unique<CustomTCPLayer>(flags, options);
    }

    std::unique_ptr<CustomUDPLayer> header_preprocessing_udp(pcpp::UdpLayer* udpLayer) {
        return std::make_unique<CustomUDPLayer>();
    }

    private:
        std::string md5Hash(const std::string& input) {
            unsigned char digest[SHA256_DIGEST_LENGTH];
            SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), digest);

            std::ostringstream oss;
            for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
                oss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
            return oss.str();
        }
};
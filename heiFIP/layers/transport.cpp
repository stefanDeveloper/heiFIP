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

    TransportPacket(const pcpp::RawPacket& packet,
        std::unordered_map<std::string, std::string> addressMapping = {},
        std::unordered_map<std::string, bool> layerMap = {})
        : IPPacket(packet, addressMapping, layerMap)
        {
        if (layerMap["TCP"]) {
            // Get the TCP layer
            pcpp::Packet temporaryPacket = pcpp::Packet(getRawPacket().get());
            pcpp::TcpLayer* tcpLayer = temporaryPacket.getLayerOfType<pcpp::TcpLayer>();
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

                        pcpp::TcpLayer newTcpLayer = pcpp::TcpLayer(*(temporaryPacket).getLayerOfType<pcpp::TcpLayer>());
                        // Reconstruct the packet with the new TCP header
                        temporaryPacket.removeLayer(pcpp::TCP);
                        temporaryPacket.addLayer(&newTcpLayer);
                        temporaryPacket.computeCalculateFields();

                        // 3. Deep copy the modified raw data
                        const uint8_t* modifiedData = temporaryPacket.getRawPacket()->getRawData();
                        int modifiedDataLen = temporaryPacket.getRawPacket()->getRawDataLen();
                        timespec ts = temporaryPacket.getRawPacket()->getPacketTimeStamp();
                        pcpp::LinkLayerType linkType = temporaryPacket.getRawPacket()->getLinkLayerType();

                        uint8_t* dataCopy = new uint8_t[modifiedDataLen];
                        std::memcpy(dataCopy, modifiedData, modifiedDataLen);

                        // 4. Replace the RawPacket in FIPPacket
                        setRawPacket(std::make_unique<pcpp::RawPacket>(dataCopy, modifiedDataLen, ts, false, linkType));
                }
            }
        } else if (layerMap["UDP"]) {
            pcpp::Packet temporaryPacket = pcpp::Packet(getRawPacket().get());
            pcpp::UdpLayer* udpLayer = temporaryPacket.getLayerOfType<pcpp::UdpLayer>();
            if (udpLayer != nullptr) {
                std::string layerName = "UDP";
                hash = md5Hash(layerName);

                if (layerMap["TLS"] || (layerMap["Raw"] && !layerMap["HTTP"])) {
                    pcpp::UdpLayer newTcpLayer = pcpp::UdpLayer(*temporaryPacket.getLayerOfType<pcpp::UdpLayer>());
                    // Reconstruct the packet with the new TCP header

                    temporaryPacket.removeLayer(pcpp::UDP);
                    temporaryPacket.addLayer(&newTcpLayer);
                    temporaryPacket.computeCalculateFields();

                    // 3. Deep copy the modified raw data
                    const uint8_t* modifiedData = temporaryPacket.getRawPacket()->getRawData();
                    int modifiedDataLen = temporaryPacket.getRawPacket()->getRawDataLen();
                    timespec ts = temporaryPacket.getRawPacket()->getPacketTimeStamp();
                    pcpp::LinkLayerType linkType = temporaryPacket.getRawPacket()->getLinkLayerType();

                    uint8_t* dataCopy = new uint8_t[modifiedDataLen];
                    std::memcpy(dataCopy, modifiedData, modifiedDataLen);

                    // 4. Replace the RawPacket in FIPPacket
                    setRawPacket(std::make_unique<pcpp::RawPacket>(dataCopy, modifiedDataLen, ts, false, linkType));
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
            pcpp::Packet temporaryPacket = pcpp::Packet(getRawPacket().get());
            pcpp::TcpLayer* oldTcp = temporaryPacket.getLayerOfType<pcpp::TcpLayer>();
            if (!oldTcp) { 
                return;  
            }

            // 2) Create your replacement CustomTCPLayer* customTcp = header_preprocessing_tcp(oldTcp);
            CustomTCPLayer* customLayer = header_preprocessing_tcp(oldTcp);

            // 3) Insert your custom TCP layer right after whatever came before the old one
            pcpp::Layer* prev = oldTcp->getPrevLayer();  
            temporaryPacket.insertLayer(prev, customLayer);

            // 4) Now safely remove the old TCP layer object
            temporaryPacket.detachLayer(oldTcp);
            delete oldTcp;

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
    
        // Process the UDP layer if it exists
        if (layer_map["UDP"]) {
            // 1) Find the TCP layer you want to replace
            pcpp::Packet temporaryPacket = pcpp::Packet(getRawPacket().get());
            pcpp::UdpLayer* oldUdp = temporaryPacket.getLayerOfType<pcpp::UdpLayer>();
            if (!oldUdp) return;  

            // 2) Create your replacement CustomTCPLayer* customTcp = header_preprocessing_tcp(oldTcp);
            CustomUDPLayer* customLayer = header_preprocessing_udp(oldUdp);

            // 3) Insert your custom TCP layer right after whatever came before the old one
            pcpp::Layer* prev = oldUdp->getPrevLayer();  
            temporaryPacket.insertLayer(prev, customLayer);

            // 4) Now safely remove the old TCP layer object
            temporaryPacket.detachLayer(oldUdp);
            delete oldUdp;

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
            unsigned char digest[SHA256_DIGEST_LENGTH];
            SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), digest);

            std::ostringstream oss;
            for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
                oss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
            return oss.str();
        }
};
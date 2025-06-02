#pragma once
#include <vector>
#include <string>
#include <iostream>
#include <unordered_set>
#include <PcapFileDevice.h>
#include <Packet.h>
#include "packet.cpp"
#include "dns.cpp"
#include "http.cpp"
#include "ip.cpp"
#include "ssh.cpp"
#include "transport.cpp"
#include <memory>


enum class SupportedHeaderType {
    IP,
    IPv6,
    DNS,
    HTTP_REQUEST,
    HTTP_RESPONSE,
    TCP,
    UDP
};

/**
 * List of supported headers in processing order.
 */
static const std::vector<SupportedHeaderType> SUPPORTED_HEADERS = {
    SupportedHeaderType::IP,
    SupportedHeaderType::IPv6,
    SupportedHeaderType::DNS,
    SupportedHeaderType::HTTP_REQUEST,
    SupportedHeaderType::HTTP_RESPONSE,
    SupportedHeaderType::TCP,
    SupportedHeaderType::UDP
};

/**
 * PacketProcessorType indicates whether processing is active,
 * and at what level (NONE or HEADER).
 */
enum class PacketProcessorType {
    NONE = 1,
    HEADER = 2
};

/**
 * PacketProcessor orchestrates per-packet handling across supported protocols,
 * accumulates packets, and can write them out to a PCAP file.
 */
class PacketProcessor {
    public:
        /**
         * Constructor initializes internal state.
         * @param fileExtension expected file extension (e.g., "pcap" or "pcapng").
         */
        PacketProcessor(const std::string& fileExtension = "pcap")
            : fileExtension(fileExtension)
        {
            // TLS session layer is available via PcapPlusPlus's TLSSessionLayer plugin.
            // No explicit runtime load is required—just link against the TLS parsing library.
        }
    
        /**
         * Add a parsed packet to the internal buffer to be written later.
         */
        void addPacket(pcpp::Packet* packet) {
            packets.push_back(packet);
        }
    
        /**
         * Write all buffered packets to a PCAP file.
         * @param baseFilename name without extension; "_converted.pcap" will be appended.
         */
        void writePackets(const std::string& baseFilename) {
            std::string outName = baseFilename + "_converted.pcap";
            pcpp::PcapFileWriterDevice writer(outName, pcpp::LINKTYPE_ETHERNET);
            if (!writer.open()) {
                // Unable to open output file
                return;
            }
            for (pcpp::Packet* pkt : packets) {
                writer.writePacket(*(pkt->getRawPacket()));
            }
            writer.close();
        }

    /**
     * Read packets from a PCAP file, preprocess them, and return FIPPacket pointers.
     * @param filename path to the PCAP file
     * @param type preprocessing type (NONE or HEADER)
     * @param maxCount maximum number of packets to read (default 64)
     */
    std::vector<std::unique_ptr<FIPPacket>> readPacketsFile(const std::string& filename, PacketProcessorType type, 
        bool removeDuplicates = false, size_t maxCount = 64) {
        
        std::vector<std::unique_ptr<FIPPacket>> result;
        pcpp::PcapFileReaderDevice reader(filename);
        
        if (!reader.open()) { 
            return result;
        }

        pcpp::RawPacket rawPacket;
        std::unique_ptr<pcpp::RawPacket> rawPacketPt;
        size_t count = 0;

        while (count < maxCount && reader.getNextPacket(rawPacket)) {
            rawPacketPt = std::make_unique<pcpp::RawPacket>(rawPacket);
            std::unique_ptr<FIPPacket> fippkt = preprocess(rawPacketPt, type);

            if (fippkt && !fippkt->getHash().empty()) {
                auto res = hashDict.insert(fippkt->getHash());
                if (res.second) { // was inserted, new
                    result.push_back(std::move(fippkt));
                } else {
                    // This case occurs if two packets are the same (have the same hash value)
                    // which results in the packet not being used if remove_duplicates is set
                    if (!removeDuplicates) {
                        result.push_back(std::move(fippkt));
                    } else {
                        std::cout << "[-] Warning: Duplicate packet with hash value " << fippkt->getHash() << " removed" << std::endl;
                    }
                }
            } else if (fippkt) {
                result.push_back(std::move(fippkt));
            }

            ++count;
        }
        reader.close();
        return result;
    }

    std::vector<std::unique_ptr<FIPPacket>> readPacketsList(std::vector<std::unique_ptr<pcpp::RawPacket>>& inputPackets,
    PacketProcessorType type, bool removeDuplicates = false) {    
        std::vector<std::unique_ptr<FIPPacket>> result;
        for (std::unique_ptr<pcpp::RawPacket>& pktPtr : inputPackets) {
            std::unique_ptr<FIPPacket> fippkt = preprocess(pktPtr, type);
            if (!fippkt) {continue;}

            if (!fippkt->getHash().empty()) {
                auto res = hashDict.insert(fippkt->getHash());
                if (res.second) {
                result.push_back(std::move(fippkt));
                } else {
                    // This case occurs if two packets are the same (have the same hash value)
                    // which results in the packet not being used if remove_duplicates is set
                    if (!removeDuplicates) {
                        result.push_back(std::move(fippkt));
                    } else {
                        std::cout << "[-] Warning: Duplicate packet with hash value " << fippkt->getHash() << " removed" << std::endl;
                    }
                }
            } else {
                result.push_back(std::move(fippkt));
            }
        }
        return result;
    }
    
        // TODO: Add methods to process packets by type
    
    private:
        std::string fileExtension;
        std::unordered_set<std::string> hashDict;
        std::vector<pcpp::Packet*> packets;  // Stored packets to write out
    
        // TLS support is integrated via PcapPlusPlus; ensure the TLS plugin library
        // is linked in your CMake configuration.

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
        case pcpp::HTTP:
            return "HTTP";
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

    std::unordered_map<std::string, bool> inspectRawPacket(pcpp::RawPacket* origRaw) {
        // 1) Grab length, timestamp, etc. from the original:
        const uint8_t*   data    = origRaw->getRawData();
        size_t           dataLen = origRaw->getRawDataLen();
        timespec          ts      = origRaw->getPacketTimeStamp();
        bool             owns   = true; // we want the new RawPacket to own+free its buffer

        // 2) Allocate a new buffer and copy the bytes:
        uint8_t* copyBuf = new uint8_t[dataLen];
        std::memcpy(copyBuf, data, dataLen);

        // 3) Build a temporary RawPacket that will own “copyBuf”:
        pcpp::RawPacket deepCopyRaw(copyBuf, (int)dataLen, ts, owns);

        // 4) Now parse that deep‐copied RawPacket exactly once:
        pcpp::Packet tempPacket(&deepCopyRaw);

        std::unordered_map<std::string, bool> layer_map;
        for (pcpp::Layer* layer = tempPacket.getFirstLayer(); layer; layer = layer->getNextLayer())
        {
            std::string protoName = getProtocolTypeAsString(layer->getProtocol());
            layer_map[protoName] = true;
        }

        // 5) When tempPacket (and deepCopyRaw) go out of scope, they free only the copyBuf,
        //    leaving the original origRaw untouched.
        return layer_map;
    }

    /**
     * Pre-process a raw pcpp::Packet into a FIPPacket subclass based on layers.
     * Optionally invoke header preprocessing.
     */
    std::unique_ptr<FIPPacket> preprocess(std::unique_ptr<pcpp::RawPacket>& packet, PacketProcessorType type) {
        std::unique_ptr<FIPPacket> fippacket = std::make_unique<UnknownPacket>(std::make_unique<pcpp::RawPacket>(*packet));
        std::unordered_map<std::string, std::string> address_mapping = fippacket->getAdressMapping();
        std::unordered_map<std::string, bool> layer_map = fippacket->getLayerMap();
        // HTTP handling
        if (layer_map.count("HTTP")) {
            fippacket = std::make_unique<HTTPPacket>(std::move(packet), address_mapping, layer_map);
        }
        else if (layer_map.count("HTTPRequest")) {
            fippacket = std::make_unique<HTTPRequestPacket>(std::move(packet), address_mapping, layer_map);
        }
        else if (layer_map.count("HTTPResponse")) {
            fippacket = std::make_unique<HTTPResponsePacket>(std::move(packet), address_mapping, layer_map);
        }
        // DNS handling
        else if (layer_map.count("DNS")) {
            fippacket = std::make_unique<DNSPacket>(std::move(packet), address_mapping, layer_map);
        }
        // Transport layer (TCP/UDP)
        else if (layer_map.count("TCP") || layer_map.count("UDP")) {
            fippacket = std::make_unique<TransportPacket>(std::move(packet), address_mapping, layer_map);
        }
        // Network layer (IPv4/IPv6)
        else if (layer_map.count("IPv4") || layer_map.count("IPv6")) {
            fippacket = std::make_unique<IPPacket>(std::move(packet), address_mapping, layer_map);
        }
        // Data link layer (Ethernet)
        else if (layer_map.count("Ethernet")) {
            fippacket = std::make_unique<EtherPacket>(std::move(packet), address_mapping, layer_map);
        }

        // Header preprocessing if requested
        if (type == PacketProcessorType::HEADER) {
            fippacket->header_preprocessing();
        }
        return fippacket;
    }
};
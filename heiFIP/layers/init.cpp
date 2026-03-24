#pragma once
#include <vector>
#include <string>
#include <iostream>
#include <unordered_set>
#include <PcapFileDevice.h>
#include <Packet.h>
#include <memory>

#include "packet.cpp"
#include "dns.cpp"
#include "http.cpp"
#include "ip.cpp"
#include "ssh.cpp"
#include "transport.cpp"

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
 * accumulates packets, and returns owning unique pointers to them.
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
        size_t limit = (maxCount == 0) ? 64 : maxCount;

        while (count < limit && reader.getNextPacket(rawPacket)) {
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
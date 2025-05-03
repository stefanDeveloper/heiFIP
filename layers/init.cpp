#pragma onces
#include <vector>
#include <string>
#include <unordered_set>
#include <PcapFileDevice.h> // Pcap writer
#include <Packet.h>
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
    std::vector<FIPPacket*> readPacketsFile(const std::string& filename, PacketProcessorType type, size_t maxCount = 64) {
        
        std::vector<FIPPacket*> result;
        pcpp::PcapFileReaderDevice reader(filename);
        
        if (!reader.open()) { 
            return result;
        }

        pcpp::RawPacket rawPacket;
        size_t count = 0;

        while (count < maxCount && reader.getNextPacket(rawPacket)) {
            pcpp::Packet parsedPacket(&rawPacket);
            FIPPacket* fippkt = preprocess(&parsedPacket, type);

            if (fippkt && !fippkt->getHash().empty()) {
                auto res = hashDict.insert(fippkt->getHash());
                if (res.second) { // was inserted, new
                result.push_back(fippkt);
                } else {
                delete fippkt;
                }
            } else if (fippkt) {
                result.push_back(fippkt);
            }

            ++count;
        }
        reader.close();
        return result;
    }

    std::vector<FIPPacket*> readPacketsList(const std::vector<pcpp::Packet*>& inputPackets, PacketProcessorType type) {
        
        std::vector<FIPPacket*> result;
        for (auto pktPtr : inputPackets) {
            FIPPacket* fippkt = preprocess(pktPtr, type);
            if (!fippkt) {continue;}

            if (!fippkt->getHash().empty()) {
                auto res = hashDict.insert(fippkt->getHash());
                if (res.second) {
                result.push_back(fippkt);
                } else {
                delete fippkt;
                }
            } else {
                result.push_back(fippkt);
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

/**
     * Pre-process a raw pcpp::Packet into a FIPPacket subclass based on layers.
     * Optionally invoke header preprocessing.
     */
    FIPPacket* preprocess(pcpp::Packet* packet, PacketProcessorType type) {
        // Wrap in UnknownPacket to inspect layer map
        FIPPacket* fippacket = new UnknownPacket(*packet);
        // HTTP handling
        if (fippacket->getLayerMap().count("HTTPRequest")) {
            delete fippacket;
            fippacket = new HTTPRequestPacket(*packet, fippacket->getAdressMapping(), fippacket->getLayerMap());
        }
        else if (fippacket->getLayerMap().count("HTTPResponse")) {
            delete fippacket;
            fippacket = new HTTPResponsePacket(*packet, fippacket->getAdressMapping(), fippacket->getLayerMap());
        }

        // DNS handling
        else if (fippacket->getLayerMap().count("DNS")) {
            delete fippacket;
            fippacket = new DNSPacket(*packet, fippacket->getAdressMapping(), fippacket->getLayerMap());
        }
        // Transport layer (TCP/UDP)
        else if (fippacket->getLayerMap().count("TCP") || fippacket->getLayerMap().count("UDP")) {
            delete fippacket;
            fippacket = new TransportPacket(*packet, fippacket->getAdressMapping(), fippacket->getLayerMap());
        }
        // Network layer (IPv4/IPv6)
        else if (fippacket->getLayerMap().count("IP") || fippacket->getLayerMap().count("IPv6")) {
            delete fippacket;
            fippacket = new IPPacket(*packet, fippacket->getAdressMapping(), fippacket->getLayerMap());
        }
        // Data link layer (Ethernet)
        else if (fippacket->getLayerMap().count("Ether")) {
            delete fippacket;
            fippacket = new EtherPacket(*packet, fippacket->getAdressMapping(), fippacket->getLayerMap());
        }

        // Header preprocessing if requested
        if (type == PacketProcessorType::HEADER) {
            fippacket->header_preprocessing();
        }
        return fippacket;
    }
};
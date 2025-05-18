#pragma once

#include "transport.cpp"

/**
 * SSHPacketProcessor is a TransportPacket subclass for SSH processing.
 * It currently defers all processing to its base class.
 */
class SSHPacketProcessor : public TransportPacket {
    public:
        /**
         * Constructor: initialize with an existing pcap Packet, address mapping, and layer map.
         */
        SSHPacketProcessor(const pcpp::RawPacket& packet,
            std::unordered_map<std::string, std::string> addressMapping = {},
            std::unordered_map<std::string, bool> layerMap = {})
            : TransportPacket(packet, addressMapping, layerMap) {}
    
        /**
         * Override header preprocessing to allow SSH-specific logic.
         * Currently calls the base implementation.
         */
        void header_preprocessing() override {
            // Call upstream preprocessing (e.g., TCP reassembly, fragments)
            TransportPacket::header_preprocessing();
            
            // TODO: Add SSH-specific preprocessing here
        }
};
#pragma once

#include "transport.cpp"

/**
 * @class SSHPacketProcessor
 * @brief Handles SSH-specific packet processing by extending TransportPacket.
 *
 * Responsibilities:
 *   - Inherits all Ethernet, IP, and transport-layer rewriting and hashing logic.
 *   - Provides a hook for SSH-specific header preprocessing in the future.
 *   - Currently, it simply delegates to TransportPacket for all work.
 */
class SSHPacketProcessor : public TransportPacket {
public:
    /**
     * @brief Constructor: initialize SSH packet processor with given raw packet and mappings.
     *
     * @param rawPacketPointer  unique_ptr to the raw pcpp::RawPacket containing packet bytes.
     * @param addressMapping    Mapping of original → rewritten MAC/IP addresses (populated by base classes).
     * @param layerMap          Map of protocol layers present (Ethernet, IP, TCP/UDP, SSH).
     *
     * Workflow:
     *   1. Calls TransportPacket constructor, which in turn:
     *        - Rewrites Ethernet MACs (EtherPacket).
     *        - Rewrites IP addresses and computes IP-header hash (IPPacket).
     *        - Computes transport-layer hash and optionally strips payload (TransportPacket).
     *   2. No SSH-specific logic in this constructor; header_preprocessing() can be overridden as needed.
     */
    SSHPacketProcessor(std::unique_ptr<pcpp::RawPacket> rawPacketPointer,
                       std::unordered_map<std::string, std::string> addressMapping = {},
                       std::unordered_map<std::string, bool> layerMap = {})
        : TransportPacket(std::move(rawPacketPointer), addressMapping, layerMap)
    {}

    /**
     * @brief Override header preprocessing to allow SSH-specific modifications.
     *
     * Workflow:
     *   1. Call TransportPacket::header_preprocessing() to apply all lower-layer logic:
     *        - Ethernet MAC rewriting
     *        - IP address rewriting and IP-header hashing
     *        - TCP/UDP hashing and optional payload stripping
     *   2. (Currently a placeholder) Insert SSH-specific header modifications here.
     *
     * Why:
     *   - SSH packets may require rewriting or sanitizing certain payload bytes, ports, or flags.
     *   - By overriding this method, SSHPacketProcessor can insert or remove layers,
     *     update checksums, or anonymize SSH-specific fields before final serialization.
     */
    void header_preprocessing() override {
        // Perform all transport-layer and lower-layer preprocessing
        TransportPacket::header_preprocessing();

        // TODO: Add SSH-specific preprocessing (e.g., port-based filtering, payload sanitization)
    }
};
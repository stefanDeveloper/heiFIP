#pragma once

#include <Packet.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <PayloadLayer.h>
#include <IPv4Layer.h>
#include <HttpLayer.h>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>  // For SHA-256 hashing

#include "header.hpp"
#include "ip.hpp"
#include "logging.hpp"
#include "packet.hpp"

/**
 * @class TransportPacket
 * @brief Extends IPPacket to handle TCP/UDP-specific hashing, optional payload stripping,
 *        and substitution of standard TCP/UDP layers with custom transport-layer classes.
 *
 * Responsibilities:
 *   - In the constructor, detect the presence of a TCP or UDP layer.
 *   - Compute a SHA-256 hash based on key transport-header fields (flags & options for TCP,
 *     or a simple identifier for UDP).
 *   - If TLS is present without a transport-layer handshake (e.g., no TCP/UDP) or if “Raw”
 *     payload exists without HTTP, strip downstream payload layers to sanitize the packet.
 *   - In header_preprocessing(), find and replace the original TCP/UDP layer with a custom
 *     transport-layer object (CustomTCPLayer or CustomUDPLayer), then recompute checksums.
 *
 * Inherits from IPPacket, so all IP- and Ethernet-level rewriting and hashing have already occurred.
 */
class TransportPacket : public IPPacket {
public:
    /// Stores the SHA-256 hex string computed over transport-layer header fields
    std::string hash;

    /**
     * @brief Constructor: Compute transport-layer hash and optionally strip payload layers.
     *
     * @param rawPacketPointer  unique_ptr to pcpp::RawPacket containing full packet bytes.
     * @param addressMapping    Initial mapping of original → replacement addresses (populated by IPPacket/EtherPacket).
     * @param layerMap          Map of protocol layers present (populated by FIPPacket base classes).
     *
     * Workflow:
     *   1. Call IPPacket constructor, which:
     *        - Rewrites Ethernet MACs (via EtherPacket),
     *        - Detects layers and computes a packet-level SHA-256,
     *        - Rewrites IP addresses and computes an IP-header-specific hash,
     *        - Optionally strips IP payload if TLS/Raw conditions met.
     *
     *   2. If a TCP layer is present (layerMap["TCP"] is true):
     *        a. Retrieve the TcpLayer from `Packet`.
     *        b. Assemble a byte representing all TCP flags (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR).
     *        c. Count the number of TCP options in the header.
     *        d. Build a string "flagsValue,optionsCount" and compute its SHA-256.
     *        e. Store the result in `hash`.
     *        f. If TLS exists without TCP/UDP, or Raw exists without HTTP, detach all downstream layers
     *           from the TCP layer and delete them, then recompute checksums (to sanitize the packet).
     *
     *   3. Else if a UDP layer is present (layerMap["UDP"] is true):
     *        a. Retrieve the UdpLayer.
     *        b. Build a simple hash input "UDP" and call md5Hash() (SHA-256) to compute a hash.
     *        c. If TLS exists without TCP/UDP, or Raw exists without HTTP, detach and delete all layers
     *           that follow the UDP layer, then recompute checksums.
     */
    TransportPacket(std::unique_ptr<pcpp::RawPacket> rawPacketPointer,
                    std::unordered_map<std::string, std::string> addressMapping = {},
                    std::unordered_map<std::string, bool> layerMap = {})
        : IPPacket(std::move(rawPacketPointer), addressMapping, layerMap)
    {
        // If packet has a TCP layer, compute a hash of flags+options and possibly strip payload
        if (layerMap["TCP"]) {
            pcpp::TcpLayer* tcpLayer = Packet.getLayerOfType<pcpp::TcpLayer>();
            if (tcpLayer != nullptr) {
                // Extract TCP header fields
                pcpp::tcphdr* tcpHeader = tcpLayer->getTcpHeader();
                // Pack all boolean flags into a single byte
                uint8_t flags = 0;
                if (tcpHeader->synFlag) flags |= 0x02;
                if (tcpHeader->ackFlag) flags |= 0x10;
                if (tcpHeader->finFlag) flags |= 0x01;
                if (tcpHeader->rstFlag) flags |= 0x04;
                if (tcpHeader->pshFlag) flags |= 0x08;
                if (tcpHeader->urgFlag) flags |= 0x20;
                if (tcpHeader->eceFlag) flags |= 0x40;
                if (tcpHeader->cwrFlag) flags |= 0x80;

                // Count TCP options present in the header
                int optionsCount = tcpLayer->getTcpOptionCount();

                // Build hash input string: "<flagsValue>,<optionsCount>"
                std::ostringstream oss;
                oss << static_cast<int>(flags) << "," << optionsCount;
                std::string hashInput = oss.str();

                // Compute SHA-256 over hashInput
                unsigned char digest[SHA256_DIGEST_LENGTH];
                SHA256(reinterpret_cast<const unsigned char*>(hashInput.c_str()),
                       hashInput.length(),
                       digest);

                // Convert digest bytes to hex string and store in `hash`
                std::ostringstream hashStream;
                hashStream << std::hex << std::setw(2) << std::setfill('0');
                for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                    hashStream << static_cast<int>(digest[i]);
                }
                hash = hashStream.str();

                // If TLS present without transport or Raw present without HTTP, strip payload
                if (layerMap["TLS"] || (layerMap["Raw"] && !layerMap["HTTP"])) {
                    // Detach all layers following the TCP layer to remove payload
                    pcpp::Layer* next = tcpLayer->getNextLayer();
                    while (next) {
                        pcpp::Layer* toRemove = next;
                        next = next->getNextLayer();  // Advance before deletion
                        Packet.detachLayer(toRemove);
                        delete toRemove;
                    }
                    // Recompute checksums/lengths for remaining headers
                    Packet.computeCalculateFields();
                }
            }
        }
        // Else if packet has a UDP layer, compute a simple hash and possibly strip payload
        else if (layerMap["UDP"]) {
            pcpp::UdpLayer* udpLayer = Packet.getLayerOfType<pcpp::UdpLayer>();
            if (udpLayer != nullptr) {
                // Use the literal "UDP" as hash input
                std::string layerName = "UDP";
                hash = md5Hash(layerName);

                // If TLS present without transport or Raw present without HTTP, strip payload
                if (layerMap["TLS"] || (layerMap["Raw"] && !layerMap["HTTP"])) {
                    // Detach all layers following the UDP layer to remove payload
                    pcpp::Layer* next = udpLayer->getNextLayer();
                    while (next) {
                        pcpp::Layer* toRemove = next;
                        next = next->getNextLayer();
                        Packet.detachLayer(toRemove);
                        delete toRemove;
                    }
                    // Recompute checksums/lengths for remaining headers
                    Packet.computeCalculateFields();
                }
            }
        }

        // Populate address_mapping with ports
        if (layerMap["TCP"]) {
            auto* tcp = Packet.getLayerOfType<pcpp::TcpLayer>();
            if (tcp) {
                std::string srcP = std::to_string(ntohs(tcp->getTcpHeader()->portSrc));
                std::string dstP = std::to_string(ntohs(tcp->getTcpHeader()->portDst));
                address_mapping[srcP] = srcP;
                address_mapping[dstP] = dstP;
            }
        } else if (layerMap["UDP"]) {
            auto* udp = Packet.getLayerOfType<pcpp::UdpLayer>();
            if (udp) {
                std::string srcP = std::to_string(ntohs(udp->getUdpHeader()->portSrc));
                std::string dstP = std::to_string(ntohs(udp->getUdpHeader()->portDst));
                address_mapping[srcP] = srcP;
                address_mapping[dstP] = dstP;
            }
        }
    }

    /**
     * @brief Replace the existing TCP/UDP layer with a Custom transport layer, then recompute checksums.
     *
     * Workflow for TCP:
     *   1. If a TCP layer exists, retrieve it via Packet.getLayerOfType<TcpLayer>().
     *   2. Call header_preprocessing_tcp(oldTcp) to build a CustomTCPLayer from the old header fields.
     *   3. Insert the CustomTCPLayer into the packet right after oldTcp’s previous layer.
     *   4. Detach and delete the old TcpLayer.
     *   5. Recompute length/checksum fields (Packet.computeCalculateFields()).
     *
     * Workflow for UDP:
     *   1. If a UdpLayer exists, retrieve it via Packet.getLayerOfType<UdpLayer>().
     *   2. Call header_preprocessing_udp(oldUdp) to build a CustomUDPLayer.
     *   3. Insert the CustomUDPLayer right after oldUdp’s previous layer.
     *   4. Detach and delete the old UdpLayer.
     *   5. Recompute length/checksum fields.
     *
     * Finally, call IPPacket::header_preprocessing() to allow IP-layer substitutions from the parent class.
     */
    void header_preprocessing() override {
        // Replace TCP layer if present
        if (layer_map["TCP"]) {
            LDEBUG("TransportPacket::header_preprocessing() - Substituting TCP layer");
            pcpp::TcpLayer* oldTcp = Packet.getLayerOfType<pcpp::TcpLayer>();
            if (!oldTcp) {
                // No TCP layer found; skip
                return;
            }

            // Build a CustomTCPLayer from the old TCP header fields
            std::unique_ptr<CustomTCPLayer> customLayer = header_preprocessing_tcp(oldTcp);

            // Insert custom layer in place of old one
            pcpp::Layer* prev = oldTcp->getPrevLayer();
            Packet.insertLayer(prev, customLayer.release());

            // Detach and delete the original TCP layer
            Packet.detachLayer(oldTcp);
            delete oldTcp;

            // Recompute upper-layer lengths and checksums
            Packet.computeCalculateFields();
        }

        // Replace UDP layer if present
        if (layer_map["UDP"]) {
            LDEBUG("TransportPacket::header_preprocessing() - Substituting UDP layer");
            pcpp::UdpLayer* oldUdp = Packet.getLayerOfType<pcpp::UdpLayer>();
            if (!oldUdp) {
                // No UDP layer found; skip
                return;
            }

            // Build a CustomUDPLayer (no fields needed from original UDP header)
            std::unique_ptr<CustomUDPLayer> customLayer = header_preprocessing_udp(oldUdp);

            // Insert custom layer in place of old one
            pcpp::Layer* prev = oldUdp->getPrevLayer();
            Packet.insertLayer(prev, customLayer.release());

            // Detach and delete the original UDP layer
            Packet.detachLayer(oldUdp);
            delete oldUdp;

            // Recompute upper-layer lengths and checksums
            Packet.computeCalculateFields();
        }

        // Delegate to IPPacket for any IPv4/IPv6 header substitutions
        IPPacket::header_preprocessing();
    }

    /**
     * @brief Build a CustomTCPLayer from an existing TcpLayer’s header fields.
     *
     * @param tcpLayer  Pointer to the original pcpp::TcpLayer being replaced.
     * @return std::unique_ptr<CustomTCPLayer>  Custom layer capturing TCP flags and options.
     *
     * Steps:
     *   1. Read the tcphdr struct from tcpLayer to extract individual flags (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR).
     *   2. Pack these booleans into a single 8-bit flags value.
     *   3. Determine the length of TCP options by subtracting the fixed header size from header_len.
     *   4. Copy those options bytes into a std::vector<uint8_t>.
     *   5. Construct a CustomTCPLayer(flags, options) with those values.
     *
     * Why:
     *   - CustomTCPLayer may implement specialized behavior (e.g., anonymization, logging) based on flags/options.
     */
    std::unique_ptr<CustomTCPLayer> header_preprocessing_tcp(pcpp::TcpLayer* tcpLayer) {
        pcpp::tcphdr* hdr = tcpLayer->getTcpHeader();
        // Pack flags into a single byte
        uint16_t flags = 0;
        if (hdr->finFlag) flags |= 0x01;
        if (hdr->synFlag) flags |= 0x02;
        if (hdr->rstFlag) flags |= 0x04;
        if (hdr->pshFlag) flags |= 0x08;
        if (hdr->ackFlag) flags |= 0x10;
        if (hdr->urgFlag) flags |= 0x20;
        if (hdr->eceFlag) flags |= 0x40;
        if (hdr->cwrFlag) flags |= 0x80;

        // Calculate length of TCP options (header length minus fixed header size)
        size_t optLen = tcpLayer->getHeaderLen() - sizeof(*hdr);
        const uint8_t* optPtr = reinterpret_cast<const uint8_t*>(hdr) + sizeof(*hdr);
        std::vector<uint8_t> options(optPtr, optPtr + optLen);

        return std::make_unique<CustomTCPLayer>(flags, options);
    }

    /**
     * @brief Build a CustomUDPLayer for a given UdpLayer.
     *
     * @param udpLayer  Pointer to the original pcpp::UdpLayer being replaced.
     * @return std::unique_ptr<CustomUDPLayer>  Custom layer; no additional fields needed.
     *
     * Why:
     *   - CustomUDPLayer can encapsulate any UDP-specific processing in one place. Currently stateless.
     */
    std::unique_ptr<CustomUDPLayer> header_preprocessing_udp(pcpp::UdpLayer* /*udpLayer*/) {
        return std::make_unique<CustomUDPLayer>();
    }

private:
    /**
     * @brief Compute a SHA-256 hash over a simple input string and return the hex string.
     *
     * @param input  A small string (e.g., "UDP") to hash.
     * @return std::string  Lowercase hex string of SHA-256 digest.
     *
     * Why:
     *   - Provides a consistent digest even when transport-layer fields are minimal,
     *     enabling indexing or deduplication based on protocol type.
     */
    std::string md5Hash(const std::string& input) {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), digest);

        std::ostringstream oss;
        oss << std::hex << std::setw(2) << std::setfill('0');
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            oss << static_cast<int>(digest[i]);
        }
        return oss.str();
    }
};
#pragma once

#include <Packet.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <PayloadLayer.h>
#include <PcapFileDevice.h>
#include <IpAddress.h>
#include <iostream>
#include <unordered_map>
#include <string>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>   // For SHA-256 hashing of header fields

#include "packet.cpp"
#include "header.cpp"

/**
 * @class IPPacket
 * @brief Extends EtherPacket to handle IPv4/IPv6 header rewriting and hashing.
 *
 * Responsibilities:
 *   - Upon construction, detect and rewrite IP addresses (IPv4 or IPv6).
 *   - Compute a hash based on selected IP header fields (version, fragment/traffic, protocol/hopLimit).
 *   - Optionally strip payload when certain layers (e.g., TLS without TCP/UDP) are present.
 *   - Perform header preprocessing by substituting standard IP layers with custom IPLayer instances.
 *
 * Inherits from EtherPacket, so Ethernet MAC rewriting occurs first (if present).
 */
class IPPacket : public EtherPacket {
public:
    /**
     * @brief Constructor: Rewrites IP addresses, computes a header-based hash, and optionally strips payload.
     *
     * @param rawPacketPointer  Owned unique_ptr to pcpp::RawPacket containing raw bytes.
     * @param addressMapping    Initial IP address mapping (original → new). If empty, new addresses generated.
     * @param layerMap          Optional precomputed layer map (protocol→presence). If empty, base class extracted layers.
     *
     * Workflow:
     *   1. Delegate to EtherPacket constructor, which handles:
     *      - MAC rewriting (if “Ethernet” present).
     *      - Building layer_map and initial SHA-256 of entire packet layers.
     *   2. If “IPv4” is present in layer_map, call filterIPv4() to rewrite src/dst IPs:
     *        • mapAddress() → returns existing mapping or generates a random address.
     *        • Set new IPv4 addresses in the IPv4Layer.
     *   3. Extract key IPv4 header fields (version, fragmentOffset, protocol) into a comma-separated string.
     *   4. Call computeHash() on that string to override hash with IPv4-specific header hash.
     *   5. If “TLS” exists without “TCP”/“UDP”, strip the IPv4 payload (set first payload byte to ‘\0’).
     *   6. If “Raw” exists without higher-level “TCP”/“UDP”/“HTTP”, also strip payload similarly.
     *   7. If “IPv6” is present instead of IPv4, perform analogous steps:
     *        • filterIPv6() rewrites src/dst IPv6 addresses.
     *        • Extract IPv6 header fields (version, trafficClass, hopLimit) for computeHash().
     *        • Conditionally strip payload if “TLS” without transport or “Raw” without transport/HTTP.
     */
    IPPacket(std::unique_ptr<pcpp::RawPacket> rawPacketPointer,
             std::unordered_map<std::string, std::string> addressMapping = {},
             std::unordered_map<std::string, bool> layerMap = {})
        : EtherPacket(std::move(rawPacketPointer), addressMapping, layerMap)
    {
        // If IPv4 layer is present, perform IPv4-specific rewriting and hashing
        if (layerMap.count("IPv4")) {
            filterIPv4();  // Rewrite source/dest IPv4 addresses based on address_mapping

            // Retrieve the IPv4Layer to extract header fields
            auto ipLayer = Packet.getLayerOfType<pcpp::IPv4Layer>();
            // Build a comma-separated string of (version, fragmentOffset, protocol)
            std::string hashInput =
                std::to_string(ipLayer->getIPv4Header()->ipVersion) + "," +
                std::to_string(ipLayer->getIPv4Header()->fragmentOffset) + "," +
                std::to_string(ipLayer->getIPv4Header()->protocol);
            computeHash(hashInput);  // Compute SHA-256 over this header-specific string

            // If TLS is present but no TCP/UDP, strip the payload to sanitize
            if (layerMap.count("TLS") && !(layerMap.count("TCP") || layerMap.count("UDP"))) {
                ipLayer->getLayerPayload()[0] = '\0';
            }
            // If Raw payload is present without transport or HTTP, strip it as well
            if (layerMap.count("Raw") && !(layerMap.count("TCP") || layerMap.count("UDP") || layerMap.count("HTTP"))) {
                ipLayer->getLayerPayload()[0] = '\0';
            }
        }
        // If IPv6 layer is present instead of IPv4, perform analogous steps
        else if (layerMap.count("IPv6")) {
            filterIPv6();  // Rewrite source/dest IPv6 addresses

            // Retrieve the IPv6Layer to extract header fields
            auto ip6Layer = Packet.getLayerOfType<pcpp::IPv6Layer>();
            // Build a comma-separated string of (version, trafficClass, hopLimit)
            std::string hashInput =
                std::to_string(ip6Layer->getIPv6Header()->ipVersion) + "," +
                std::to_string(ip6Layer->getIPv6Header()->trafficClass) + "," +
                std::to_string(ip6Layer->getIPv6Header()->hopLimit);
            computeHash(hashInput);  // Compute SHA-256 over this IPv6-specific string

            // Strip payload when TLS present without transport
            if (layerMap.count("TLS") && !(layerMap.count("TCP") || layerMap.count("UDP"))) {
                ip6Layer->getLayerPayload()[0] = '\0';
            }
            // Strip Raw payload if no transport or HTTP
            if (layerMap.count("Raw") && !(layerMap.count("TCP") || layerMap.count("UDP") || layerMap.count("HTTP"))) {
                ip6Layer->getLayerPayload()[0] = '\0';
            }
        }
    }

    /**
     * @brief Override header_preprocessing to replace standard IP layers with custom IPLayer types.
     *
     * Reasons:
     *   - Certain analysis or transformations require a custom representation (CustomIPLayer / CustomIPv6Layer).
     *   - After detaching the original layer, recompute checksums to keep the packet consistent.
     *
     * Workflow (IPv4 case):
     *   1. Find the existing IPv4Layer using Packet.getLayerOfType<IPv4Layer>(). If none, return.
     *   2. Store a pointer to the layer’s previous layer (prev).
     *   3. Detach the original IPv4Layer from Packet (Packet.detachLayer(oldIp)).
     *   4. Call header_preprocessing_ipv4(oldIp) to build a CustomIPLayer instance from old header fields.
     *   5. Delete the old IPv4Layer object to free memory.
     *   6. Insert the new CustomIPLayer after prev (Packet.insertLayer(prev, customLayer.release(), true)):
     *        - The 'true' flag tells PcapPlusPlus to update layer pointers automatically.
     *   7. Recompute upper-layer length and checksum fields (Packet.computeCalculateFields()).
     *
     * The IPv6 case is analogous, substituting IPv6Layer with CustomIPv6Layer.
     * Finally, call EtherPacket::header_preprocessing() to allow any Ethernet‐level adjustments.
     */
    void header_preprocessing() override {
        // IPv4 replacement logic
        if (layer_map.count("IPv4")) {
            pcpp::IPv4Layer* oldIp = Packet.getLayerOfType<pcpp::IPv4Layer>();
            if (!oldIp) return;  // No IPv4 layer found—nothing to replace

            // Remember the layer that preceded the IPv4 layer
            pcpp::Layer* prev = oldIp->getPrevLayer();
            // Detach the old IPv4 layer from the packet’s layer chain
            Packet.detachLayer(oldIp);

            // Build a CustomIPLayer from the old header fields
            std::unique_ptr<CustomIPLayer> customLayer = header_preprocessing_ipv4(oldIp);
            delete oldIp;  // Free the original layer’s memory

            // Insert the custom IPv4 layer into the same position
            Packet.insertLayer(prev, customLayer.release(), true);

            // Recompute checksums/lengths for all upstream layers
            Packet.computeCalculateFields();
        }

        // IPv6 replacement logic
        if (layer_map.count("IPv6")) {
            pcpp::IPv6Layer* oldIp = Packet.getLayerOfType<pcpp::IPv6Layer>();
            if (!oldIp) return;  // No IPv6 layer found

            pcpp::Layer* prev = oldIp->getPrevLayer();
            // Build a CustomIPv6Layer from the old header fields
            std::unique_ptr<CustomIPv6Layer> customLayer = header_preprocessing_ipv6(oldIp);

            // Insert the new layer before detaching the old one (to preserve layer pointers)
            Packet.insertLayer(prev, customLayer.release());

            // Now detach and delete the old IPv6 layer
            Packet.detachLayer(oldIp);
            delete oldIp;

            // Recompute length/checksum fields after substitution
            Packet.computeCalculateFields();
        }

        // Delegate to EtherPacket for any Ethernet‐level preprocessing
        EtherPacket::header_preprocessing();
    }

    /**
     * @brief Build a CustomIPLayer from an existing IPv4Layer’s header fields.
     *
     * @param ipLayer  Pointer to the original IPv4Layer being replaced.
     * @return std::unique_ptr<CustomIPLayer>  New layer capturing version, flags, TOS, TTL, protocol.
     *
     * Steps:
     *   1. Extract pointers to the IPv4 header (ipVersion, fragmentOffset, protocol, etc.).
     *   2. Compute fragment flags by shifting and masking the fragmentOffset field.
     *   3. Construct a CustomIPLayer with (version, flags, typeOfService, timeToLive, protocol).
     *
     * Why:
     *   - CustomIPLayer can enforce custom behaviors (e.g., anonymization, logging) 
     *     without modifying the original pcpp::IPv4Layer class.
     */
    std::unique_ptr<CustomIPLayer> header_preprocessing_ipv4(pcpp::IPv4Layer* ipLayer) {
        pcpp::iphdr* hdr = ipLayer->getIPv4Header();
        uint8_t version     = hdr->ipVersion;
        // Network-byte-order fragmentOffset: mask off the top 3 bits for flags
        uint16_t fragOffset = ntohs(hdr->fragmentOffset);
        uint8_t flags       = static_cast<uint8_t>((fragOffset >> 13) & 0x07);

        // Build the custom IPv4 layer with key header fields
        return std::make_unique<CustomIPLayer>(
            version,
            flags,
            hdr->typeOfService,
            hdr->timeToLive,
            hdr->protocol
        );
    }

    /**
     * @brief Build a CustomIPv6Layer from an existing IPv6Layer’s header fields.
     *
     * @param ipv6Layer  Pointer to the original IPv6Layer being replaced.
     * @return std::unique_ptr<CustomIPv6Layer>  New layer capturing version, trafficClass, nextHeader, hopLimit.
     *
     * Why:
     *   - Similar to IPv4 case: isolate key fields for custom processing (e.g., anonymization or analysis).
     */
    std::unique_ptr<CustomIPv6Layer> header_preprocessing_ipv6(pcpp::IPv6Layer* ipv6Layer) {
        uint8_t ipVersion    = ipv6Layer->getIPv6Header()->ipVersion;
        uint8_t trafficClass = ipv6Layer->getIPv6Header()->trafficClass;
        uint8_t nextHeader   = ipv6Layer->getIPv6Header()->nextHeader;
        uint8_t hopLimit     = ipv6Layer->getIPv6Header()->hopLimit;

        return std::make_unique<CustomIPv6Layer>(
            ipVersion,
            trafficClass,
            nextHeader,
            hopLimit
        );
    }

private:
    /// Stores the hash computed in the constructor or computeHash()
    std::string hash;

    /**
     * @brief Compute a SHA-256 hash over a short input string and store it in `hash`.
     *
     * @param input  A comma-separated string of selected header fields (e.g., “4,0,6” for IPv4 version=4, fragOffset=0, proto=6).
     *
     * Workflow:
     *   1. Call SHA256(input.c_str(), input.length(), resultBuffer).
     *   2. Convert the 32-byte digest (256 bits) into a lowercase hex string.
     *   3. Store the hex string in `hash`.
     *
     * Why:
     *   - Provide a concise, reproducible fingerprint of core IP header fields for deduplication or indexing.
     */
    void computeHash(const std::string& input) {
        unsigned char result[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result);

        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            oss << std::setw(2) << static_cast<int>(result[i]);
        }
        hash = oss.str();
    }

    /**
     * @brief Rewrite IPv4 source and destination addresses based on address_mapping.
     *
     * Steps:
     *   1. Retrieve the IPv4Layer pointer from Packet.
     *   2. Extract original src and dst IPs as std::string.
     *   3. Call mapAddress() for each; if not present, generateRandomIPv4().
     *   4. Set the new IPv4 addresses on the IPv4Layer.
     *
     * Why:
     *   - Anonymize or normalize IP addresses consistently across packets (e.g., for privacy).
     */
    void filterIPv4() {
        auto ipLayer = Packet.getLayerOfType<pcpp::IPv4Layer>();
        std::string src = ipLayer->getSrcIPAddress().toString();
        std::string dst = ipLayer->getDstIPAddress().toString();

        std::string newSrc = mapAddress(src);
        std::string newDst = mapAddress(dst);

        ipLayer->setSrcIPv4Address(pcpp::IPv4Address(newSrc));
        ipLayer->setDstIPv4Address(pcpp::IPv4Address(newDst));
    }

    /**
     * @brief Rewrite IPv6 source and destination addresses based on address_mapping.
     *
     * Steps:
     *   1. Retrieve the IPv6Layer pointer from Packet.
     *   2. Extract original src and dst IPv6 as std::string.
     *   3. Call mapAddress(src, true) / mapAddress(dst, true); generateRandomIPv6() if missing.
     *   4. Set the new IPv6 addresses on the IPv6Layer.
     *
     * Why:
     *   - Consistently anonymize or remap IPv6 addresses across packets.
     */
    void filterIPv6() {
        auto ip6Layer = Packet.getLayerOfType<pcpp::IPv6Layer>();
        std::string src = ip6Layer->getSrcIPAddress().toString();
        std::string dst = ip6Layer->getDstIPAddress().toString();

        std::string newSrc = mapAddress(src, true);
        std::string newDst = mapAddress(dst, true);

        ip6Layer->setSrcIPv6Address(pcpp::IPv6Address(newSrc));
        ip6Layer->setDstIPv6Address(pcpp::IPv6Address(newDst));
    }

    /**
     * @brief Return a new or existing mapping for an IP address string.
     *
     * @param oldAddr  The original IP address string (IPv4 or IPv6).
     * @param isIPv6   If true, call generateRandomIPv6(); otherwise generateRandomIPv4().
     * @return std::string  The mapped or newly generated IP address.
     *
     * Logic:
     *   - If oldAddr exists in address_mapping, return the stored value.
     *   - Otherwise, generate a random address (IPv4 or IPv6), store it in mapping, and return it.
     *
     * Why:
     *   - Ensure consistent rewriting: future packets with the same original address map to the same new one.
     */
    std::string mapAddress(const std::string& oldAddr, bool isIPv6 = false) {
        if (address_mapping.count(oldAddr)) {
            return address_mapping[oldAddr];
        }
        std::string newAddr = isIPv6 ? generateRandomIPv6() : generateRandomIPv4();
        address_mapping[oldAddr] = newAddr;
        return newAddr;
    }

    /**
     * @brief Generate a random IPv4 address in dotted-decimal format.
     *
     * Steps:
     *   1. Seed the RNG using current time (std::time(nullptr)).
     *   2. Generate four octets (0–255) and join with dots.
     *
     * Why:
     *   - Provide a pseudorandom anonymized IPv4 when no mapping exists.
     */
    std::string generateRandomIPv4() {
        std::srand(static_cast<unsigned int>(std::time(nullptr)));
        std::string ip;
        for (int i = 0; i < 4; ++i) {
            int octet = std::rand() % 256;
            ip += std::to_string(octet);
            if (i < 3) ip += ".";
        }
        return ip;
    }

    /**
     * @brief Generate a random IPv6 address in standard colon-hex format.
     *
     * Steps:
     *   1. Seed the RNG using current time.
     *   2. Generate eight 16-bit blocks (0–65535) and format each as four-digit hex.
     *   3. Join blocks with colons.
     *
     * Why:
     *   - Provide a pseudorandom anonymized IPv6 when no mapping exists.
     */
    std::string generateRandomIPv6() {
        std::srand(static_cast<unsigned int>(std::time(nullptr)));
        std::ostringstream oss;
        for (int i = 0; i < 8; ++i) {
            int block = std::rand() % 0x10000;
            oss << std::hex << std::setw(4) << std::setfill('0') << block;
            if (i < 7) oss << ":";
        }
        return oss.str();
    }
};
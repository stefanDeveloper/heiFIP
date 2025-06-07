#pragma once

#include <iostream>
#include <pcap.h>
#include <PcapFileDevice.h>
#include <Packet.h>
#include <EthLayer.h>
#include <unordered_map>
#include <string>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>   // Using SHA-256 for hashing layer bytes
#include <cstdlib>
#include <ctime>

/**
 * @class FIPPacket
 * @brief Base class for wrapping a pcpp::RawPacket and extracting features.
 *
 * Responsibilities:
 *   - Store a unique_ptr to a RawPacket (pcpp::RawPacket).
 *   - Build a pcpp::Packet from the RawPacket for easy layer access.
 *   - Generate a SHA-256 hash of all protocol-layer bytes.
 *   - Build a map of which protocol layers are present.
 *   - Maintain an address_mapping for rewriting addresses (e.g., MAC or IP).
 */
class FIPPacket {
private:
    /// Unique pointer that owns the raw packet bytes (pcpp::RawPacket).
    std::unique_ptr<pcpp::RawPacket> rawPtr;

protected:
    /// Parsed packet object created from rawPtr for layer-level manipulations.
    pcpp::Packet Packet;

    /**
     * @brief Maps original address strings (e.g., MAC/IP) to rewritten addresses.
     *
     * Used by derived classes (e.g., EtherPacket) to replace source/dest addresses consistently.
     * Key: original address string. Value: new (random or mapped) address string.
     */
    std::unordered_map<std::string, std::string> address_mapping;

    /**
     * @brief Indicates which protocol layers are present in this packet.
     *
     * Key: protocol name (e.g., "Ethernet", "IPv4", "TCP").
     * Value: true if that layer is present, false otherwise (currently always true for present layers).
     */
    std::unordered_map<std::string, bool> layer_map;

    /// Hex-encoded SHA-256 hash of all concatenated layer bytes.
    std::string hash;

    /**
     * @brief Concatenates all layer data and computes a SHA-256 hash.
     *
     * Steps:
     *   1. Iterate through each layer in Packet (using getFirstLayer()/getNextLayer()).
     *   2. Write raw bytes of each layer into a std::ostringstream.
     *   3. Compute SHA-256 over the concatenated byte buffer.
     *   4. Convert the resulting digest into a lowercase hex string.
     *
     * @return std::string  Hex-encoded SHA-256 of the packet’s layered bytes.
     */
    std::string generate_sha256() {
        // 1) Gather all layer-bytes into a continuous buffer
        std::ostringstream raw_stream;
        for (pcpp::Layer* layer = Packet.getFirstLayer(); layer; layer = layer->getNextLayer()) {
            raw_stream.write(
                reinterpret_cast<const char*>(layer->getData()),
                layer->getDataLen()
            );
        }
        std::string data = raw_stream.str();

        // 2) Compute SHA-256 digest
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256(
            reinterpret_cast<const unsigned char*>(data.data()),
            data.size(),
            digest
        );

        // 3) Convert digest to hex string
        std::ostringstream hash_stream;
        hash_stream << std::hex << std::setfill('0');
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            hash_stream << std::setw(2) << static_cast<int>(digest[i]);
        }
        return hash_stream.str();
    }

    /**
     * @brief Populates layer_map with all protocol layers present in this Packet.
     *
     * For each layer in Packet:
     *   - Get its ProtocolType via layer->getProtocol().
     *   - Convert that enum to a human-readable string.
     *   - Insert {layerName, true} into layer_map.
     *
     * Called by the constructor if the user did not supply a prebuilt layer_map.
     */
    void extract_layers() {
        layer_map.clear();
        for (pcpp::Layer* layer = Packet.getFirstLayer(); layer; layer = layer->getNextLayer()) {
            std::string layerName = getProtocolTypeAsString(layer->getProtocol());
            layer_map.insert({layerName, true});
        }
    }

    /**
     * @brief Convert a pcpp::ProtocolType enum to a std::string.
     *
     * Recognizes common protocols; defaults to "Unknown" otherwise.
     *
     * @param protocolType  The ProtocolType enum from PcapPlusPlus.
     * @return std::string  Human-readable protocol name.
     */
    std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType) {
        switch (protocolType) {
            case pcpp::Ethernet:
                return "Ethernet";
            case pcpp::IPv4:
                return "IPv4";
            case pcpp::IPv6:
                return "IPv6";
            case pcpp::TCP:
                return "TCP";
            case pcpp::UDP:
                return "UDP";
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

public:
    /**
     * @brief Constructor: Wraps a unique_ptr<pcpp::RawPacket> and initializes metadata.
     *
     * @param rawPacketPointer  A unique_ptr pointing to a dynamically allocated RawPacket.
     * @param addr_map          Optional mapping from original addresses → replacement addresses.
     * @param lmap              Optional precomputed map of layer presence. If empty, extract_layers() is called.
     *
     * Workflow:
     *   1. Move rawPacketPointer into rawPtr (taking ownership).
     *   2. Construct a pcpp::Packet from rawPtr.get(), enabling layer inspection.
     *   3. If the user provided a non-empty lmap, copy it into layer_map;
     *      otherwise call extract_layers() to detect layers automatically.
     *   4. Compute the SHA-256 hash over all layer bytes via generate_sha256().
     */
    FIPPacket(std::unique_ptr<pcpp::RawPacket> rawPacketPointer,
              const std::unordered_map<std::string, std::string>& addr_map = {},
              const std::unordered_map<std::string, bool>& lmap = {})
        : address_mapping(addr_map),
          rawPtr(std::move(rawPacketPointer)) 
    {
        // Build a pcpp::Packet wrapper around the raw data
        Packet = pcpp::Packet(rawPtr.get());

        // Populate layer_map: either use provided lmap or auto-detect
        if (lmap.empty()) {
            extract_layers();
        } else {
            layer_map = lmap;
        }

        // Compute the SHA-256 hash over all concatenated layer bytes
        hash = generate_sha256();
    }

    /// Virtual destructor ensures proper cleanup in derived classes
    virtual ~FIPPacket() = default;

    /**
     * @brief Placeholder method for header preprocessing in derived classes.
     *
     * Derived classes (e.g., EtherPacket) can override to implement protocol-specific
     * header manipulation (e.g., rewriting MAC addresses, stripping fields).
     */
    virtual void header_preprocessing() {
        // Base class does not modify headers by default.
    }

    /**
     * @brief Retrieve the SHA-256 hash string for this packet.
     * @return const std::string&  Reference to the precomputed hash string.
     */
    const std::string& getHash() const {
        return hash;
    }

    /**
     * @brief Retrieve a const reference to the layer presence map.
     * @return const std::unordered_map<std::string,bool>&  layer_map indicating present protocols.
     */
    const std::unordered_map<std::string, bool>& getLayerMap() const {
        return layer_map;
    }

    /**
     * @brief Retrieve a const reference to the address mapping used when rewriting addresses.
     * @return const std::unordered_map<std::string,std::string>&  Mapping of original → new addresses.
     */
    const std::unordered_map<std::string, std::string>& getAdressMapping() const {
        return address_mapping;
    }

    /**
     * @brief Access the underlying RawPacket pointer for additional, low-level operations.
     * @return pcpp::RawPacket*  Raw pointer to the owned RawPacket.
     */
    pcpp::RawPacket* getRawPacket() {
        return rawPtr.get();
    }

    /**
     * @brief Const overload: Access the underlying RawPacket pointer without modification.
     * @return const pcpp::RawPacket*  Const raw pointer to the owned RawPacket.
     */
    const pcpp::RawPacket* getRawPacket() const {
        return rawPtr.get();
    }
};

/**
 * @class UnknownPacket
 * @brief A concrete subclass of FIPPacket for packets with no protocol-specific preprocessing.
 *
 * Often used as a default when the type of packet is not recognized or does not require special handling.
 */
class UnknownPacket : public FIPPacket {
public:
    /**
     * @brief Constructor: Passes parameters to base FIPPacket.
     *
     * @param rawPacketPointer  Owned unique_ptr to RawPacket.
     * @param addr_map          Optional address rewriting map.
     * @param lmap              Optional precomputed layer map.
     *
     * Simply delegates to FIPPacket’s constructor. No additional extraction logic.
     */
    UnknownPacket(std::unique_ptr<pcpp::RawPacket> rawPacketPointer,
                  const std::unordered_map<std::string, std::string>& addr_map = {},
                  const std::unordered_map<std::string, bool>& lmap = {})
        : FIPPacket(std::move(rawPacketPointer), addr_map, lmap) 
    {}

    /**
     * @brief Override placeholder for header preprocessing.
     *
     * Calls base-class header_preprocessing (which does nothing), but can be extended in future.
     */
    void header_preprocessing() override {
        FIPPacket::header_preprocessing();
    }
};

/**
 * @brief Generate a random MAC address string in uppercase hex format (e.g., "A1:B2:C3:D4:E5:F6").
 *
 * Steps:
 *   1. For each of 6 octets, generate a random number 0–255 (using rand()).
 *   2. Format each octet as two uppercase hex digits, separated by colons.
 *
 * @return std::string  A randomly generated 6-byte MAC address.
 */
std::string generate_random_mac() {
    std::stringstream mac;
    mac << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (rand() % 256);
    for (int i = 0; i < 5; ++i) {
        mac << ":" << std::setw(2) << std::setfill('0') << (rand() % 256);
    }
    return mac.str();
}

/**
 * @class EtherPacket
 * @brief A subclass of FIPPacket that specifically handles Ethernet-layer address rewriting.
 *
 * Responsibilities:
 *   - On construction, detect if the packet contains an Ethernet layer.
 *   - If so, replace source and destination MAC addresses according to address_mapping,
 *     or generate new random MACs if none exist in the map.
 *   - Update the address_mapping so future packets with the same original MAC map to the same new MAC.
 */
class EtherPacket : public FIPPacket {
public:
    /**
     * @brief Constructor: Initializes base class and invokes __filter if Ethernet is present.
     *
     * @param rawPacketPointer  Owned unique_ptr to the RawPacket.
     * @param addr_map          Initial address mapping (original → new MAC). May be empty.
     * @param lmap              Initial layer presence map. If empty, base class will extract layers.
     *
     * Workflow:
     *   1. Delegate to FIPPacket constructor, which parses layers and computes hash.
     *   2. Check if "Ethernet" appears in layer_map; if so, call __filter() to rewrite MACs.
     */
    EtherPacket(std::unique_ptr<pcpp::RawPacket> rawPacketPointer,
                const std::unordered_map<std::string, std::string>& addr_map = {},
                const std::unordered_map<std::string, bool>& lmap = {})
        : FIPPacket(std::move(rawPacketPointer), addr_map, lmap)
    {
        // If this packet has an Ethernet layer, perform address rewriting
        if (layer_map.find("Ethernet") != layer_map.end()) {
            __filter();
        }
    }

    /**
     * @brief Inspect and modify the Ethernet source/destination MAC addresses.
     *
     * Steps:
     *   1. Retrieve the EthLayer pointer from Packet (pcpp::Packet::getLayerOfType<EthLayer>()).
     *   2. If no Ethernet layer is found, return immediately.
     *   3. Read the original src and dst MAC addresses (as strings).
     *   4. For each address, check if it already exists in address_mapping:
     *        - If yes, use the mapped value.
     *        - If no, generate a random MAC via generate_random_mac(), insert into address_mapping.
     *   5. Set the new MAC addresses on the EthLayer (pcpp::MacAddress).
     */
    void __filter() {
        // Get the Ethernet layer from the parsed packet
        pcpp::EthLayer* ethLayer = Packet.getLayerOfType<pcpp::EthLayer>();
        if (ethLayer == nullptr) {
            // Packet does not actually contain an Ethernet layer
            return;
        }

        // Extract original MAC addresses as strings
        std::string previous_src = ethLayer->getSourceMac().toString();
        std::string previous_dst = ethLayer->getDestMac().toString();

        std::string new_src, new_dst;

        // Determine or generate a replacement for the source MAC
        if (address_mapping.count(previous_src) > 0) {
            new_src = address_mapping[previous_src];
        } else {
            new_src = generate_random_mac();
            address_mapping[previous_src] = new_src;
        }

        // Determine or generate a replacement for the destination MAC
        if (address_mapping.count(previous_dst) > 0) {
            new_dst = address_mapping[previous_dst];
        } else {
            new_dst = generate_random_mac();
            address_mapping[previous_dst] = new_dst;
        }

        // Apply the new addresses back into the EthLayer
        ethLayer->setSourceMac(pcpp::MacAddress(new_src));
        ethLayer->setDestMac(pcpp::MacAddress(new_dst));
    }

    /**
     * @brief Override header preprocessing for EtherPacket.
     *
     * Currently, this simply invokes the base-class behavior (which is a no-op),
     * but can be extended to add further Ethernet-specific modifications if needed.
     */
    void header_preprocessing() override {
        FIPPacket::header_preprocessing();
        // Future: add any additional preprocessing steps here (e.g., VLAN tag stripping).
    }
};
#pragma once

#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <IpAddress.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <PayloadLayer.h>
#include <vector>
#include <cstdint>
#include <Packet.h>
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>

/*
 * =============================================================================
 * Custom IP Header Structures and Layers
 * =============================================================================
 */

#pragma pack(push,1)
/**
 * @struct CustomIPHeader
 * @brief Defines a minimal 8-byte “IP-like” header layout for internal use.
 *
 * Fields (1 byte each):
 *   - version_and_flags: High 4 bits = version, low 4 bits = flags.
 *   - tos             : Type of Service.
 *   - ttl             : Time to Live.
 *   - proto           : Upper-layer protocol (e.g., TCP=6, UDP=17).
 *   - reserved[4]     : Reserved for alignment/possible future use.
 */
struct CustomIPHeader {
    uint8_t version_and_flags;  // high 4 bits: version, low 4 bits: flags
    uint8_t tos;                // Type of Service
    uint8_t ttl;                // Time to Live
    uint8_t proto;              // Protocol number
    uint8_t reserved[4];        // Reserved/padding
};
#pragma pack(pop)

#pragma pack(push, 1)
/**
 * @struct custom_ip_header
 * @brief 4-byte minimal IPv4-like header for the CustomIPLayer.
 *
 * Fields:
 *   - versionAndFlags: 1 byte, high nibble = IP version, low nibble = custom flags.
 *   - typeOfService  : 1 byte, TOS field.
 *   - timeToLive     : 1 byte, TTL value.
 *   - protocol       : 1 byte, encodes the upper-layer protocol.
 */
struct custom_ip_header {
    uint8_t versionAndFlags;  // 4 bits version, 4 bits flags
    uint8_t typeOfService;    // TOS
    uint8_t timeToLive;       // TTL
    uint8_t protocol;         // Protocol number
};
#pragma pack(pop)

/**
 * @class CustomIPLayer
 * @brief Implements a minimal custom IPv4-like header as a pcpp::Layer.
 *
 * Responsibilities:
 *   - Allocate and store a 4-byte custom_ip_header in m_Data.
 *   - Expose getters/setters for version, flags, TOS, TTL, and protocol.
 *   - Provide PcapPlusPlus overrides so it can be inserted into a pcpp::Packet.
 */
class CustomIPLayer : public pcpp::Layer {
public:
    /**
     * @brief Constructor: build a new custom IPv4 header from individual fields.
     *
     * @param version  4-bit IP version (e.g., 4 for IPv4).
     * @param flags    4-bit custom flags.
     * @param tos      8-bit Type of Service.
     * @param ttl      8-bit Time to Live.
     * @param proto    8-bit upper-layer protocol number.
     *
     * Workflow:
     *   1. Allocate m_Data of size sizeof(custom_ip_header).
     *   2. Set m_Protocol = UnknownProtocol (no standard PcapPlusPlus enum).
     *   3. Fill the custom_ip_header fields in network (native) byte order:
     *        - versionAndFlags = (version << 4) | (flags & 0x0F).
     *        - typeOfService  = tos.
     *        - timeToLive     = ttl.
     *        - protocol       = proto.
     *   4. Call computeCalculateFields() to recalc any checksums if needed (no-op here).
     */
    CustomIPLayer(uint8_t version,
                  uint8_t flags,
                  uint8_t tos,
                  uint8_t ttl,
                  uint8_t proto)
    {
        // Allocate header buffer
        m_DataLen  = sizeof(custom_ip_header);
        m_Data     = new uint8_t[m_DataLen];
        m_Protocol = pcpp::UnknownProtocol;

        // Cast m_Data to our struct and populate fields
        auto* hdr = reinterpret_cast<custom_ip_header*>(m_Data);
        hdr->versionAndFlags = static_cast<uint8_t>((version << 4) | (flags & 0x0F));
        hdr->typeOfService   = tos;
        hdr->timeToLive      = ttl;
        hdr->protocol        = proto;

        computeCalculateFields();
    }

    /**
     * @brief Copy constructor: duplicate another CustomIPLayer, copying m_Data.
     */
    CustomIPLayer(const CustomIPLayer& other)
      : Layer(other) 
    {
        m_DataLen = other.m_DataLen;
        m_Data    = new uint8_t[m_DataLen];
        memcpy(m_Data, other.m_Data, m_DataLen);
    }

    virtual ~CustomIPLayer() {
        // Base Layer destructor will free m_Data if it is owned
    }

    /**
     * @brief Return the size of our header (4 bytes).
     */
    virtual size_t getHeaderLen() const override {
        return sizeof(custom_ip_header);
    }

    /**
     * @brief Recompute any dynamic fields. No dynamic fields here, so no action.
     *
     * Called by PcapPlusPlus whenever the packet is re-serialized or length fields need recalculation.
     */
    virtual void computeCalculateFields() override {
        // No additional fields to recalculate (version/flags are static once set).
    }

    /**
     * @brief Called by PcapPlusPlus when parsing subsequent layers.
     * We do not parse any next layer from our custom header, so do nothing.
     */
    void parseNextLayer() override {}

    /**
     * @brief Indicate that this layer sits at the Network layer in the OSI stack.
     */
    pcpp::OsiModelLayer getOsiModelLayer() const override {
        return pcpp::OsiModelNetworkLayer;
    }

    /**
     * @brief Return a human-readable layer name for debugging.
     */
    virtual std::string toString() const override {
        return "CustomIPLayer";
    }

    // ------------------------------------------------------------------------
    // Field Accessors
    // ------------------------------------------------------------------------

    /**
     * @brief Extract the high-nibble (version) from versionAndFlags.
     */
    uint8_t getVersion() const {
        auto* hdr = reinterpret_cast<const custom_ip_header*>(m_Data);
        return hdr->versionAndFlags >> 4;
    }

    /**
     * @brief Extract the low-nibble (flags) from versionAndFlags.
     */
    uint8_t getFlags() const {
        auto* hdr = reinterpret_cast<const custom_ip_header*>(m_Data);
        return hdr->versionAndFlags & 0x0F;
    }

    /**
     * @brief Return the Type of Service field.
     */
    uint8_t getTos() const {
        auto* hdr = reinterpret_cast<const custom_ip_header*>(m_Data);
        return hdr->typeOfService;
    }

    /**
     * @brief Return the Time To Live field.
     */
    uint8_t getTtl() const {
        auto* hdr = reinterpret_cast<const custom_ip_header*>(m_Data);
        return hdr->timeToLive;
    }

    /**
     * @brief Return the Protocol (upper-layer) field.
     */
    uint8_t getProtocol() const {
        auto* hdr = reinterpret_cast<const custom_ip_header*>(m_Data);
        return hdr->protocol;
    }

    // ------------------------------------------------------------------------
    // Field Setters (optional: if you want to change header after creation)
    // ------------------------------------------------------------------------

    /**
     * @brief Update the version (high 4 bits) in versionAndFlags.
     */
    void setVersion(uint8_t v) {
        auto* hdr = reinterpret_cast<custom_ip_header*>(m_Data);
        hdr->versionAndFlags = static_cast<uint8_t>((v << 4) | (hdr->versionAndFlags & 0x0F));
    }

    /**
     * @brief Update the flags (low 4 bits) in versionAndFlags.
     */
    void setFlags(uint8_t f) {
        auto* hdr = reinterpret_cast<custom_ip_header*>(m_Data);
        hdr->versionAndFlags = static_cast<uint8_t>((hdr->versionAndFlags & 0xF0) | (f & 0x0F));
    }

    // Similar setters can be added for TOS, TTL, and protocol if desired
};


#pragma pack(push, 1)
/**
 * @struct custom_ipv6_header
 * @brief 4-byte minimal IPv6-like header layout for CustomIPv6Layer.
 *
 * Fields:
 *   - version      : 8-bit version (high nibble valid, low nibble zero).
 *   - trafficClass : 8-bit Traffic Class.
 *   - nextHeader   : 8-bit next header field (upper-layer protocol).
 *   - hopLimit     : 8-bit Hop Limit.
 */
struct custom_ipv6_header {
    uint8_t version;      ///< IPv6 version (e.g., 6) in high nibble
    uint8_t trafficClass; ///< Traffic Class field
    uint8_t nextHeader;   ///< Next Layer protocol (e.g., TCP=6, UDP=17)
    uint8_t hopLimit;     ///< Hop Limit field
};
#pragma pack(pop)

/**
 * @class CustomIPv6Layer
 * @brief Implements a minimal custom IPv6-like header as a pcpp::Layer.
 *
 * Responsibilities:
 *   - Allocate and store a 4-byte custom_ipv6_header in m_Data.
 *   - Expose getters/setters for version, trafficClass, nextHeader, and hopLimit.
 *   - Provide necessary PcapPlusPlus overrides for header length, parsing, and serialization.
 */
class CustomIPv6Layer : public pcpp::Layer {
public:
    /**
     * @brief Constructor: build a new custom IPv6 header from individual fields.
     *
     * @param version  8-bit version (e.g., 6 for IPv6; lower nibble unused).
     * @param tc       8-bit Traffic Class.
     * @param nh       8-bit Next Header (upper-layer protocol).
     * @param hlim     8-bit Hop Limit.
     *
     * Workflow:
     *   1. Allocate m_Data of size sizeof(custom_ipv6_header).
     *   2. Set m_Protocol = UnknownProtocol (no standard PcapPlusPlus enum).
     *   3. Fill the custom_ipv6_header fields directly:
     *        - version       = version.
     *        - trafficClass  = tc.
     *        - nextHeader    = nh.
     *        - hopLimit      = hlim.
     *   4. Call computeCalculateFields() (no dynamic fields here).
     */
    CustomIPv6Layer(uint8_t version,
                    uint8_t tc,
                    uint8_t nh,
                    uint8_t hlim)
    {
        m_DataLen  = sizeof(custom_ipv6_header);
        m_Data     = new uint8_t[m_DataLen];
        m_Protocol = pcpp::UnknownProtocol;

        auto* hdr = reinterpret_cast<custom_ipv6_header*>(m_Data);
        hdr->version      = version;
        hdr->trafficClass = tc;
        hdr->nextHeader   = nh;
        hdr->hopLimit     = hlim;

        computeCalculateFields();
    }

    /**
     * @brief Copy constructor: duplicate another CustomIPv6Layer, copying m_Data.
     */
    CustomIPv6Layer(const CustomIPv6Layer& other)
      : Layer(other)
    {
        m_DataLen = other.m_DataLen;
        m_Data    = new uint8_t[m_DataLen];
        memcpy(m_Data, other.m_Data, m_DataLen);
    }

    virtual ~CustomIPv6Layer() = default;

    /**
     * @brief Return the size of our header (4 bytes).
     */
    virtual size_t getHeaderLen() const override {
        return sizeof(custom_ipv6_header);
    }

    /**
     * @brief Recompute dynamic fields. No dynamic fields here, so no action.
     */
    virtual void computeCalculateFields() override {
        // Nothing to recalc for our simple header
    }

    /**
     * @brief Called by PcapPlusPlus when parsing subsequent layers. We stop here.
     */
    void parseNextLayer() override {}

    /**
     * @brief Return a human-readable layer name.
     */
    virtual std::string toString() const override {
        return "CustomIPv6Layer";
    }

    /**
     * @brief Indicate this is a Network layer (IPv6).
     */
    pcpp::OsiModelLayer getOsiModelLayer() const override {
        return pcpp::OsiModelNetworkLayer;
    }

    // ------------------------------------------------------------------------
    // Field Accessors
    // ------------------------------------------------------------------------

    uint8_t getVersion() const {
        auto* hdr = reinterpret_cast<const custom_ipv6_header*>(m_Data);
        return hdr->version;
    }

    uint8_t getTrafficClass() const {
        auto* hdr = reinterpret_cast<const custom_ipv6_header*>(m_Data);
        return hdr->trafficClass;
    }

    uint8_t getNextHeader() const {
        auto* hdr = reinterpret_cast<const custom_ipv6_header*>(m_Data);
        return hdr->nextHeader;
    }

    uint8_t getHopLimit() const {
        auto* hdr = reinterpret_cast<const custom_ipv6_header*>(m_Data);
        return hdr->hopLimit;
    }

    // ------------------------------------------------------------------------
    // Field Setters
    // ------------------------------------------------------------------------

    void setVersion(uint8_t v) {
        reinterpret_cast<custom_ipv6_header*>(m_Data)->version = v;
    }

    void setTrafficClass(uint8_t tc) {
        reinterpret_cast<custom_ipv6_header*>(m_Data)->trafficClass = tc;
    }

    void setNextHeader(uint8_t nh) {
        reinterpret_cast<custom_ipv6_header*>(m_Data)->nextHeader = nh;
    }

    void setHopLimit(uint8_t hlim) {
        reinterpret_cast<custom_ipv6_header*>(m_Data)->hopLimit = hlim;
    }
};


/*
 * =============================================================================
 * Custom TCP Layer
 * =============================================================================
 */

#pragma pack(push,1)
/**
 * @struct CustomTCPHeader
 * @brief Minimal representation of a TCP header storing only flags in network byte order.
 *
 * Fields:
 *   - flags: 16-bit TCP flags, already converted to network byte order by the constructor.
 *   - Raw TCP options (variable length) follow this 2-byte field in the payload.
 */
struct CustomTCPHeader {
    uint16_t flags;    // TCP flags (in network byte order)
    // options follow immediately, but not part of this struct layout
};
#pragma pack(pop)

/**
 * @class CustomTCPLayer
 * @brief Implements a custom TCP header that contains only flags and raw options, as a pcpp::Layer.
 *
 * Responsibilities:
 *   - Allocate a buffer containing a 2-byte flags field (network byte order) followed by raw options.
 *   - Provide parseNextLayer() to create a PayloadLayer for any bytes beyond the header.
 *   - Expose getCustomHeader() to access the CustomTCPHeader in the buffer.
 *   - Override required Layer methods (getHeaderLen(), computeCalculateFields(), toString(), getOsiModelLayer()).
 */
class CustomTCPLayer : public pcpp::Layer {
public:
    /**
     * @brief Constructor: build a custom TCP header with flags and options.
     *
     * @param flags    16-bit TCP flags in host byte order (will be converted to network order).
     * @param options  Vector<uint8_t> of raw TCP options bytes (variable length).
     *
     * Workflow:
     *   1. Convert flags to network byte order (htons).
     *   2. Resize internal `_buffer` to hold 2 bytes (flags) + options.size().
     *   3. Copy `flagsNet` into `_buffer[0..1]`, then append `options`.
     *   4. Set m_Data = pointer to `_buffer` data, and m_DataLen = `_buffer.size()`.
     *   5. Call computeCalculateFields() (no dynamic fields here).
     */
    CustomTCPLayer(uint16_t flags, const std::vector<uint8_t>& options)
        : Layer(nullptr, 0, nullptr, 0)
    {
        // Convert flags to network byte order
        uint16_t flagsNet = htons(flags);

        // Build buffer: flags(2 bytes) + options
        _buffer.resize(sizeof(CustomTCPHeader));
        memcpy(_buffer.data(), &flagsNet, sizeof(flagsNet));
        _buffer.insert(_buffer.end(), options.begin(), options.end());

        m_Data    = _buffer.data();
        m_DataLen = _buffer.size();
        computeCalculateFields();
    }

    /**
     * @brief Access the custom TCP header (first 2 bytes) from the buffer.
     */
    CustomTCPHeader* getCustomHeader() const {
        return reinterpret_cast<CustomTCPHeader*>(const_cast<uint8_t*>(m_Data));
    }

    /**
     * @brief parseNextLayer: any bytes beyond the header become a PayloadLayer.
     */
    void parseNextLayer() override {
        size_t headerLen = getHeaderLen();
        if (m_DataLen > headerLen) {
            // The remaining bytes form a payload
            m_NextLayer = new pcpp::PayloadLayer(
                m_Data + headerLen,
                m_DataLen - headerLen,
                this,
                m_Packet
            );
        }
    }

    /**
     * @brief Recompute dynamic fields. No dynamic fields, so no action.
     */
    void computeCalculateFields() override {
        // No checksums or length fields to recalc here
    }

    /**
     * @brief Return a human-readable string for this layer.
     */
    std::string toString() const override {
        return "CustomTCPLayer(len=" + std::to_string(getHeaderLen()) + ")";
    }

    /**
     * @brief Indicate this layer is at the Transport layer in OSI model.
     */
    pcpp::OsiModelLayer getOsiModelLayer() const override {
        return pcpp::OsiModelTransportLayer;
    }

    /**
     * @brief Return the header length (flags + options).
     */
    size_t getHeaderLen() const override {
        return _buffer.size();
    }

    /**
     * @brief Return a short name for the layer (TCP).
     */
    std::string getName() const {
        return "TCP";
    }

private:
    std::vector<uint8_t> _buffer;  ///< Internal buffer storing flags + options
};

/*
 * =============================================================================
 * Custom UDP Layer
 * =============================================================================
 */

/**
 * @class CustomUDPLayer
 * @brief Implements a “no-op” UDP layer (zero-length), primarily for consistency.
 *
 * Responsibilities:
 *   - Provide getHeaderLen() = 0 (no UDP header).
 *   - parseNextLayer() will consume any remaining bytes as PayloadLayer.
 *   - Override computeCalculateFields(), toString(), getOsiModelLayer(), getName().
 */
class CustomUDPLayer : public pcpp::Layer {
public:
    /**
     * @brief Constructor: no header data is allocated (m_Data = nullptr, m_DataLen = 0).
     */
    CustomUDPLayer()
        : Layer(nullptr, 0, nullptr, 0)
    {
        m_Data    = nullptr;
        m_DataLen = 0;
        computeCalculateFields();
    }

    /**
     * @brief parseNextLayer: if there is any data beyond “header” (none), treat as payload.
     */
    void parseNextLayer() override {
        if (m_DataLen > getHeaderLen()) {
            m_NextLayer = new pcpp::PayloadLayer(
                m_Data + getHeaderLen(),
                m_DataLen - getHeaderLen(),
                this,
                m_Packet
            );
        }
    }

    /**
     * @brief No dynamic fields, so no action.
     */
    void computeCalculateFields() override {}

    /**
     * @brief Return human-readable name for debugging.
     */
    std::string toString() const override {
        return "CustomUDPLayer(len=0)";
    }

    /**
     * @brief Indicate this layer is at the Transport layer (UDP).
     */
    pcpp::OsiModelLayer getOsiModelLayer() const override {
        return pcpp::OsiModelTransportLayer;
    }

    /**
     * @brief Return header length (zero bytes).
     */
    size_t getHeaderLen() const override {
        return 0;
    }

    /**
     * @brief Return short layer name.
     */
    std::string getName() const {
        return "UDP";
    }
};

/*
 * =============================================================================
 * Custom HTTP Layer
 * =============================================================================
 */

/**
 * @class CustomHTTP
 * @brief Base class for custom HTTP layers (requests and responses).
 *
 * Responsibilities:
 *   - Maintain a vector<Field> of HTTP header field name/value pairs.
 *   - On computeCalculateFields(), serialize those fields into m_Data as ASCII text:
 *        • For “Method” or “Path” or “Status_Code”, output “value ”.
 *        • For other fields, output “Name: Value\r\n”.
 *   - Set m_Protocol = UnknownProtocol, since this is an application-layer payload.
 *   - Provide getHeaderLen(), parseNextLayer() (no next layer), toString(), getOsiModelLayer().
 */
class CustomHTTP : public pcpp::Layer {
public:
    /**
     * @struct Field
     * @brief Represents one HTTP header field with name and value.
     */
    struct Field { 
        std::string name;  ///< Field name (e.g., "User-Agent")
        std::string value; ///< Field value (e.g., "Mozilla/5.0")
    };

    std::vector<Field> fields;  ///< List of all fields in this HTTP layer

    /**
     * @brief Constructor: initialize with no fields, m_DataLen = 0.
     */
    CustomHTTP()
    {
        m_Protocol = pcpp::UnknownProtocol;
        m_DataLen  = 0;
        m_Data     = nullptr;
        computeCalculateFields();
    }

    /**
     * @brief Add an HTTP header field (name:value) to this layer.
     *
     * @param fieldName   Name of the header (e.g., "Content-Type").
     * @param fieldValue  Value of the header (e.g., "text/html").
     */
    void addField(const std::string& fieldName, const std::string& fieldValue)
    {
        fields.push_back({fieldName, fieldValue});
    }

    /**
     * @brief Serialize all fields into m_Data buffer as ASCII text.
     *
     * Workflow:
     *   1. Create a std::ostringstream.
     *   2. For each field in `fields`:
     *        - If field.value is empty, skip it.
     *        - If field.name is "Method", "Path", or "Status_Code", append "value " (space, not CRLF).
     *        - Otherwise, append "Name: Value\r\n".
     *   3. Convert the stream to a string `serialized`.
     *   4. Allocate m_Data of length serialized.size() and copy serialized.data() to m_Data.
     */
    void computeCalculateFields() override
    {
        std::ostringstream stream;
        for (const auto& field : fields) {
            if (field.value.empty())
                continue;

            if (field.name == "Method" || field.name == "Path" || field.name == "Status_Code") {
                stream << field.value << ' ';
            } else {
                stream << field.name << ": " << field.value << "\r\n";
            }
        }
        std::string serialized = stream.str();

        m_DataLen = serialized.size();
        m_Data = new uint8_t[m_DataLen];
        std::memcpy(m_Data, serialized.data(), m_DataLen);
    }

    /**
     * @brief Return the header length (size of m_Data).
     */
    size_t getHeaderLen() const override {
        return m_DataLen;
    }

    /**
     * @brief No subsequent layer is parsed (application layer terminates).
     */
    void parseNextLayer() override {
        m_NextLayer = nullptr;
    }

    /**
     * @brief Human-readable name for this layer.
     */
    std::string toString() const override {
        return "CustomHTTP Layer";
    }

    /**
     * @brief Indicate that this layer is at the Application layer (HTTP).
     */
    pcpp::OsiModelLayer getOsiModelLayer() const override {
        return pcpp::OsiModelApplicationLayer;
    }
};

/**
 * @class CustomHTTPRequest
 * @brief Specialization of CustomHTTP for HTTP request messages.
 *
 * Responsibilities:
 *   - On construction, pre-populate common HTTP request fields with defaults:
 *        • Method  = "GET"
 *        • Path    = "/"
 *        • User_Agent, Content_Type, Connection, Accept, Accept_Charset, Accept_Encoding, Cookie, TE
 *          all begin as empty.
 *   - After construction, call computeCalculateFields() to build m_Data from defaults.
 */
class CustomHTTPRequest : public CustomHTTP {
public:
    /**
     * @brief Constructor: initialize standard request fields with default values.
     */
    CustomHTTPRequest()
    {
        // Set default request-line fields
        addField("Method", "GET");
        addField("Path", "/");
        // Add common header fields (initially empty)
        addField("User_Agent",      "");
        addField("Content_Type",    "");
        addField("Connection",      "");
        addField("Accept",          "");
        addField("Accept_Charset",  "");
        addField("Accept_Encoding", "");
        addField("Cookie",          "");
        addField("TE",              "");
        computeCalculateFields();
    }

    /**
     * @brief Human-readable name override.
     */
    virtual std::string toString() const override {
        return "HTTP Request Layer";
    }

    /**
     * @brief Return the layer name for printing or debugging.
     */
    std::string getName() const {
        return "HTTP Request";
    }
};

/**
 * @class CustomHTTPResponse
 * @brief Specialization of CustomHTTP for HTTP response messages.
 *
 * Responsibilities:
 *   - On construction, pre-populate common HTTP response fields with defaults:
 *        • Status_Code       = "200"
 *        • Connection, Content_Encoding, Content_Type, Server, Set_Cookie, Transfer_Encoding
 *          all begin as empty.
 *   - After construction, call computeCalculateFields() to build m_Data from defaults.
 */
class CustomHTTPResponse : public CustomHTTP {
public:
    /**
     * @brief Constructor: initialize standard response fields with default values.
     */
    CustomHTTPResponse()
    {
        // Set default response-line field
        addField("Status_Code", "200");
        // Add common response headers (initially empty)
        addField("Connection",         "");
        addField("Content_Encoding",   "");
        addField("Content_Type",       "");
        addField("Server",             "");
        addField("Set_Cookie",         "");
        addField("Transfer_Encoding",  "");
        computeCalculateFields();
    }

    /**
     * @brief Human-readable name override.
     */
    virtual std::string toString() const override {
        return "HTTP Response Layer";
    }

    /**
     * @brief Return the layer name for printing or debugging.
     */
    std::string getName() const {
        return "HTTP Response";
    }
};

/*
 * =============================================================================
 * Custom DNS Layers (Question Record, Resource Record, Header)
 * =============================================================================
 */

/**
 * @class CustomDNSQR
 * @brief Represents a custom DNS Question Record (QNAME, QTYPE, QCLASS).
 *
 * Responsibilities:
 *   - Store qname (domain name string) and qtype (DNS query type, e.g., A=1).
 *   - On computeCalculateFields(), encode qname in DNS wire format:
 *        • Split qname by '.', write each label as length-prefixed.
 *        • Terminate with a null byte.
 *        • Append QTYPE (2 bytes, network byte order) and QCLASS=1 (IN, 2 bytes).
 *   - Provide getHeaderLen(), parseNextLayer() (no next), toString(), getOsiModelLayer().
 */
class CustomDNSQR : public pcpp::Layer {
public:
    std::string qname;    ///< Domain name (e.g., "example.com")
    uint16_t qtype;       ///< Query type (e.g., 1 for A)

    /**
     * @brief Constructor: store qname and qtype (default “none”, type=1).
     */
    CustomDNSQR(const std::string& name = "none", uint16_t type = 1)
        : Layer(), qname(name), qtype(type)
    {
        m_Protocol = pcpp::UnknownProtocol;
        m_DataLen  = 0;
        m_Data     = nullptr;
    }

    /**
     * @brief Change the stored qname.
     */
    void setQName(const std::string& name) { qname = name; }

    /**
     * @brief Change the stored qtype.
     */
    void setQType(uint16_t type)    { qtype = type; }

    /**
     * @brief Serialize the DNS question into m_Data in standard DNS “QNAME” + “QTYPE QCLASS” format.
     *
     * Workflow:
     *   1. Split `qname` on '.' into labels vector.
     *   2. Compute `nameLen` = sum(labelLengths + 1) + 1 for final null byte.
     *   3. m_DataLen = nameLen + 4 (2 bytes QTYPE + 2 bytes QCLASS).
     *   4. Allocate m_Data = new uint8_t[m_DataLen].
     *   5. Write each label with length prefix, then a final 0 byte.
     *   6. Write QTYPE in network byte order, then QCLASS=1 (IN) in network order.
     */
    void computeCalculateFields() override {
        // 1) Split qname into labels by '.'
        std::vector<std::string> labels;
        std::istringstream iss(qname);
        std::string label;
        while (std::getline(iss, label, '.')) {
            labels.push_back(label);
        }

        // 2) Compute length of name portion
        size_t nameLen = 1;  // final null
        for (auto& lbl : labels) {
            nameLen += lbl.size() + 1;  // length byte + label
        }

        // 3) Total length = nameLen + 2 bytes QTYPE + 2 bytes QCLASS
        m_DataLen = nameLen + 4;
        m_Data = new uint8_t[m_DataLen];

        // 4) Fill QNAME
        size_t offset = 0;
        for (auto& lbl : labels) {
            m_Data[offset++] = static_cast<uint8_t>(lbl.size());  // label length
            memcpy(m_Data + offset, lbl.data(), lbl.size());
            offset += lbl.size();
        }
        m_Data[offset++] = 0;  // end of QNAME

        // 5) Write QTYPE in network order
        uint16_t netType = htons(qtype);
        memcpy(m_Data + offset, &netType, sizeof(netType));
        offset += sizeof(netType);

        // 6) Write QCLASS = 1 (IN) in network order
        uint16_t qclass = htons(1);
        memcpy(m_Data + offset, &qclass, sizeof(qclass));
    }

    /**
     * @brief Return the question-record length.
     */
    size_t getHeaderLen() const override {
        return m_DataLen;
    }

    /**
     * @brief No next layer to parse (application layer terminates).
     */
    void parseNextLayer() override {
        m_NextLayer = nullptr;
    }

    /**
     * @brief Human-readable layer name.
     */
    std::string toString() const override {
        return "Custom DNS Question Record";
    }

    /**
     * @brief Indicate this is an application-layer object (DNS).
     */
    pcpp::OsiModelLayer getOsiModelLayer() const override {
        return pcpp::OsiModelApplicationLayer;
    }

    /**
     * @brief Return a short name for this custom layer.
     */
    std::string getName() const {
        return "DNS Question Record";
    }
};

/**
 * @class CustomDNSRR
 * @brief Represents a custom DNS Resource Record (RR) without RDATA.
 *
 * Responsibilities:
 *   - Store rrname (domain name), type (e.g., A=1), and TTL (time to live).
 *   - On computeCalculateFields(), serialize the RR in DNS wire format:
 *        • NAME (labels + null terminator).
 *        • TYPE (2 bytes), CLASS=1 (2 bytes), TTL (4 bytes), RDLENGTH=0 (2 bytes).
 *   - Provide getHeaderLen(), parseNextLayer(), toString(), getOsiModelLayer().
 */
class CustomDNSRR : public pcpp::Layer {
public:
    std::string rrname;  ///< Domain name for the RR (e.g., "example.com")
    uint16_t type;       ///< RR type (e.g., 1 for A record)
    uint32_t ttl;        ///< Time to Live for this record

    /**
     * @brief Constructor: store rrname, type, and TTL. No m_Data allocated yet.
     */
    CustomDNSRR(const std::string& name = "",
                uint16_t t = 1,
                uint32_t timeToLive = 0)
        : Layer(), rrname(name), type(t), ttl(timeToLive)
    {
        m_Protocol = pcpp::UnknownProtocol;
        m_DataLen  = 0;
        m_Data     = nullptr;
    }

    /**
     * @brief Update the stored RR name.
     */
    void setRRName(const std::string& name) { rrname = name; }

    /**
     * @brief Update the stored type.
     */
    void setType(uint16_t t) { type = t; }

    /**
     * @brief Update the stored TTL.
     */
    void setTTL(uint32_t timeToLive) { ttl = timeToLive; }

    /**
     * @brief Serialize the RR into m_Data in DNS wire format (excluding RDATA).
     *
     * Workflow:
     *   1. Split rrname into labels by '.'.
     *   2. Compute nameLen = sum(label lengths + 1) + 1 for terminating null.
     *   3. Total length = nameLen + 2(TYPE) + 2(CLASS) + 4(TTL) + 2(RDLENGTH=0).
     *   4. Allocate m_Data of size m_DataLen.
     *   5. Write NAME (labels + null).
     *   6. Write TYPE in network order.
     *   7. Write CLASS=1 (IN) in network order.
     *   8. Write TTL in network order.
     *   9. Write RDLENGTH=0 in network order.
     */
    void computeCalculateFields() override {
        // 1) Split rrname into labels
        std::vector<std::string> labels;
        std::istringstream iss(rrname);
        std::string label;
        while (std::getline(iss, label, '.')) {
            labels.push_back(label);
        }

        // 2) Compute length of NAME portion
        size_t nameLen = 1;  // final null
        for (auto& lbl : labels) {
            nameLen += lbl.size() + 1;
        }

        // 3) Total length = nameLen + 2 bytes TYPE + 2 bytes CLASS + 4 bytes TTL + 2 bytes RDLENGTH
        m_DataLen = nameLen + 10;
        m_Data = new uint8_t[m_DataLen];

        // 4) Fill NAME
        size_t offset = 0;
        for (auto& lbl : labels) {
            m_Data[offset++] = static_cast<uint8_t>(lbl.size());
            memcpy(m_Data + offset, lbl.data(), lbl.size());
            offset += lbl.size();
        }
        m_Data[offset++] = 0;  // end of NAME

        // 5) Write TYPE
        uint16_t netType = htons(type);
        memcpy(m_Data + offset, &netType, sizeof(netType));
        offset += sizeof(netType);

        // 6) Write CLASS = 1 (IN)
        uint16_t qclass = htons(1);
        memcpy(m_Data + offset, &qclass, sizeof(qclass));
        offset += sizeof(qclass);

        // 7) Write TTL
        uint32_t netTTL = htonl(ttl);
        memcpy(m_Data + offset, &netTTL, sizeof(netTTL));
        offset += sizeof(netTTL);

        // 8) Write RDLENGTH = 0 (no RDATA)
        uint16_t rdlen = htons(0);
        memcpy(m_Data + offset, &rdlen, sizeof(rdlen));
    }

    /**
     * @brief Return the length of the RR (header only, no RDATA).
     */
    size_t getHeaderLen() const override {
        return m_DataLen;
    }

    /**
     * @brief No next layer is parsed (application layer).
     */
    void parseNextLayer() override {
        m_NextLayer = nullptr;
    }

    /**
     * @brief Human-readable layer name.
     */
    std::string toString() const override {
        return "Custom DNS Resource Record";
    }

    /**
     * @brief Indicate this is an application-layer DNS RR.
     */
    pcpp::OsiModelLayer getOsiModelLayer() const override {
        return pcpp::OsiModelApplicationLayer;
    }

    /**
     * @brief Return short layer name.
     */
    std::string getName() const {
        return "DNS Resource Record";
    }
};

/**
 * @class CustomDNS
 * @brief Represents a custom DNS header (12 bytes) without any question or record bodies.
 *
 * Responsibilities:
 *   - Store DNS header fields (QR, opcode, AA, TC, RD, RA, Z, AD, CD, rcode).
 *   - Store section counts: qdCount (questions), anCount (answers),
 *                          nsCount (authority), arCount (additional).
 *   - On computeCalculateFields(), build a 12-byte DNS header in wire format:
 *        • ID (2 bytes) = 0.
 *        • Flags (2 bytes) assembled from individual bits.
 *        • QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT (each 2 bytes, network order).
 *   - Provide getHeaderLen(), parseNextLayer(), toString(), getOsiModelLayer().
 */
class CustomDNS : public pcpp::Layer {
public:
    // DNS FLAGS (1 bit each except opcode (4 bits) and rcode (4 bits))
    bool qr = false;         ///< Query (0) or Response (1)
    uint8_t opcode = 0;      ///< 4-bit operation code
    bool aa = false;         ///< Authoritative Answer
    bool tc = false;         ///< Truncation
    bool rd = true;          ///< Recursion Desired (default true)
    bool ra = false;         ///< Recursion Available
    bool z = false;          ///< Reserved (zero)
    bool ad = false;         ///< Authenticated Data
    bool cd = false;         ///< Checking Disabled
    uint8_t rcode = 0;       ///< 4-bit response code

    // SECTION COUNTS
    uint16_t qdCount = 0;    ///< Number of question records
    uint16_t anCount = 0;    ///< Number of answer records
    uint16_t nsCount = 0;    ///< Number of authority records
    uint16_t arCount = 0;    ///< Number of additional records

    /**
     * @brief Constructor: initialize all DNS header fields to defaults (zero except RD).
     */
    CustomDNS() {
        m_Protocol = pcpp::UnknownProtocol;
        m_DataLen  = 0;
        m_Data     = nullptr;
    }

    /**
     * @brief Serialize the 12-byte DNS header into m_Data in wire format.
     *
     * Workflow:
     *   1. m_DataLen = 12.
     *   2. Allocate m_Data = new uint8_t[12].
     *   3. Write ID = 0 (2 bytes, network order).
     *   4. Build flags field (16 bits) by shifting individual bits into correct positions:
     *        - bit15: QR
     *        - bits14-11: opcode
     *        - bit10: AA
     *        - bit9: TC
     *        - bit8: RD
     *        - bit7: RA
     *        - bit6: Z
     *        - bit5: AD
     *        - bit4: CD
     *        - bits3-0: rcode
     *      Write flags as 2 bytes in network order.
     *   5. Write qdCount, anCount, nsCount, arCount each as 2 bytes in network order.
     */
    void computeCalculateFields() override {
        m_DataLen = 12;
        m_Data = new uint8_t[m_DataLen];
        size_t offset = 0;

        // 1) ID = 0
        uint16_t id = 0;
        uint16_t netId = htons(id);
        memcpy(m_Data + offset, &netId, sizeof(netId));
        offset += sizeof(netId);

        // 2) Build flags in a 16-bit field
        uint16_t flags = 0;
        flags |= (qr  ? 1u << 15 : 0);
        flags |= (static_cast<uint16_t>(opcode & 0xF) << 11);
        flags |= (aa  ? 1u << 10 : 0);
        flags |= (tc  ? 1u << 9  : 0);
        flags |= (rd  ? 1u << 8  : 0);
        flags |= (ra  ? 1u << 7  : 0);
        flags |= (z   ? 1u << 6  : 0);
        flags |= (ad  ? 1u << 5  : 0);
        flags |= (cd  ? 1u << 4  : 0);
        flags |= (static_cast<uint16_t>(rcode & 0xF));
        uint16_t netFlags = htons(flags);
        memcpy(m_Data + offset, &netFlags, sizeof(netFlags));
        offset += sizeof(netFlags);

        // 3) Write section counts (network order)
        auto writeCount = [&](uint16_t val) {
            uint16_t netVal = htons(val);
            memcpy(m_Data + offset, &netVal, sizeof(netVal));
            offset += sizeof(netVal);
        };
        writeCount(qdCount);
        writeCount(anCount);
        writeCount(nsCount);
        writeCount(arCount);
    }

    /**
     * @brief Return the fixed header length (12 bytes).
     */
    size_t getHeaderLen() const override {
        return m_DataLen;
    }

    /**
     * @brief No next layer is parsed (DNS header stands alone; questions/records inserted separately).
     */
    void parseNextLayer() override {
        m_NextLayer = nullptr;
    }

    /**
     * @brief Human-readable layer name for debugging.
     */
    std::string toString() const override {
        return "Custom DNS Header";
    }

    /**
     * @brief Indicate application-layer (DNS).
     */
    pcpp::OsiModelLayer getOsiModelLayer() const override {
        return pcpp::OsiModelApplicationLayer;
    }

    /**
     * @brief Return short layer name.
     */
    std::string getName() const {
        return "DNS";
    }
};
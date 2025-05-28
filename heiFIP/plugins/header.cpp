#pragma once

#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <IpAddress.h>
#include <TcpLayer.h>
#include <vector>
#include <cstdint>
#include <TcpLayer.h>
#include <Packet.h>
#include <iostream>
#include "UdpLayer.h"
#include "Packet.h"
#include <string>
#include <PayloadLayer.h>
#include <fstream>
#include <sstream>

#pragma pack(push,1)
struct CustomIPHeader {
    uint8_t version_and_flags; // high 4 bits: version, low 4 bits: flags
    uint8_t tos;
    uint8_t ttl;
    uint8_t proto;
    uint8_t reserved[4];
};
#pragma pack(pop)

/**
 * CustomIPLayer implements an 8-byte minimal IPv4-like header.
 */
#pragma pack(push, 1)
struct custom_ip_header {
    uint8_t versionAndFlags;  // high nibble = version, low nibble = flags
    uint8_t typeOfService;
    uint8_t timeToLive;
    uint8_t protocol;
};
#pragma pack(pop)

class CustomIPLayer : public pcpp::Layer {
public:
    CustomIPLayer(uint8_t version,
                  uint8_t flags,
                  uint8_t tos,
                  uint8_t ttl,
                  uint8_t proto)
    {
        m_DataLen = sizeof(custom_ip_header);
        m_Data = new uint8_t[m_DataLen];
        m_DataLen   = sizeof(custom_ip_header);
        m_Protocol  = pcpp::UnknownProtocol;  // or a custom enum
        auto* hdr   = reinterpret_cast<custom_ip_header*>(m_Data);
        hdr->versionAndFlags = uint8_t((version << 4) | (flags & 0x0F));
        hdr->typeOfService   = tos;
        hdr->timeToLive      = ttl;
        hdr->protocol        = proto;
        computeCalculateFields();
    }

    // Copy constructor
    CustomIPLayer(const CustomIPLayer& other)
      : Layer(other)
    {
        m_Data     = new uint8_t[other.m_DataLen];
        m_DataLen  = other.m_DataLen;
        memcpy(m_Data, other.m_Data, m_DataLen);
    }

    virtual ~CustomIPLayer() { /* base~ will free m_Data if owned */ }

    // Must override this to tell PcapPlusPlus how big your header is
    virtual size_t getHeaderLen() const override {
        return sizeof(custom_ip_header);
    }

    // Called when layer is re-serialized: recalc versionAndFlags byte
    virtual void computeCalculateFields() override {
        auto* hdr = reinterpret_cast<custom_ip_header*>(m_Data);
        // version and flags are already baked in, so nothing to do here
        // unless you expose setters that modify version or flags
    }

    // Called by PcapPlusPlus when parsing next layer—return nullptr since
    // we don’t know what comes after our custom IP layer.
    void parseNextLayer() override {}

    pcpp::OsiModelLayer getOsiModelLayer() const override {
        return pcpp::OsiModelNetworkLayer;
    }

    // Human-readable name
    virtual std::string toString() const override {
        return "CustomIPLayer";
    }

    // Field accessors
    uint8_t getVersion() const {
        return (reinterpret_cast<custom_ip_header*>(m_Data)->versionAndFlags) >> 4;
    }
    uint8_t getFlags() const {
        return reinterpret_cast<custom_ip_header*>(m_Data)->versionAndFlags & 0x0F;
    }
    uint8_t getTos() const {
        return reinterpret_cast<custom_ip_header*>(m_Data)->typeOfService;
    }
    uint8_t getTtl() const {
        return reinterpret_cast<custom_ip_header*>(m_Data)->timeToLive;
    }
    uint8_t getProtocol() const {
        return reinterpret_cast<custom_ip_header*>(m_Data)->protocol;
    }

    // (Optional) setters that update the header and then recalc:
    void setVersion(uint8_t v) {
        auto* hdr = reinterpret_cast<custom_ip_header*>(m_Data);
        hdr->versionAndFlags = uint8_t((v << 4) | (hdr->versionAndFlags & 0x0F));
    }
    void setFlags(uint8_t f) {
        auto* hdr = reinterpret_cast<custom_ip_header*>(m_Data);
        hdr->versionAndFlags = uint8_t((hdr->versionAndFlags & 0xF0) | (f & 0x0F));
    }
    // … similarly setTos, setTtl, setProtocol …
};


#pragma pack(push, 1)
struct custom_ipv6_header {
    uint8_t version;     ///< high-nibble used, low-nibble zero
    uint8_t trafficClass;
    uint8_t nextHeader;  ///< “nh” in your Scapy code
    uint8_t hopLimit;    ///< “hlim”
};
#pragma pack(pop)

class CustomIPv6Layer : public pcpp::Layer {
public:
    /// Build a brand-new header
    CustomIPv6Layer(uint8_t version,
                    uint8_t tc,
                    uint8_t nh,
                    uint8_t hlim)
    {
        m_DataLen  = sizeof(custom_ipv6_header);
        m_Data     = new uint8_t[m_DataLen];
        m_Protocol = pcpp::UnknownProtocol;
        auto* hdr  = reinterpret_cast<custom_ipv6_header*>(m_Data);
        hdr->version      = version;     // you can mask out lower nibble if you like
        hdr->trafficClass = tc;
        hdr->nextHeader   = nh;
        hdr->hopLimit     = hlim;
        computeCalculateFields();
    }

    /// Copy constructor
    CustomIPv6Layer(const CustomIPv6Layer& other)
      : Layer(other)
    {
        m_Data    = new uint8_t[other.m_DataLen];
        m_DataLen = other.m_DataLen;
        memcpy(m_Data, other.m_Data, m_DataLen);
    }

    virtual ~CustomIPv6Layer() = default;

    /// Number of bytes in header
    virtual size_t getHeaderLen() const override {
        return sizeof(custom_ipv6_header);
    }

    /// Called after you change fields; reserialize if needed
    virtual void computeCalculateFields() override {
        // nothing dynamic to recalc here; we just leave the bytes as set
    }

    /// We don’t know what comes next, so stop parsing
    void parseNextLayer() override {}

    /// Friendly name
    virtual std::string toString() const override {
        return "CustomIPv6Layer";
    }
    pcpp::OsiModelLayer getOsiModelLayer() const override {
        return pcpp::OsiModelNetworkLayer;
    }
    //— Field accessors —//

    uint8_t getVersion() const {
        return reinterpret_cast<custom_ipv6_header*>(m_Data)->version;
    }
    uint8_t getTrafficClass() const {
        return reinterpret_cast<custom_ipv6_header*>(m_Data)->trafficClass;
    }
    uint8_t getNextHeader() const {
        return reinterpret_cast<custom_ipv6_header*>(m_Data)->nextHeader;
    }
    uint8_t getHopLimit() const {
        return reinterpret_cast<custom_ipv6_header*>(m_Data)->hopLimit;
    }

    //— Field setters —//

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

#pragma pack(push,1)
struct CustomTCPHeader {
    uint16_t flags;    // TCP flags, network byte order
    // raw options follow immediately
};
#pragma pack(pop)

class CustomTCPLayer : public pcpp::Layer {
    public:
        /**
         * Construct from flags and raw options bytes
         */
        CustomTCPLayer(uint16_t flags, const std::vector<uint8_t>& options)
            : Layer(nullptr, 0, nullptr, 0)
        {
            // Prepare header buffer: flags (2 bytes) + options
            uint16_t flagsNet = htons(flags);
            _buffer.resize(sizeof(CustomTCPHeader));
            memcpy(_buffer.data(), &flagsNet, sizeof(flagsNet));
            _buffer.insert(_buffer.end(), options.begin(), options.end());
    
            m_Data    = _buffer.data();
            m_DataLen = _buffer.size();
            computeCalculateFields();
        }
    
        CustomTCPHeader* getCustomHeader() const {
            return reinterpret_cast<CustomTCPHeader*>(const_cast<uint8_t*>(m_Data));
        }
    
        void parseNextLayer() override {
            size_t headerLen = getHeaderLen();
            if (m_DataLen > headerLen) {
                m_NextLayer = new pcpp::PayloadLayer(m_Data + headerLen,
                                               m_DataLen - headerLen,
                                               this,
                                               m_Packet);
            }
        }
    
        void computeCalculateFields() override {
            // No dynamic fields to compute
        }
    
        std::string toString() const override {
            return "CustomTCPLayer(len=" + std::to_string(getHeaderLen()) + ")";
        }
    
        pcpp::OsiModelLayer getOsiModelLayer() const override {
            return pcpp::OsiModelTransportLayer;
        }
    
        size_t getHeaderLen() const override {
            return _buffer.size();
        }
            
        std::string getName() const {
            return "TCP";
        }
    
    private:
        std::vector<uint8_t> _buffer;
};


class CustomUDPLayer : public pcpp::Layer {
    public:
        CustomUDPLayer()
            : Layer(nullptr, 0, nullptr, 0)
        {
            m_Data    = nullptr;
            m_DataLen = 0;
            computeCalculateFields();
        }
    
        void parseNextLayer() override {
            if (m_DataLen > getHeaderLen())
                m_NextLayer = new pcpp::PayloadLayer(m_Data + getHeaderLen(),
                                               m_DataLen - getHeaderLen(),
                                               this, m_Packet);
        }
    
        void computeCalculateFields() override {}
        std::string toString() const override { return "CustomUDPLayer(len=0)"; }
        pcpp::OsiModelLayer getOsiModelLayer() const override { return pcpp::OsiModelTransportLayer; }
        size_t getHeaderLen() const override { return 0; }
        std::string getName() const {
            return "UDP";
        }
};

class CustomHTTP : public pcpp::Layer
{
public:
    struct Field { std::string name; std::string value; };
    std::vector<Field> fields;

    CustomHTTP()
    {
        m_Protocol = pcpp::UnknownProtocol;
        m_DataLen = 0;
        m_Data = nullptr;
    }

    void addField(const std::string& fieldName, const std::string& fieldValue)
    {
        fields.push_back({fieldName, fieldValue});
    }

    // Serialize fields into m_Data buffer
    void computeCalculateFields() override
    {
        // Ensure stringstream is fully defined by including <sstream>
        std::ostringstream stream;
        for (const auto& field : fields)
        {
            if (field.value.empty())
                continue;
            if (field.name == "Method" || field.name == "Path" || field.name == "Status_Code")
                stream << field.value << ' ';
            else
                stream << field.name << ": " << field.value << "\r\n";
        }
        std::string serialized = stream.str();

        delete[] m_Data;
        m_DataLen = serialized.size();
        m_Data = new uint8_t[m_DataLen];
        std::memcpy(m_Data, serialized.data(), m_DataLen);
    }

    size_t getHeaderLen() const override { return m_DataLen; }
    void parseNextLayer() override { m_NextLayer = nullptr; }
    std::string toString() const override { return "CustomHTTP Layer"; }

    // Required overrides
    pcpp::OsiModelLayer getOsiModelLayer() const override { return pcpp::OsiModelApplicationLayer; }
};

class CustomHTTPRequest : public CustomHTTP {
    public:
        CustomHTTPRequest()
        {
            // Set the default fields with default values
            addField("Method", "GET");
            addField("Path", "/");
            addField("User_Agent", "");
            addField("Content_Type", "");
            addField("Connection", "");
            addField("Accept", "");
            addField("Accept_Charset", "");
            addField("Accept_Encoding", "");
            addField("Cookie", "");
            addField("TE", "");
        }

        virtual std::string toString() const override
        {
            return "HTTP Request Layer";
        }

        std::string getName() const {
            return "HTTP Request";
        }
};

class CustomHTTPResponse : public CustomHTTP {
    public:
        CustomHTTPResponse()
        {
            // Set the default fields with their default values
            addField("Status_Code", "200");
            addField("Connection", "");
            addField("Content_Encoding", "");
            addField("Content_Type", "");
            addField("Server", "");
            addField("Set_Cookie", "");
            addField("Transfer_Encoding", "");
        }

        virtual std::string toString() const override
        {
            return "HTTP Response Layer";
        }

        std::string getName() const {
            return "HTTP Response";
        }
};

class CustomDNSQR : public pcpp::Layer {
    public:
        std::string qname;
        uint16_t qtype;
    
        CustomDNSQR(const std::string& name = "none", uint16_t type = 1)
            : Layer(), qname(name), qtype(type)
        {
            m_Protocol = pcpp::UnknownProtocol;
            m_DataLen = 0;
            m_Data = nullptr;
        }
    
        void setQName(const std::string& name) { qname = name; }
        void setQType(uint16_t type)    { qtype = type; }
    
        // Serialize question into m_Data in DNS wire format
        void computeCalculateFields() override {
            // Encode qname: labels split by '.'
            std::vector<std::string> labels;
            std::istringstream iss(qname);
            std::string label;
            while (std::getline(iss, label, '.'))
                labels.push_back(label);
    
            // Calculate total length: sum(label lengths +1) +1 null + 4 bytes for QType and QClass
            size_t nameLen = 1; // final null
            for (auto& lbl : labels)
                nameLen += lbl.size() + 1;
            m_DataLen = nameLen + 4;
    
            delete[] m_Data;
            m_Data = new uint8_t[m_DataLen];
    
            // Fill QNAME
            size_t offset = 0;
            for (auto& lbl : labels) {
                m_Data[offset++] = static_cast<uint8_t>(lbl.size());
                std::memcpy(m_Data + offset, lbl.data(), lbl.size());
                offset += lbl.size();
            }
            m_Data[offset++] = 0; // end of QNAME
    
            // Fill QTYPE (network order)
            uint16_t netType = htons(qtype);
            std::memcpy(m_Data + offset, &netType, sizeof(netType));
            offset += sizeof(netType);
    
            // Fill QCLASS: 1 (IN)
            uint16_t qclass = htons(1);
            std::memcpy(m_Data + offset, &qclass, sizeof(qclass));
        }
    
        size_t getHeaderLen() const override { return m_DataLen; }
        void parseNextLayer() override { m_NextLayer = nullptr; }
        std::string toString() const override { return "Custom DNS Question Record"; }
    
        // Clone and OSI layer type
        pcpp::OsiModelLayer getOsiModelLayer() const override { return pcpp::OsiModelApplicationLayer; }

        std::string getName() const {
            return "DNS Question Record";
        }
};

class CustomDNSRR : public pcpp::Layer {
    public:
        std::string rrname;
        uint16_t type;
        uint32_t ttl;
    
        CustomDNSRR(const std::string& name = "", uint16_t t = 1, uint32_t timeToLive = 0)
            : Layer(), rrname(name), type(t), ttl(timeToLive)
        {
            m_Protocol = pcpp::UnknownProtocol;
            m_DataLen = 0;
            m_Data = nullptr;
        }
    
        void setRRName(const std::string& name) { rrname = name; }
        void setType(uint16_t t)               { type = t; }
        void setTTL(uint32_t timeToLive)        { ttl = timeToLive; }
    
        // Serialize RR into m_Data in DNS wire format (no RDATA)
        void computeCalculateFields() override {
            // Encode rrname
            std::vector<std::string> labels;
            std::istringstream iss(rrname);
            std::string label;
            while (std::getline(iss, label, '.'))
                labels.push_back(label);
    
            // NAME length: sum(label lengths +1) +1 null
            size_t nameLen = 1;
            for (auto& lbl : labels)
                nameLen += lbl.size() + 1;
            // Fixed 10 bytes: Type(2) + Class(2) + TTL(4) + RDLENGTH(2)
            m_DataLen = nameLen + 10;
    
            delete[] m_Data;
            m_Data = new uint8_t[m_DataLen];
    
            size_t offset = 0;
            // Fill NAME
            for (auto& lbl : labels) {
                m_Data[offset++] = static_cast<uint8_t>(lbl.size());
                std::memcpy(m_Data + offset, lbl.data(), lbl.size());
                offset += lbl.size();
            }
            m_Data[offset++] = 0; // end of NAME
    
            // Fill TYPE
            uint16_t netType = htons(type);
            std::memcpy(m_Data + offset, &netType, sizeof(netType));
            offset += sizeof(netType);
    
            // Fill CLASS: 1 (IN)
            uint16_t qclass = htons(1);
            std::memcpy(m_Data + offset, &qclass, sizeof(qclass));
            offset += sizeof(qclass);
    
            // Fill TTL
            uint32_t netTTL = htonl(ttl);
            std::memcpy(m_Data + offset, &netTTL, sizeof(netTTL));
            offset += sizeof(netTTL);
    
            // Fill RDLENGTH = 0
            uint16_t rdlen = htons(0);
            std::memcpy(m_Data + offset, &rdlen, sizeof(rdlen));
        }
    
        size_t getHeaderLen() const override { return m_DataLen; }
        void parseNextLayer() override { m_NextLayer = nullptr; }
        std::string toString() const override { return "Custom DNS Resource Record"; }
    
        pcpp::OsiModelLayer getOsiModelLayer() const override { return pcpp::OsiModelApplicationLayer; }

        std::string getName() const {
            return "DNS Resource Record";
        }
};

class CustomDNS : public pcpp::Layer {
    public:
        // DNS flags
        bool qr = false;
        uint8_t opcode = 0;
        bool aa = false;
        bool tc = false;
        bool rd = true;
        bool ra = false;
        bool z = false;
        bool ad = false;
        bool cd = false;
        uint8_t rcode = 0;
    
        // Section counts
        uint16_t qdCount = 0;
        uint16_t anCount = 0;
        uint16_t nsCount = 0;
        uint16_t arCount = 0;
    
        CustomDNS() {
            m_Protocol = pcpp::UnknownProtocol;
            m_DataLen = 0;
            m_Data = nullptr;
        }
    
        // Serialize DNS header into m_Data
        void computeCalculateFields() override {
            m_DataLen = 12;
            m_Data = new uint8_t[m_DataLen];
            size_t offset = 0;
    
            // ID (set to 0)
            uint16_t id = 0;
            uint16_t netId = htons(id);
            std::memcpy(m_Data + offset, &netId, sizeof(netId));
            offset += sizeof(netId);
    
            // Flags
            uint16_t flags = 0;
            flags |= (qr  ? 1u << 15 : 0);
            flags |= (opcode & 0xF) << 11;
            flags |= (aa  ? 1u << 10 : 0);
            flags |= (tc  ? 1u << 9  : 0);
            flags |= (rd  ? 1u << 8  : 0);
            flags |= (ra  ? 1u << 7  : 0);
            flags |= (z   ? 1u << 6  : 0);
            flags |= (ad  ? 1u << 5  : 0);
            flags |= (cd  ? 1u << 4  : 0);
            flags |= (rcode & 0xF);
            uint16_t netFlags = htons(flags);
            std::memcpy(m_Data + offset, &netFlags, sizeof(netFlags));
            offset += sizeof(netFlags);
    
            // Counts
            auto writeCount = [&](uint16_t val) {
                uint16_t netVal = htons(val);
                std::memcpy(m_Data + offset, &netVal, sizeof(netVal));
                offset += sizeof(netVal);
            };
            writeCount(qdCount);
            writeCount(anCount);
            writeCount(nsCount);
            writeCount(arCount);
        }
    
        size_t getHeaderLen() const override { return m_DataLen; }
        void parseNextLayer() override { m_NextLayer = nullptr; }
        std::string toString() const override { return "Custom DNS Header"; }
    
        pcpp::OsiModelLayer getOsiModelLayer() const override { return pcpp::OsiModelApplicationLayer; }

        std::string getName() const {
            return "DNS";
        }
};
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
class CustomIPLayer : public pcpp::Layer {
    public:
        /**
         * Construct a new CustomIPLayer.
         * @param version  IP version (4 bits)
         * @param flags    Flags field (3 bits used)
         * @param tos      Type of Service
         * @param ttl      Time To Live
         * @param proto    Protocol
         */
        CustomIPLayer(uint8_t version, uint8_t flags, uint8_t tos, uint8_t ttl, uint8_t proto)
            : Layer((uint8_t*)&_header, sizeof(CustomIPHeader), nullptr, 0)
        {
            _header.version_and_flags = static_cast<uint8_t>((version << 4) | (flags & 0x0F));
            _header.tos                 = tos;
            _header.ttl                 = ttl;
            _header.proto               = proto;
            memset(_header.reserved, 0, sizeof(_header.reserved));
            computeCalculateFields();
        }

        CustomIPHeader* getCustomHeader() { return &_header; }

        /**
         * After our header, everything is payload.
         */
        void parseNextLayer() override {
            size_t headerLen = sizeof(CustomIPHeader);
            if (m_DataLen > headerLen) {
                m_NextLayer = new pcpp::PayloadLayer(m_Data + headerLen,
                                                m_DataLen - headerLen,
                                                this,
                                                m_Packet);
            }
        }

        pcpp::OsiModelLayer getOsiModelLayer() const override {
            return pcpp::OsiModelNetworkLayer;
        }

        /**
         * No dynamic fields to calculate, but override to satisfy abstract base.
         */
        void computeCalculateFields() override {
            // Nothing to compute for fixed-size header
        }

        /**
         * Provide a text representation.
         */
        std::string toString() const override {
            return "CustomIPLayer(headerLen=" + std::to_string(sizeof(CustomIPHeader)) + ")";
        }

        size_t getHeaderLen() const override {
            return sizeof(CustomIPHeader);
        }

        std::string getName() const {
            return "IPv4";
        }

    private:
        CustomIPHeader _header;
};

#pragma pack(push,1)
struct CustomIPv6Header {
    uint8_t version;  // should be 6
    uint8_t tc;       // traffic class
    uint8_t nh;       // next header
    uint8_t hlim;     // hop limit
};
#pragma pack(pop)

/**
 * CustomIPv6Layer implements a 4-byte minimal IPv6-like header.
 */
class CustomIPv6Layer : public pcpp::Layer {
    public:
        CustomIPv6Layer(uint8_t version, uint8_t tc, uint8_t nh, uint8_t hlim)
            : pcpp::Layer((uint8_t*)&_header, sizeof(CustomIPv6Header), nullptr, 0)
        {
            _header.version = version;
            _header.tc      = tc;
            _header.nh      = nh;
            _header.hlim    = hlim;
            computeCalculateFields();
        }

        CustomIPv6Header* getCustomHeader() { return &_header; }
        void parseNextLayer() override {
            size_t hdrLen = sizeof(CustomIPv6Header);
            if (m_DataLen > hdrLen)
                m_NextLayer = new pcpp::PayloadLayer(m_Data + hdrLen, m_DataLen - hdrLen, this, m_Packet);
        }
        void computeCalculateFields() override {}
        std::string toString() const override { return "CustomIPv6Layer(len=" + std::to_string(sizeof(CustomIPv6Header)) + ")"; }
        pcpp::OsiModelLayer getOsiModelLayer() const override { return pcpp::OsiModelNetworkLayer; }
        size_t getHeaderLen() const override { return sizeof(CustomIPv6Header); }
        std::string getName() const {
            return "IPv6";
        }

    private:
        CustomIPv6Header _header;
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
            delete[] m_Data;
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
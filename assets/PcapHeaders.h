#pragma once

#include <cstdint>

// PCAP Global Header Structure (24 bytes)
struct PcapGlobalHeader {
    uint32_t magic_number;   // File format identifier
    uint16_t version_major;  // Major version number
    uint16_t version_minor;  // Minor version number
    int32_t  thiszone;       // Time zone offset
    uint32_t sigfigs;        // Timestamp accuracy
    uint32_t snaplen;        // Max packet size
    uint32_t network;        // Data link type
};

// PCAP Packet Header Structure (16 bytes)
struct PcapPacketHeader {
    uint32_t ts_sec;    // Timestamp seconds
    uint32_t ts_usec;   // Timestamp microseconds
    uint32_t caplen;    // Captured packet length
    uint32_t len;       // Original packet length
};
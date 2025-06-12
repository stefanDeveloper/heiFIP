#pragma once

#include <cstdint>

/**
 * @struct PcapGlobalHeader
 * @brief Represents the 24-byte global header at the start of a PCAP file.
 *
 * Fields (in file byte order, typically little-endian):
 *   magic_number  : 4 bytes
 *     • Identifies the file as a PCAP. Common value 0xa1b2c3d4 (nanosecond‐resolution variants differ).
 *   version_major : 2 bytes
 *     • Major version of the libpcap file format (e.g., 2).
 *   version_minor : 2 bytes
 *     • Minor version of the libpcap file format (e.g., 4).
 *   thiszone      : 4 bytes (signed)
 *     • Offset from UTC in seconds (usually 0). Historically used for timestamp adjustment.
 *   sigfigs       : 4 bytes
 *     • Timestamp accuracy; typically set to 0 (no accuracy information).
 *   snaplen       : 4 bytes
 *     • “Snapshot length” or maximum number of bytes captured per packet. Packets larger than this are truncated.
 *   network       : 4 bytes
 *     • Data link type (DLT) identifier, e.g., 1 for Ethernet. Determines how to interpret raw packet headers.
 */
struct PcapGlobalHeader {
    uint32_t magic_number;   // File format identifier: 0xa1b2c3d4 (or swapped/endian variants)
    uint16_t version_major;  // Major version number (e.g., 2)
    uint16_t version_minor;  // Minor version number (e.g., 4)
    int32_t  thiszone;       // GMT to local time correction (in seconds; usually 0)
    uint32_t sigfigs;        // Accuracy of timestamps (in microseconds; typically 0)
    uint32_t snaplen;        // Max length of captured packets, in bytes
    uint32_t network;        // Data link type (e.g., 1 = Ethernet)
};

/**
 * @struct PcapPacketHeader
 * @brief Represents the 16-byte per-packet header for each packet in a PCAP file.
 *
 * Fields (in file byte order, typically little-endian):
 *   ts_sec  : 4 bytes
 *     • Timestamp, seconds portion, when the packet was captured.
 *   ts_usec : 4 bytes
 *     • Timestamp, microseconds portion (0–999999) for finer granularity.
 *   caplen  : 4 bytes
 *     • Number of bytes of packet data actually saved in the file (may be ≤ original length).
 *   len     : 4 bytes
 *     • Original length of the packet on the wire (before any truncation).
 */
struct PcapPacketHeader {
    uint32_t ts_sec;    // Timestamp: seconds since Epoch (Unix time)
    uint32_t ts_usec;   // Timestamp: microseconds past ts_sec
    uint32_t caplen;    // Captured length (number of bytes written to file)
    uint32_t len;       // Original packet length (on-the-wire size)
};
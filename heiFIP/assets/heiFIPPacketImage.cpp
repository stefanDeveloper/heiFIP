#pragma once

#include <iostream>
#include <cmath>
#include "PcapHeaders.h"   // Provides PcapPacketHeader for captured length
#include <vector>
#include <iomanip>
#include <bitset>
#include <memory>
#include <sstream>

/**
 * @class heiFIPPacketImage
 * @brief Base class for converting raw packet byte data into a 2D matrix representation.
 *
 * Responsibilities:
 *   - Store raw packet bytes (std::vector<uint8_t>) and captured length (_cap_length).
 *   - Offer multiple constructors for different initialization styles:
 *       • Direct data + cap_length.
 *       • Data only (read cap_length from PcapPacketHeader).
 *       • Data + image-dimension parameters (dim, fill, auto_dim), which immediately
 *         build a square “tiled” matrix and store both the matrix and a “binaries” copy.
 *   - Provide utilities:
 *       • printHexData(): Print packet bytes in hex for debugging.
 *       • getHexData(): Retrieve raw bytes as a vector<uint8_t>.
 *       • bit_array(): Convert each byte to its 8-bit binary representation, then pack into 4-bit nibbles.
 *       • get_matrix_tiled(): Build a dim×dim grayscale matrix from raw bytes, with padding/truncation.
 *   - Provide getters/setters for data, cap_length, and the computed matrix.
 */
class heiFIPPacketImage {
public:
    /**
     * @brief Constructor: initialize with raw byte data and explicit captured length.
     *
     * @param data        Vector of raw packet bytes (0–255).
     * @param cap_length  The “caplen” field from the pcap header indicating how many bytes were captured.
     *
     * Why:
     *   - Some callers know the cap_length in advance; this constructor lets them set both fields directly.
     */
    heiFIPPacketImage(std::vector<uint8_t> data, uint32_t cap_length)
        : _data(std::move(data)), _cap_length(cap_length)
    {}

    /**
     * @brief Constructor: initialize with raw byte data only, reading cap_length from a PcapPacketHeader.
     *
     * @param data  Vector of raw packet bytes.
     *
     * Workflow:
     *   1. Store input bytes in _data.
     *   2. Instantiate a PcapPacketHeader (uninitialized), then read its caplen member.
     *      This assumes that PcapPacketHeader() will auto-populate caplen appropriately (e.g., via global state).
     *   3. Store caplen in _cap_length.
     *
     * Why:
     *   - In contexts where cap_length comes from a shared or externally managed PcapPacketHeader,
     *     callers need only supply the byte array; the header’s caplen is fetched internally.
     */
    heiFIPPacketImage(std::vector<uint8_t> data)
        : _data(std::move(data))
    {
        PcapPacketHeader packetHeader;
        _cap_length = packetHeader.caplen;
    }

    /**
     * @brief Constructor: initialize with raw byte data and immediately build a tiled image matrix.
     *
     * @param data      Vector of raw packet bytes.
     * @param dim       Target dimension of the square output image (width = height = dim).
     *                  If auto_dim is true, the actual dimension is computed as ceil(sqrt(length)).
     * @param fill      Fill value (0–255) used to pad if the flattened data is smaller than dim×dim.
     * @param auto_dim  If true, ignore provided dim and compute dim = ceil(sqrt(length of data)).
     *
     * Workflow:
     *   1. Store input bytes in _data.
     *   2. Instantiate a PcapPacketHeader to fetch cap_length (same as data-only constructor).
     *   3. Call get_matrix_tiled(fill, dim, auto_dim), which returns:
     *        • result.first  = 2D matrix (dim×dim) of uint8_t values (padded/truncated).
     *        • result.second = “binaries” vector-of-vectors, here just a single row of raw data.
     *   4. Store result.first in matrix member and result.second in binaries member.
     *
     * Why:
     *   - Some callers want to immediately get a matrix representation upon construction,
     *     so this constructor does that in one step, storing both the matrix and raw-binary copy.
     */
    heiFIPPacketImage(std::vector<uint8_t> data, int dim, int fill, bool auto_dim)
        : _data(std::move(data))
    {
        PcapPacketHeader packetHeader;
        _cap_length = packetHeader.caplen;

        // Build the tiled matrix and binaries representation in one call.
        auto result = heiFIPPacketImage::get_matrix_tiled(fill, dim, auto_dim);
        heiFIPPacketImage::matrix   = std::move(result.first);
        heiFIPPacketImage::binaries = std::move(result.second);
    }

    ~heiFIPPacketImage() = default;

    /**
     * @brief Print the raw packet bytes in hexadecimal to stdout for debugging.
     *
     * Output format:
     *   “Packet has size (Size: <cap_length> bytes):”
     *   Then each byte printed in “HH ” (two-digit hex, space-separated).
     */
    void printHexData() const {
        std::cout << std::dec
                  << "Packet has size"
                  << " (Size: " << get_cap_length() << " bytes):\n";
        for (size_t i = 0; i < _data.size(); ++i) {
            std::cout << std::hex
                      << std::setw(2) << std::setfill('0')
                      << static_cast<int>(_data[i]) << " ";
        }
        std::cout << std::endl;
    }

    /**
     * @brief Return a copy of the raw packet bytes as a vector<uint8_t>.
     *
     * @return std::vector<uint8_t>  Each element is one byte from _data.
     *
     * Why:
     *   - Some image classes need a direct copy of the packet bytes.
     *   - Ensures callers cannot modify the original _data member.
     */
    std::vector<uint8_t> getHexData() const {
        std::vector<uint8_t> hexData;
        hexData.reserve(_data.size());
        for (size_t i = 0; i < _data.size(); ++i) {
            hexData.push_back(_data[i]);
        }
        return hexData;
    }

    /**
     * @brief Convert raw bytes to a 4-bit–granularity “bit array.”
     *
     * Workflow:
     *   1. Copy each byte from _data into a local vector<uint8_t> called data.
     *   2. For each byte, produce an 8-character string of ‘0’/‘1’ bits (std::bitset<8>).
     *   3. Concatenate all these bit strings into one long string “bytes_as_bits.”
     *   4. Walk through bytes_as_bits in 4-bit chunks; each chunk is interpreted as a binary number
     *      in range 0–15, then appended to transition vector.
     *   5. Return transition, a vector<uint8_t> of size ceil((8 * _data.size()) / 4).
     *
     * Why:
     *   - Some image formats (e.g., certain Markov or n-gram matrices) operate on 4-bit “nibble” values.
     *   - Converting each byte into two 4-bit values allows constructing those images.
     */
    std::vector<uint8_t> bit_array() const {
        // 1) Copy bytes so as not to modify _data
        std::vector<uint8_t> data;
        data.reserve(_data.size());
        for (uint8_t byte : _data) {
            data.push_back(byte);
        }

        // 2) Build a concatenated string of bits, 8 bits per byte
        std::string bytes_as_bits;
        bytes_as_bits.reserve(data.size() * 8);
        for (unsigned char byte : data) {
            bytes_as_bits += std::bitset<8>(byte).to_string();
        }

        // 3) Group into 4-bit chunks and convert to byte values 0–15
        std::vector<uint8_t> transition;
        transition.reserve((bytes_as_bits.size() + 3) / 4);
        for (size_t i = 0; i < bytes_as_bits.length(); i += 4) {
            // If remaining bits < 4 at the end, substring still works (std::stoi will parse up to end)
            transition.push_back(
                static_cast<uint8_t>(
                    std::stoi(bytes_as_bits.substr(i, 4), nullptr, 2)
                )
            );
        }
        return transition;
    }

    /**
     * @brief Build a square “tiled” matrix (dim × dim) from raw bytes, with padding or truncation.
     *
     * @param fill      Value (0–255) to pad matrix cells if flattened data is shorter than dim².
     * @param dim       Desired dimension of the square output matrix (width = height = dim).
     * @param auto_dim  If true, compute dim = ceil( sqrt(max(binaries[i].size())) ) before flattening.
     *
     * Workflow:
     *   1. Create a single-element vector-of-vectors called binaries, containing one row: hexData = getHexData().
     *   2. Determine length = max row length in binaries (here, just hexData.size()).
     *   3. If auto_dim is true, recompute dim = ceil(sqrt(length)).
     *   4. Compute total = dim × dim.
     *   5. Flatten binaries into one 1D vector “flat” (binaries only has one row here, but code is generic).
     *   6. If flat.size() < total, append (total − flat.size()) copies of fill.
     *   7. Else if flat.size() > total, truncate flat to size = total.
     *   8. Allocate result as vector<vector<uint8_t>>(dim, vector<uint8_t>(dim)).
     *   9. Fill result[i][j] sequentially from flat[k], where i = k / dim, j = k % dim.
     *  10. Return a pair: { result, binaries }.
     *
     * Returns:
     *   - first:  dim×dim matrix of uint8_t
     *   - second: original “binaries” row(s) used (here, just hexData).
     *
     * Why:
     *   - Many image types represent packet bytes as a square grayscale image, padding/truncating as needed.
     *   - The “binaries” return value allows higher layers to also inspect the raw vector(s) of bytes.
     */
    std::pair<std::vector<std::vector<uint8_t>>, std::vector<std::vector<uint8_t>>>
    get_matrix_tiled(int fill, int dim, bool auto_dim) {
        // 1) Build “binaries” as a vector of one row (hexData)
        std::vector<std::vector<uint8_t>> binaries;
        std::vector<uint8_t> hexData = getHexData();
        binaries.push_back(hexData);

        // 2) Determine maximum row length in binaries (only one row here)
        size_t length = 0;
        for (const auto& b : binaries) {
            if (b.size() > length) {
                length = b.size();
            }
        }

        // 3) If auto_dim is requested, compute dim = ceil(sqrt(length))
        if (auto_dim) {
            dim = static_cast<int>(std::ceil(std::sqrt(static_cast<double>(length))));
        }

        int total = dim * dim;

        // 4) Flatten binaries into a single 1D array “flat”
        std::vector<uint8_t> flat;
        flat.reserve(total);
        for (const auto& row : binaries) {
            flat.insert(flat.end(), row.begin(), row.end());
        }

        // 5) Pad with “fill” if too short
        if (flat.size() < static_cast<size_t>(total)) {
            flat.insert(flat.end(), total - flat.size(), static_cast<uint8_t>(fill));
        }
        // 6) Truncate if too long
        else if (flat.size() > static_cast<size_t>(total)) {
            flat.resize(total);
        }

        // 7) Reshape into a 2D dim×dim matrix
        std::vector<std::vector<uint8_t>> result(dim, std::vector<uint8_t>(dim));
        for (size_t idx = 0; idx < static_cast<size_t>(total); ++idx) {
            size_t i = idx / dim;
            size_t j = idx % dim;
            result[i][j] = flat[idx];
        }

        return { result, binaries };
    }

    /**
     * @brief Get a copy of the raw packet data vector.
     * @return std::vector<uint8_t>  Copy of _data.
     */
    std::vector<uint8_t> get_data() const {
        return _data;
    }

    /**
     * @brief Replace the raw packet data.
     * @param data  New vector of raw bytes.
     */
    void set_data(std::vector<uint8_t> data) {
        _data = std::move(data);
    }

    /**
     * @brief Get the captured length (caplen) of this packet.
     * @return uint32_t  The stored captured length.
     */
    uint32_t get_cap_length() const {
        return _cap_length;
    }

    /**
     * @brief Set the captured length (caplen).
     * @param cap_length  New captured length value.
     */
    void set_cap_length(uint32_t cap_length) {
        _cap_length = cap_length;
    }

    /**
     * @brief Return a reference to the stored 2D matrix.
     * @return std::vector<std::vector<uint8_t>>&  The dim×dim matrix built by a tiled constructor.
     *
     * Note: If get_matrix_tiled() was never called, matrix may be empty.
     */
    std::vector<std::vector<uint8_t>>& get_matrix() {
        return matrix;
    }

private:
    std::vector<uint8_t> _data;                               ///< Raw bytes of the packet
    uint32_t _cap_length;                                      ///< Captured length from pcap header
    std::vector<std::vector<uint8_t>> binaries;                ///< Original binaries as rows (usually one row of raw bytes)
    std::vector<std::vector<uint8_t>> matrix;                  ///< Tiled dim×dim matrix representation of packet bytes
};
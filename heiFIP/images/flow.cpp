#pragma once

#include <iostream>
#include <vector>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <cstdint>
#include <memory>
#include <string>

#include "NetworkTrafficImage.hpp"
#include "heiFIPPacketImage.cpp"

/**
 * @class FlowImage
 * @brief Converts a sequence of heiFIPPacketImage instances (one per flow) into a 2D matrix.
 *
 * Inherits from NetworkTrafficImage, which provides shared logic for traffic-based images.
 * Responsibilities:
 *   - Accept a vector of packet images representing one flow.
 *   - Either “append” all packet byte vectors into a single long vector and reshape,
 *     or lay out each packet’s bytes on its own row, padding to a uniform length.
 *   - Provide getters for both the tiled matrix and the raw binaries.
 */
class FlowImage : public NetworkTrafficImage {
public:
    /**
     * @brief Constructor: build a FlowImage from a list of packet‐level images.
     *
     * @param packets  Vector of heiFIPPacketImage, each representing one packet’s bytes.
     * @param dim      If append=true, width of each row when concatenating all packets.
     *                 If append=false, this is ignored (rows are padded to the maximum packet length).
     * @param fill     Value (0–255) to pad shorter rows (when not appending) or at end of concatenation.
     * @param append   If true, concatenate all packet byte arrays into one long vector and then
     *                 split into rows of width=dim. If false, place each packet’s bytes on its own row.
     *
     * Workflow:
     *   1. Call NetworkTrafficImage(fill, dim) to initialize base-class fields (e.g., storing fill and dim).
     *   2. Store the input `packets` and `append` flag.
     *   3. Call getMatrix(dim, append, fill, packets) to build:
     *        - matrix: 2D vector<uint8_t> representing the flow image.
     *        - binaries: vector of each packet’s raw byte vector (for reference).
     *   4. Store the returned matrix and binaries in member variables.
     */
    FlowImage(std::vector<heiFIPPacketImage> packets, int dim = 16, int fill = 0, bool append = false)
        : NetworkTrafficImage(fill, dim), packets(packets), append(append) 
    {
        auto result = getMatrix(dim, append, fill, packets);
        matrix   = std::move(result.first);
        binaries = std::move(result.second);
    }

    /**
     * @brief Get the raw binaries for each packet in the flow.
     * @return Reference to the vector of vectors of uint8_t, one per packet.
     */
    std::vector<std::vector<uint8_t>>& get_binaries() {
        return binaries;
    }

    /**
     * @brief Get the 2D matrix representing the flow image.
     * @return Reference to a 2D vector<uint8_t> of size [numRows][numCols].
     *
     * If append=true, numRows = ceil(totalBytes / dim) and numCols = dim.
     * If append=false, numRows = number of packets and numCols = max packet length.
     */
    const std::vector<std::vector<uint8_t>>& get_matrix() const {
        return matrix;
    }

private:
    std::vector<heiFIPPacketImage> packets;            ///< Input packet images for this flow
    bool append;                                        ///< Whether to concatenate all packet bytes before reshaping
    std::vector<std::vector<uint8_t>> matrix;           ///< Resulting 2D image matrix
    std::vector<std::vector<uint8_t>> binaries;         ///< Original raw byte vectors (one per packet)

    /**
     * @brief Build the matrix and store raw binaries depending on the append flag.
     *
     * @param dim      Desired width when appending all bytes into one long vector.
     * @param append   If true, concatenate all packet byte arrays first; otherwise treat each packet separately.
     * @param fill     Byte value used to pad incomplete rows.
     * @param packets  Vector of heiFIPPacketImage instances to process.
     * @return pair:
     *            - first:  2D matrix of uint8_t values (each row corresponds to either a flow segment or a packet).
     *            - second: Raw packet‐byte vectors as originally extracted (“binaries”).
     *
     * Workflow when append=true:
     *   1. For each heiFIPPacketImage in `packets`, call getHexData() to get a vector<uint8_t>.
     *   2. Append each packet’s bytes in sequence into one long vector `fh`.
     *   3. Compute number of rows: rn = ceil(fh.size() / dim). Resize fh to rn*dim by appending zeros.
     *   4. Allocate a 2D vector `reshaped` of size [rn][dim].
     *   5. Copy fh[i*dim ... (i+1)*dim−1] into reshaped[i] for i in [0..rn−1].
     *   6. Return {reshaped, binaries}.
     *
     * Workflow when append=false:
     *   1. For each heiFIPPacketImage in `packets`, call getHexData() to get vector<uint8_t> `binary`.
     *   2. Track the maximum length among all `binary.size()`.
     *   3. For each `binary`, create a new row `row = binary` then resize to length=maxLength, filling with `fill`.
     *   4. Push `row` into `reshaped`.
     *   5. Return {reshaped, binaries}.
     */
    std::pair<std::vector<std::vector<uint8_t>>, std::vector<std::vector<uint8_t>>> 
    getMatrix(int dim, bool append, int fill, const std::vector<heiFIPPacketImage>& packets) {
        std::vector<std::vector<uint8_t>> binaries;

        // 1) Extract raw bytes from each heiFIPPacketImage
        for (const auto& packet : packets) {
            std::vector<uint8_t> hexData = packet.getHexData();
            binaries.push_back(std::move(hexData));
        }

        // If concatenating all packet bytes into one long flow image
        if (append) {
            std::vector<uint8_t> fh;
            // a) Append each packet’s bytes into fh
            for (const auto& binary : binaries) {
                fh.insert(fh.end(), binary.begin(), binary.end());
            }

            // b) Compute number of rows needed and pad with zeros
            int rn = static_cast<int>(fh.size()) / dim + (fh.size() % dim > 0 ? 1 : 0);
            fh.resize(rn * dim, static_cast<uint8_t>(0));  // Pad tail to make length = rn*dim

            // c) Reshape into a 2D matrix of size [rn][dim]
            std::vector<std::vector<uint8_t>> reshaped(rn, std::vector<uint8_t>(dim));
            for (int i = 0; i < rn; ++i) {
                std::copy(
                    fh.begin() + i * dim,
                    fh.begin() + (i + 1) * dim,
                    reshaped[i].begin()
                );
            }

            return { reshaped, binaries };
        }
        // If placing each packet’s bytes on its own row
        else {
            // a) Determine maximum packet length
            size_t maxLength = 0;
            for (const auto& binary : binaries) {
                maxLength = std::max(maxLength, binary.size());
            }

            // b) Build one row per packet, padding each to maxLength with `fill`
            std::vector<std::vector<uint8_t>> reshaped;
            reshaped.reserve(binaries.size());
            for (const auto& binary : binaries) {
                std::vector<uint8_t> row = binary;                     // Copy raw bytes
                row.resize(maxLength, static_cast<uint8_t>(fill));     // Pad to uniform length
                reshaped.push_back(std::move(row));
            }

            return { reshaped, binaries };
        }
    }
};
#pragma once

#include <iostream>
#include <vector>
#include <cmath>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <iterator>
#include <cstring>
#include <cstdint>
#include <memory>
#include <array>

#include "heiFIPPacketImage.cpp"
#include "NetworkTrafficImage.hpp"

/**
 * @class FlowImageTiledAuto
 * @brief Builds a square, tiled image from a sequence of packet images, automatically determining tile dimensions.
 *
 * Inherits from NetworkTrafficImage, which stores a default fill value and base dimension.
 * Responsibilities:
 *   - Convert each packet’s raw bytes into its own dim×dim tile, padding/truncating as needed.
 *   - Arrange all those tiles into a larger square grid (dim_total×dim_total), where dim_total = ceil(sqrt(numTiles)).
 *   - Provide getters for the final tiled matrix and the original per-packet binaries.
 */
class FlowImageTiledAuto : public NetworkTrafficImage {
public:
    /**
     * @brief Constructor: prepare tiled flow image using automatic dimension calculation if requested.
     *
     * @param packets  Vector of heiFIPPacketImage, each containing raw bytes for one packet.
     * @param dim      Base dimension for each packet’s tile (width = height = dim) if auto_dim=false.
     *                 If auto_dim=true, each tile’s dim is recalculated as ceil(sqrt(maxPacketLength)).
     * @param fill     Byte value (0–255) used to pad shorter packet byte arrays when building each tile.
     * @param auto_dim If true, automatically set each tile’s dim = ceil(sqrt(max length among all packets)).
     *
     * Workflow:
     *   1. Call NetworkTrafficImage(fill, dim) to store base fill and dim.
     *   2. Store given `packets` and `auto_dim` flag in members.
     *   3. Call get_matrix_tiled(fill, dim, auto_dim, packets), which:
     *        a. Extracts raw bytes from each packet image.
     *        b. Finds max packet length; if auto_dim, compute dim = ceil(sqrt(maxLength)).
     *        c. For each packet, reshape its bytes into a dim×dim tile (row-major), padding with `fill`.
     *        d. Compute dim_total = ceil(sqrt(numPackets)).
     *        e. Arrange all packet tiles into a dim_total×dim_total grid by:
     *             • Placing tiles row by row, concatenating horizontally via npconcatenate().
     *             • Padding with zero tiles (via npzero()) if fewer than dim_total² packets.
     *        f. Return {tiledMatrix, binaries}, where binaries is the vector of each packet’s raw byte vector.
     *   4. Store the returned tiled matrix and binaries in member variables.
     */
    FlowImageTiledAuto(const std::vector<heiFIPPacketImage>& packets, int dim = 16, int fill = 0, bool auto_dim = false)
        : NetworkTrafficImage(fill, dim), packets(packets), auto_dim(auto_dim) 
    {
        auto result = get_matrix_tiled(fill, dim, auto_dim, packets);
        matrix   = std::move(result.first);
        binaries = std::move(result.second);
    }

    /**
     * @brief Get the final tiled image matrix (square of tiles stacked).
     * @return Reference to a 2D vector<uint8_t> of size [dim_total*dim][dim_total*dim].
     */
    const std::vector<std::vector<uint8_t>>& get_matrix() const {
        return matrix;
    }

    /**
     * @brief Get the raw byte vectors for each packet (binaries used to build tiles).
     * @return Reference to a vector of vectors, one per packet.
     */
    std::vector<std::vector<uint8_t>>& get_binaries() {
        return binaries;
    }

private:
    std::vector<heiFIPPacketImage> packets;            ///< Input packet images
    bool auto_dim;                                      ///< Whether to recalc tile dim = ceil(sqrt(maxPacketLength))
    std::vector<std::vector<uint8_t>> matrix;           ///< Final tiled flow image
    std::vector<std::vector<uint8_t>> binaries;         ///< Raw byte vectors for each packet

    /**
     * @brief Build per-packet tiles and assemble them into one large square matrix.
     *
     * @param fill      Byte value to use when padding individual packet tiles.
     * @param dim       Base dimension for each packet tile (unless overridden by auto_dim).
     * @param auto_dim  If true, recompute dim = ceil(sqrt(max packet length)).
     * @param packets   Vector of heiFIPPacketImage, each containing raw bytes for one packet.
     * @return pair:
     *            - first:  2D tiled image (size = dim_total*dim × dim_total*dim).
     *            - second: Original raw byte vectors (for reference).
     *
     * Workflow:
     *   1. Extract raw bytes from each packet (packet.getHexData()) into `binaries`.
     *   2. Determine max packet length across all binaries.
     *   3. If auto_dim=true, set dim = ceil(sqrt(maxLength)).
     *   4. For each packet’s byte vector `x`:
     *        a. Allocate a dim×dim tile, initialized to `fill`.
     *        b. Copy x[k] into tile[i][j] for k from 0 to x.size()-1, filling row-major:
     *             • i = k / dim, j = k % dim; stop when k ≥ x.size() or out of bounds.
     *        c. Store that tile in a temporary list `result` (vector of 2D arrays).
     *   5. Compute dim_total = ceil(sqrt(numPackets)) → number of tiles per row/column.
     *   6. Call tile_images(result, dim_total, dim) to arrange tiles into one big matrix:
     *        a. Build rows of concatenated tiles horizontally: each row has dim_total tiles side by side.
     *           Use npzero(dim) to fill missing tiles if numPackets < dim_total².
     *           Use npconcatenate() to join tiles horizontally (rows must have same height=dim).
     *        b. After building each row (dim rows high, width = dim_total*dim), stack all rows vertically.
     *   7. Return {tiledMatrix, binaries}.
     */
    std::pair<std::vector<std::vector<uint8_t>>, std::vector<std::vector<uint8_t>>> 
    get_matrix_tiled(int fill, int dim, bool auto_dim, const std::vector<heiFIPPacketImage>& packets) {
        // 1) Extract raw bytes from each packet and push into binaries
        std::vector<std::vector<uint8_t>> binaries;
        for (const heiFIPPacketImage& packet : packets) {
            binaries.push_back(packet.getHexData());
        }

        // 2) Determine the maximum length among all packet byte vectors
        size_t length = 0;
        for (const auto& b : binaries) {
            length = std::max(length, b.size());
        }

        // 3) If auto_dim=true, set each tile’s dim = ceil(sqrt(length))
        if (auto_dim) {
            dim = static_cast<int>(std::ceil(std::sqrt(static_cast<double>(length))));
        }

        // 4) Build a 3D list of per-packet dim×dim tiles
        std::vector<std::vector<std::vector<uint8_t>>> result;
        for (const auto& x : binaries) {
            // a) Initialize a dim×dim tile with `fill`
            std::vector<std::vector<uint8_t>> reshaped(dim, std::vector<uint8_t>(dim, static_cast<uint8_t>(fill)));

            // b) Copy x[k] into reshaped row-major until x is exhausted or tile is filled
            size_t k = 0;
            for (int i = 0; i < dim && k < x.size(); ++i) {
                for (int j = 0; j < dim && k < x.size(); ++j) {
                    reshaped[i][j] = x[k++];
                }
            }
            result.push_back(std::move(reshaped));
        }

        // 5) Compute dim_total = ceil(sqrt(number of tiles)) → grid is dim_total×dim_total tiles
        size_t length_total = result.size();
        uint dim_total = static_cast<uint>(std::ceil(std::sqrt(static_cast<double>(length_total))));

        // 6) Arrange all tiles into a large tiled image
        std::vector<std::vector<uint8_t>> fh = tile_images(result, dim_total, dim);
        return { fh, binaries };
    }

    /**
     * @brief Create a dim×dim tile filled with zeros.
     *
     * @param dim  Dimension for both width and height.
     * @return 2D vector<uint8_t> of size [dim][dim], all elements = 0.
     *
     * Why:
     *   - Used to fill grid slots when numPackets < dim_total², ensuring the final image remains square.
     */
    std::vector<std::vector<uint8_t>> npzero(size_t dim) {
        return std::vector<std::vector<uint8_t>>(dim, std::vector<uint8_t>(dim, static_cast<uint8_t>(0)));
    }

    /**
     * @brief Horizontally concatenate two same-height images (2D arrays).
     *
     * @param img1  First image: vector of rows, each row is a vector<uint8_t>.
     * @param img2  Second image: must have same number of rows as img1.
     * @return Concatenated image: each row is img1[row] followed by img2[row].
     *
     * Throws:
     *   - std::invalid_argument if img1 and img2 have different heights.
     *
     * Why:
     *   - Used in tile_images() to join tiles side by side when building each row of the grid.
     */
    std::vector<std::vector<uint8_t>> npconcatenate(const std::vector<std::vector<uint8_t>>& img1,
                                                    const std::vector<std::vector<uint8_t>>& img2) 
    {
        if (img1.empty()) return img2;
        if (img2.empty()) return img1;

        if (img1.size() != img2.size()) {
            throw std::invalid_argument("Images must have the same number of rows to concatenate horizontally.");
        }

        std::vector<std::vector<uint8_t>> result = img1;
        for (size_t i = 0; i < result.size(); ++i) {
            result[i].insert(result[i].end(), img2[i].begin(), img2[i].end());
        }
        return result;
    }

    /**
     * @brief Arrange a list of per-packet tiles into a single large square image.
     *
     * @param images  3D vector: [numTiles][dim][dim], each is a dim×dim tile.
     * @param cols    Number of tiles per row/column in the final grid (dim_total).
     * @param dim     Dimension of each tile (width = height = dim).
     * @return 2D vector<uint8_t> of size [dim_total*dim][dim_total*dim], the tiled image.
     *
     * Workflow:
     *   1. For each row i in [0..cols−1]:
     *        a. Initialize an empty 2D array `row` (to accumulate tile rows).
     *        b. For each column j in [0..cols−1]:
     *             - If k < images.size(), let im = images[k], else let im = npzero(dim).
     *             - If `row` is empty, set row = im; else row = npconcatenate(row, im).
     *             - Increment k.
     *        c. Append `row` to `rows` (vector of row-blocks).
     *   2. Initialize `tiled` = rows[0].
     *   3. For i in [1..rows.size()−1], append rows[i] to the bottom of `tiled` using vector::insert.
     *   4. Return `tiled`, which now has height = cols*dim and width = cols*dim.
     *
     * Why:
     *   - Ensures that if there are fewer tiles than cols², the missing slots are zero-filled, maintaining a square.
     *   - Maintains row-major order: first fill the top-left tile, then the next tile to its right, etc.
     */
    std::vector<std::vector<uint8_t>> tile_images(const std::vector<std::vector<std::vector<uint8_t>>>& images,
                                                  const uint cols, const uint dim) 
    {
        std::vector<std::vector<std::vector<uint8_t>>> rows;
        size_t k = 0;  // Tracks which tile we’re on

        // 1) Build each tile row (concatenate tiles horizontally)
        for (size_t i = 0; i < cols; ++i) {
            std::vector<std::vector<uint8_t>> row;  // Start with an empty row-block
            for (size_t j = 0; j < cols; ++j) {
                std::vector<std::vector<uint8_t>> im;
                if (k < images.size()) {
                    im = images[k];  // Use actual tile
                } else {
                    im = npzero(dim);  // Use zero tile if no more packets
                }

                if (row.empty()) {
                    row = std::move(im);
                } else {
                    row = npconcatenate(row, im);
                }
                ++k;
            }
            rows.push_back(std::move(row));
        }

        // 2) Stack all rows vertically to form the final tiled image
        std::vector<std::vector<uint8_t>> tiled = std::move(rows[0]);
        for (size_t i = 1; i < rows.size(); ++i) {
            tiled.insert(tiled.end(), rows[i].begin(), rows[i].end());
        }
        return tiled;
    }
};
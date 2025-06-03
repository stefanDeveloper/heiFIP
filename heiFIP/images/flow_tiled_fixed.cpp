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
 * @class FlowImageTiledFixed
 * @brief Builds a fixed-grid tiled image from a sequence of packet images.
 *
 * Inherits from NetworkTrafficImage, which provides base logic for traffic-based images.
 * Responsibilities:
 *   - Convert each packet’s raw bytes into its own dim×dim tile, padding/truncating as needed.
 *   - Arrange all those tiles into a fixed-size grid with `cols` tiles per row and per column.
 *   - Provide getters for both the tiled matrix and the original per-packet binaries.
 */
class FlowImageTiledFixed : public NetworkTrafficImage {
public:
    /**
     * @brief Constructor: prepare tiled flow image using a fixed number of columns.
     *
     * @param packets  Vector of heiFIPPacketImage, each containing raw bytes for one packet.
     * @param dim      Dimension for each packet’s tile (width = height = dim).
     * @param fill     Byte value (0–255) used to pad shorter packet byte arrays when building each tile.
     * @param cols     Number of tiles per row (and column) in the final grid. Grid is cols×cols tiles.
     *
     * Workflow:
     *   1. Call NetworkTrafficImage(fill, dim) to store base fill and dim.
     *   2. Store input `packets` and `cols` in member variables.
     *   3. Call get_matrix_tiled(fill, dim, packets), which:
     *        a. Extracts raw bytes from each packet image into `binaries`.
     *        b. For each packet’s byte vector `x`:
     *             i. Allocate a dim×dim tile, initialized to `fill`.
     *             ii. Copy x[k] into tile[i][j] in row-major until x is exhausted or tile is filled.
     *             iii. Append that tile to a local list `result` (vector of 2D arrays).
     *        c. Call tile_images(result, cols, dim) to arrange exactly cols×cols tiles:
     *             i. Place tiles row by row, concatenating horizontally with npconcatenate().
     *             ii. If there are fewer than cols² tiles, use npzero(dim) to fill missing slots.
     *             iii. Stack all rows vertically to form the final matrix.
     *   4. Store the returned matrix and binaries in member variables.
     */
    FlowImageTiledFixed(const std::vector<heiFIPPacketImage>& packets, int dim = 16, int fill = 0, int cols = 3)
        : NetworkTrafficImage(fill, dim), packets(packets), cols(cols) 
    {
        auto result = get_matrix_tiled(fill, dim, packets);
        matrix   = std::move(result.first);
        binaries = std::move(result.second);
    }

    /**
     * @brief Get the final tiled image matrix (fixed size: cols*dim by cols*dim).
     * @return Reference to a 2D vector<uint8_t> representing the tiled image.
     */
    std::vector<std::vector<uint8_t>>& get_matrix() {
        return matrix;
    }

    /**
     * @brief Get the raw byte vectors for each packet (binaries used to build tiles).
     * @return Reference to a vector of vectors, one per packet’s bytes.
     */
    std::vector<std::vector<uint8_t>>& get_binaries() {
        return binaries;
    }

private:
    std::vector<heiFIPPacketImage> packets;            ///< Input packet images
    int cols;                                           ///< Number of tiles per row/column
    std::vector<std::vector<uint8_t>> matrix;           ///< Final tiled flow image
    std::vector<std::vector<uint8_t>> binaries;         ///< Raw byte vectors for each packet

    /**
     * @brief Build per-packet tiles and assemble them into a fixed-size grid.
     *
     * @param fill     Byte value to use when padding individual packet tiles.
     * @param dim      Dimension for each packet tile (width = height = dim).
     * @param packets  Vector of heiFIPPacketImage, each containing raw bytes for one packet.
     * @return pair:
     *            - first:  2D tiled image (size = cols*dim × cols*dim).
     *            - second: Original raw byte vectors (for reference).
     *
     * Workflow:
     *   1. Extract raw bytes from each packet (packet.getHexData()) into `binaries`.
     *   2. For each packet’s byte vector `x`:
     *        a. Allocate a dim×dim tile, initialized to `fill`.
     *        b. Copy x[k] into tile[i][j] in row-major until x is exhausted or tile is filled.
     *        c. Append that tile to a local list `result` (vector of 2D tiles).
     *   3. Call tile_images(result, cols, dim) to arrange exactly cols×cols tiles:
     *        a. Iterate over `cols` rows; for each row, iterate `cols` columns:
     *             • If a tile is available (k < result.size()), use it; else use npzero(dim).
     *             • Concatenate horizontally onto `row` via npconcatenate().
     *        b. Append each completed `row` to `rows`.
     *        c. Stack all `rows` vertically into one matrix: first row, then subsequent rows appended.
     *   4. Return {tiledMatrix, binaries}.
     */
    std::pair<std::vector<std::vector<uint8_t>>, std::vector<std::vector<uint8_t>>> 
    get_matrix_tiled(int fill, int dim, const std::vector<heiFIPPacketImage>& packets) {
        std::vector<std::vector<uint8_t>> binaries;

        // 1) Extract raw bytes from each heiFIPPacketImage
        for (const heiFIPPacketImage& packet : packets) {
            binaries.push_back(packet.getHexData());
        }

        // 2) Build a dim×dim tile for each packet’s bytes
        std::vector<std::vector<std::vector<uint8_t>>> result;
        for (const auto& x : binaries) {
            // a) Initialize a dim×dim tile filled with `fill`
            std::vector<std::vector<uint8_t>> reshaped(dim, std::vector<uint8_t>(dim, static_cast<uint8_t>(fill)));
            // b) Copy bytes into reshaped row-major
            size_t k = 0;
            for (size_t i = 0; i < static_cast<size_t>(dim) && k < x.size(); ++i) {
                for (size_t j = 0; j < static_cast<size_t>(dim) && k < x.size(); ++j) {
                    reshaped[i][j] = x[k++];
                }
            }
            result.push_back(std::move(reshaped));
        }

        // 3) Arrange the tiles into a fixed cols×cols grid
        std::vector<std::vector<uint8_t>> fh = tile_images(result, static_cast<uint>(cols), static_cast<uint>(dim));
        return { fh, binaries };
    }

    /**
     * @brief Create a dim×dim tile filled entirely with zeros.
     *
     * @param dim  Dimension for both width and height.
     * @return 2D vector<uint8_t> of size [dim][dim], all elements = 0.
     *
     * Why:
     *   - Used in tile_images() to fill missing slots when fewer than cols² packets are available.
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
     * @brief Arrange a list of per-packet tiles into one large fixed-grid image.
     *
     * @param images  3D vector: [numTiles][dim][dim], each is a dim×dim tile.
     * @param cols    Number of tiles per row/column in the final grid (fixed).
     * @param dim     Dimension of each tile (width = height = dim).
     * @return 2D vector<uint8_t> of size [cols*dim][cols*dim], the tiled image.
     *
     * Workflow:
     *   1. For each row i in [0..cols−1]:
     *        a. Initialize an empty 2D array `row`.
     *        b. For each column j in [0..cols−1]:
     *             - If k < images.size(), let im = images[k]; else im = npzero(dim).
     *             - If `row` is empty, set row = im; else row = npconcatenate(row, im).
     *             - Increment k.
     *        c. Append this completed `row` (size = dim rows, width = cols*dim) into `rows`.
     *   2. Initialize `tiled` = rows[0].
     *   3. For i in [1..rows.size()−1], append rows[i] to the bottom of `tiled`.
     *   4. Return `tiled`, which now has height = cols*dim and width = cols*dim.
     *
     * Why:
     *   - Having a fixed number of columns ensures a consistent final image size even if the number
     *     of packets < cols² (missing slots become zero-filled tiles).
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
                    im = npzero(dim);  // Zero tile if fewer than cols² packets
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
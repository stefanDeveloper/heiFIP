#pragma once

#include <memory>
#include <string>
#include <vector>
#include <sstream>
#include "heiFIPPacketImage.cpp"
#include "NetworkTrafficImage.hpp"

/**
 * @class MarkovTransitionMatrix
 * @brief Base class for computing a normalized, grayscale Markov transition matrix from a sequence of symbols.
 *
 * Responsibilities:
 *   - Given a 1D vector of “transitions” (values in [0..15]), count the transitions between consecutive symbols.
 *   - Normalize each row of the count matrix so that probabilities sum to 1, then scale to [0..255].
 *   - Return the resulting 16×16 matrix of uint8_t intensities.
 */
class MarkovTransitionMatrix : public NetworkTrafficImage {
public:
    /**
     * @brief Compute a 16×16 Markov transition matrix from a sequence of 4-bit symbols.
     *
     * @param transitions  Vector<uint8_t> of length L containing values 0..15. Each adjacent pair
     *                     (transitions[k], transitions[k+1]) contributes to the count at [i][j].
     * @return 2D vector<uint8_t> of size [16][16], where each cell holds a normalized probability
     *         scaled to [0..255]. Rows with zero total count remain all zeros.
     *
     * Workflow:
     *   1. Allocate a 16×16 uintMatrix initialized to zero (counts of each transition).
     *   2. For k in [0..L-2], let i = transitions[k], j = transitions[k+1]; increment uintMatrix[i][j].
     *   3. For each row i in uintMatrix:
     *        a. Compute sum = Σ_j uintMatrix[i][j].
     *        b. If sum > 0, for each j: compute probability = uintMatrix[i][j] / sum.
     *           Then multiply by 255, clamp to [0..255], and store back as uint8_t.
     *   4. Return the resulting 16×16 grayscale matrix.
     *
     * Why:
     *   - Captures the first-order Markov distribution between successive 4-bit values in a packet’s bit array.
     *   - Scaling to 0–255 yields a grayscale image representation suitable for CNNs or other image-based analysis.
     */
    std::vector<std::vector<uint8_t>> transition_matrix(const std::vector<uint8_t>& transitions) {
        const size_t n = 16;  
        // 1) Initialize a 16×16 count matrix to zero
        std::vector<std::vector<uint8_t>> uintMatrix(n, std::vector<uint8_t>(n, 0));

        // 2) Count transitions between consecutive symbols
        for (size_t k = 0; k + 1 < transitions.size(); ++k) {
            size_t i = transitions[k];
            size_t j = transitions[k + 1];
            uintMatrix[i][j] += 1;
        }

        // 3) Normalize each row to probabilities and scale to [0..255]
        for (auto& row : uintMatrix) {
            double sum = 0.0;
            // Compute total count for this row
            for (double value : row) {
                sum += value;
            }
            if (sum > 0.0) {
                // Convert each count to a probability, multiply by 255, clamp, and cast to uint8_t
                for (auto& value : row) {
                    double prob = static_cast<double>(value) / sum;
                    double scaled = prob * 255.0;
                    // clamp to [0..255]
                    value = static_cast<uint8_t>(std::clamp(scaled, 0.0, 255.0));
                }
            }
            // If sum == 0, leave row as all zeros
        }

        return uintMatrix;
    }
};

/**
 * @class MarkovTransitionMatrixFlow
 * @brief Builds a larger image by computing a Markov transition matrix for each packet in a flow,
 *        then arranging all 16×16 matrices into a fixed grid of tiles.
 *
 * Inherits from MarkovTransitionMatrix to leverage the transition_matrix() method.
 * Responsibilities:
 *   - For each heiFIPPacketImage in `packets`, extract its 4-bit bit array and compute a 16×16 matrix.
 *   - Tile all per-packet matrices into a grid with `cols` tiles per row and column.
 *   - Store the final tiled matrix as a single 2D vector<uint8_t>, accessible via get_matrix().
 */
class MarkovTransitionMatrixFlow : public MarkovTransitionMatrix {
public:
    /**
     * @brief Constructor: compute and tile per-packet Markov matrices.
     *
     * @param packets  Vector of heiFIPPacketImage, each representing one packet in the flow.
     * @param cols     Number of tiles per row and per column in the final grid (grid is cols×cols).
     *
     * Workflow:
     *   1. Store `packets` and `cols`.
     *   2. For each packet in `packets`:
     *        a. Call packet.bit_array() to get a vector<uint8_t> of 4-bit values.
     *        b. Pass that vector to transition_matrix() to get a 16×16 grayscale matrix.
     *        c. Append that 16×16 matrix to a local list `result`.
     *   3. Call tile_images(result, cols, 16) to arrange all 16×16 matrices into one large image:
     *        - Creates a cols×cols grid of 16×16 tiles.
     *        - If fewer than cols² matrices, fill missing spots with zero tiles (npzero).
     *        - Concatenate horizontally then vertically as necessary.
     *   4. Store the final tiled image in member `matrix`.
     */
    MarkovTransitionMatrixFlow(const std::vector<heiFIPPacketImage>& packets, uint cols = 4)
        : packets(packets), cols(cols)
    {
        std::vector<std::vector<std::vector<uint8_t>>> result;
        // 2) Compute a 16×16 Markov matrix for each packet
        for (const heiFIPPacketImage& packet : packets) {
            std::vector<uint8_t> transition = packet.bit_array();
            std::vector<std::vector<uint8_t>> m = transition_matrix(transition);
            result.push_back(std::move(m));
        }
        // 3) Tile all 16×16 matrices into a cols×cols grid
        matrix = tile_images(result, cols, 16);
    }

    /// Accessor for the final tiled flow image
    const std::vector<std::vector<uint8_t>>& get_matrix() const {
        return matrix;
    }

private:
    std::vector<heiFIPPacketImage> packets;            ///< Each packet in the flow
    uint cols;                                          ///< Number of tiles per row/column
    MarkovTransitionMatrix transitionMatrix;            ///< Base class instance (not strictly necessary)
    std::vector<std::vector<uint8_t>> matrix;           ///< Final tiled image composed of 16×16 tiles

    /**
     * @brief Create a 16×16 tile filled with zeros (if a packet’s matrix is missing).
     *
     * @param dim  Tile dimension (16 for Markov matrices).
     * @return 2D vector<uint8_t> of size [dim][dim], all zeros.
     */
    std::vector<std::vector<uint8_t>> npzero(size_t dim) {
        return std::vector<std::vector<uint8_t>>(dim, std::vector<uint8_t>(dim, 0));
    }

    /**
     * @brief Horizontally concatenate two same-height images (2D arrays).
     * 
     * @param img1  First image: vector of rows, each row is a vector<uint8_t>.
     * @param img2  Second image: must have the same number of rows as img1.
     * @return Concatenated image: each row is img1[row] followed by img2[row].
     * 
     * Throws:
     *   - std::invalid_argument if img1 and img2 have different heights.
     * 
     * Why:
     *   - Used in tile_images() to join 16×16 tiles side by side when constructing each grid row.
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
     * @brief Arrange a list of 16×16 tiles into one large square image of size [cols*dim][cols*dim].
     *
     * @param images  3D vector: [numTiles][16][16], each a 16×16 grayscale matrix.
     * @param cols    Number of tiles per row/column in the final grid.
     * @param dim     Dimension of each tile (16).
     * @return 2D vector<uint8_t> of size [cols*dim][cols*dim], the tiled image.
     *
     * Workflow:
     *   1. Initialize an empty vector `rows` to hold each combined grid-row.
     *   2. Set k = 0 to track current tile index.
     *   3. For each row i in [0..cols−1]:
     *        a. Initialize an empty 16×0 “row” block.
     *        b. For j in [0..cols−1]:
     *             - If k < images.size(), let im = images[k]; else use a zero tile npzero(dim).
     *             - If row is empty, set row = im; else row = npconcatenate(row, im).
     *             - Increment k.
     *        c. Append the completed row block (size = dim rows, width = cols*dim) to `rows`.
     *   4. Initialize `tiled` = rows[0].
     *   5. For each subsequent row i in [1..rows.size()−1], append rows[i] to the bottom of `tiled`.
     *   6. Return `tiled`.
     *
     * Why:
     *   - Ensures that if there are fewer than cols² packets, the missing grid slots are zero-filled tiles,
     *     preserving a square final image of consistent size.
     */
    std::vector<std::vector<uint8_t>> tile_images(const std::vector<std::vector<std::vector<uint8_t>>>& images,
                                                  const uint cols, const uint dim) 
    {
        std::vector<std::vector<std::vector<uint8_t>>> rows;
        size_t k = 0;  // Tracks which tile index we’re on

        // 1) Build each row of the tile grid
        for (size_t i = 0; i < cols; ++i) {
            std::vector<std::vector<uint8_t>> row;  // Combined row of tiles
            for (size_t j = 0; j < cols; ++j) {
                std::vector<std::vector<uint8_t>> im;
                if (k < images.size()) {
                    im = images[k];  // Use actual 16×16 tile
                } else {
                    im = npzero(dim);  // Use zero tile if no more images
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

        // 2) Stack all rows vertically to form final tiled image
        std::vector<std::vector<uint8_t>> tiled = std::move(rows[0]);
        for (size_t i = 1; i < rows.size(); ++i) {
            tiled.insert(tiled.end(), rows[i].begin(), rows[i].end());
        }
        return tiled;
    }
};

/**
 * @class MarkovTransitionMatrixPacket
 * @brief Computes a single 16×16 Markov transition matrix for one packet and exposes it as an image.
 *
 * Inherits from MarkovTransitionMatrix to reuse transition_matrix().
 * Responsibilities:
 *   - Given one heiFIPPacketImage, extract its 4-bit bit array.
 *   - Compute the 16×16 transition matrix and store it as `matrix`.
 *   - Provide get_matrix() to retrieve that single matrix.
 */
class MarkovTransitionMatrixPacket : public MarkovTransitionMatrix {
public:
    /**
     * @brief Constructor: compute the Markov transition matrix for a single packet.
     *
     * @param packet  heiFIPPacketImage containing raw packet bytes.
     *
     * Workflow:
     *   1. Call packet.bit_array() to get a vector<uint8_t> of 4-bit values.
     *   2. Call transition_matrix(transition) to produce a 16×16 grayscale matrix.
     *   3. Store the resulting matrix in member `matrix`.
     */
    MarkovTransitionMatrixPacket(const heiFIPPacketImage packet) : packet(packet) {
        std::vector<uint8_t> transition = packet.bit_array();
        matrix = transition_matrix(transition);
    }

    /// Accessor for the computed 16×16 matrix
    const std::vector<std::vector<uint8_t>>& get_matrix() const {
        return matrix;
    }

private:
    heiFIPPacketImage packet;                          ///< The raw packet image to process
    std::vector<std::vector<uint8_t>> matrix;          ///< Resulting 16×16 transition matrix
};
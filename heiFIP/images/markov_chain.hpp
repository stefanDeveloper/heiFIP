#pragma once

#include <memory>
#include <string>
#include <vector>
#include <sstream>
#include "heiFIPPacketImage.hpp"
#include "NetworkTrafficImage.hpp"
#include "tile_utils.hpp"

/**
 * @class MarkovTransitionMatrix
 * @brief Base class for computing a normalized, grayscale Markov transition matrix from a sequence of symbols.
 *
 * Responsibilities:
 *   - Given a 1D vector of "transitions" (values in [0..15]), count the transitions between consecutive symbols.
 *   - Normalize each row of the count matrix so that probabilities sum to 1, then scale to [0..255].
 *   - Return the resulting 16×16 matrix of uint8_t intensities.
 */
class MarkovTransitionMatrix : public NetworkTrafficImage {
public:
    /**
     * @brief Compute a 16×16 Markov transition matrix from a sequence of 4-bit symbols.
     */
    std::vector<std::vector<uint8_t>> transition_matrix(const std::vector<uint8_t>& transitions) {
        const size_t n = 16;  
        std::vector<std::vector<uint8_t>> uintMatrix(n, std::vector<uint8_t>(n, 0));

        for (size_t k = 0; k + 1 < transitions.size(); ++k) {
            size_t i = transitions[k];
            size_t j = transitions[k + 1];
            uintMatrix[i][j] += 1;
        }

        for (auto& row : uintMatrix) {
            double sum = 0.0;
            for (double value : row) {
                sum += value;
            }
            if (sum > 0.0) {
                for (auto& value : row) {
                    double prob = static_cast<double>(value) / sum;
                    double scaled = prob * 255.0;
                    value = static_cast<uint8_t>(std::clamp(scaled, 0.0, 255.0));
                }
            }
        }

        return uintMatrix;
    }
};

/**
 * @class MarkovTransitionMatrixFlow
 * @brief Builds a larger image by computing a Markov transition matrix for each packet in a flow,
 *        then arranging all 16×16 matrices into a fixed grid of tiles.
 */
class MarkovTransitionMatrixFlow : public MarkovTransitionMatrix {
public:
    MarkovTransitionMatrixFlow(const std::vector<heiFIPPacketImage>& packets, unsigned int cols = 4)
        : packets(packets), cols(cols)
    {
        std::vector<std::vector<std::vector<uint8_t>>> result;
        for (const heiFIPPacketImage& packet : packets) {
            std::vector<uint8_t> transition = packet.bit_array();
            std::vector<std::vector<uint8_t>> m = transition_matrix(transition);
            result.push_back(std::move(m));
        }
        matrix = tile_utils::tile_images(result, cols, 16);
    }

    const std::vector<std::vector<uint8_t>>& get_matrix() const {
        return matrix;
    }

private:
    std::vector<heiFIPPacketImage> packets;
    unsigned int cols;
    MarkovTransitionMatrix transitionMatrix;
    std::vector<std::vector<uint8_t>> matrix;
};

/**
 * @class MarkovTransitionMatrixPacket
 * @brief Computes a single 16×16 Markov transition matrix for one packet and exposes it as an image.
 */
class MarkovTransitionMatrixPacket : public MarkovTransitionMatrix {
public:
    MarkovTransitionMatrixPacket(const heiFIPPacketImage packet) : packet(packet) {
        std::vector<uint8_t> transition = packet.bit_array();
        matrix = transition_matrix(transition);
    }

    const std::vector<std::vector<uint8_t>>& get_matrix() const {
        return matrix;
    }

private:
    heiFIPPacketImage packet;
    std::vector<std::vector<uint8_t>> matrix;
};
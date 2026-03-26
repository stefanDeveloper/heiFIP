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

#include "heiFIPPacketImage.hpp"
#include "NetworkTrafficImage.hpp"
#include "tile_utils.hpp"

/**
 * @class FlowImageTiledFixed
 * @brief Builds a fixed-grid tiled image from a sequence of packet images.
 *
 * Inherits from NetworkTrafficImage, which provides base logic for traffic-based images.
 * Responsibilities:
 *   - Convert each packet's raw bytes into its own dim×dim tile, padding/truncating as needed.
 *   - Arrange all those tiles into a fixed-size grid with `cols` tiles per row and per column.
 *   - Provide getters for both the tiled matrix and the original per-packet binaries.
 */
class FlowImageTiledFixed : public NetworkTrafficImage {
public:
    FlowImageTiledFixed(const std::vector<heiFIPPacketImage>& packets, int dim = 16, int fill = 0, int cols = 3)
        : NetworkTrafficImage(fill, dim), packets(packets), cols(cols) 
    {
        auto result = get_matrix_tiled(fill, dim, packets);
        matrix   = std::move(result.first);
        binaries = std::move(result.second);
    }

    const std::vector<std::vector<uint8_t>>& get_matrix() const {
        return matrix;
    }

    std::vector<std::vector<uint8_t>>& get_binaries() {
        return binaries;
    }

private:
    std::vector<heiFIPPacketImage> packets;
    int cols;
    std::vector<std::vector<uint8_t>> matrix;
    std::vector<std::vector<uint8_t>> binaries;

    std::pair<std::vector<std::vector<uint8_t>>, std::vector<std::vector<uint8_t>>> 
    get_matrix_tiled(int fill, int dim, const std::vector<heiFIPPacketImage>& packets) {
        std::vector<std::vector<uint8_t>> binaries;

        for (const heiFIPPacketImage& packet : packets) {
            binaries.push_back(packet.getHexData());
        }

        std::vector<std::vector<std::vector<uint8_t>>> result;
        for (const auto& x : binaries) {
            std::vector<std::vector<uint8_t>> reshaped(dim, std::vector<uint8_t>(dim, static_cast<uint8_t>(fill)));
            size_t k = 0;
            for (size_t i = 0; i < static_cast<size_t>(dim) && k < x.size(); ++i) {
                for (size_t j = 0; j < static_cast<size_t>(dim) && k < x.size(); ++j) {
                    reshaped[i][j] = x[k++];
                }
            }
            result.push_back(std::move(reshaped));
        }

        std::vector<std::vector<uint8_t>> fh = tile_utils::tile_images(
            result, static_cast<unsigned int>(cols), static_cast<unsigned int>(dim));
        return { fh, binaries };
    }
};
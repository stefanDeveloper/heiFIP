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
 * @class FlowImageTiledAuto
 * @brief Builds a square, tiled image from a sequence of packet images, automatically determining tile dimensions.
 *
 * Inherits from NetworkTrafficImage, which stores a default fill value and base dimension.
 * Responsibilities:
 *   - Convert each packet's raw bytes into its own dim×dim tile, padding/truncating as needed.
 *   - Arrange all those tiles into a larger square grid (dim_total×dim_total), where dim_total = ceil(sqrt(numTiles)).
 *   - Provide getters for the final tiled matrix and the original per-packet binaries.
 */
class FlowImageTiledAuto : public NetworkTrafficImage {
public:
    FlowImageTiledAuto(const std::vector<heiFIPPacketImage>& packets, int dim = 16, int fill = 0, bool auto_dim = false)
        : NetworkTrafficImage(fill, dim), packets(packets), auto_dim(auto_dim) 
    {
        auto result = get_matrix_tiled(fill, dim, auto_dim, packets);
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
    bool auto_dim;
    std::vector<std::vector<uint8_t>> matrix;
    std::vector<std::vector<uint8_t>> binaries;

    std::pair<std::vector<std::vector<uint8_t>>, std::vector<std::vector<uint8_t>>> 
    get_matrix_tiled(int fill, int dim, bool auto_dim, const std::vector<heiFIPPacketImage>& packets) {
        std::vector<std::vector<uint8_t>> binaries;
        for (const heiFIPPacketImage& packet : packets) {
            binaries.push_back(packet.getHexData());
        }

        size_t length = 0;
        for (const auto& b : binaries) {
            length = std::max(length, b.size());
        }

        if (auto_dim) {
            dim = static_cast<int>(std::ceil(std::sqrt(static_cast<double>(length))));
        }

        std::vector<std::vector<std::vector<uint8_t>>> result;
        for (const auto& x : binaries) {
            std::vector<std::vector<uint8_t>> reshaped(dim, std::vector<uint8_t>(dim, static_cast<uint8_t>(fill)));
            size_t k = 0;
            for (int i = 0; i < dim && k < x.size(); ++i) {
                for (int j = 0; j < dim && k < x.size(); ++j) {
                    reshaped[i][j] = x[k++];
                }
            }
            result.push_back(std::move(reshaped));
        }

        size_t length_total = result.size();
        unsigned int dim_total = static_cast<unsigned int>(std::ceil(std::sqrt(static_cast<double>(length_total))));

        std::vector<std::vector<uint8_t>> fh = tile_utils::tile_images(result, dim_total, static_cast<unsigned int>(dim));
        return { fh, binaries };
    }
};
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
#include "packetHelper.cpp"
#include "NetworkTrafficImage.hpp"

class FlowImageTiledAuto : public NetworkTrafficImage {

public:
    FlowImageTiledAuto(const std::vector<heiFIPPacketImage>& packets, int dim = 16, int fill = 0, bool auto_dim = false)
        : NetworkTrafficImage(fill, dim), packets(packets), auto_dim(auto_dim) {
            std::pair<std::vector<std::vector<uint8_t>>, std::vector<std::vector<uint8_t>>>  result = get_matrix_tiled(fill, dim, auto_dim, packets);
            matrix = result.first;
            binaries = result.second;    }
    
    std::vector<std::vector<uint8_t>>& get_matrix() {
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

    std::pair<std::vector<std::vector<uint8_t>>, std::vector<std::vector<uint8_t>>> get_matrix_tiled(int fill, int dim, bool auto_dim, const std::vector<heiFIPPacketImage>& packets) {
        std::vector<std::vector<uint8_t>> binaries;

        for (const heiFIPPacketImage& packet : packets) {
            std::vector<uint8_t> hexData = packet.getHexData();
            binaries.push_back(hexData);
        }

        size_t length = 0;
        for (const std::vector<uint8_t>& b : binaries) {
            length = std::max(length, b.size());
        }

        if (auto_dim) {
            dim = static_cast<int>(std::ceil(std::sqrt(length)));
        }
        std::vector<std::vector<std::vector<uint8_t>>> result;
        for (const std::vector<uint8_t>& x : binaries) {
            std::vector<std::vector<uint8_t>> reshaped(dim, std::vector<uint8_t>(dim, fill));
            size_t k = 0;
            for(int i = 0; dim > i && k < x.size(); ++i) {
                for(int j = 0; dim > j && k < x.size(); ++j) {
                    reshaped[i][j] = x[k];
                    ++k;
                }
            }
            result.push_back(reshaped);
        }

        size_t length_total = result.size();
        uint dim_total = static_cast<uint>(std::ceil(std::sqrt(length_total)));

        std::vector<std::vector<uint8_t>> fh = tile_images(result, dim_total, dim);
        return {fh, binaries};
    }

    std::vector<std::vector<uint8_t>> npzero(size_t dim) {
        return std::vector<std::vector<uint8_t>>(dim, std::vector<uint8_t>(dim, 0));
    }

    std::vector<std::vector<uint8_t>> npconcatenate(const std::vector<std::vector<uint8_t>>& img1, const std::vector<std::vector<uint8_t>>& img2) {
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

    std::vector<std::vector<uint8_t>> tile_images(const std::vector<std::vector<std::vector<uint8_t>>>& images, const uint cols, const uint dim) {
        
        std::vector<std::vector<std::vector<uint8_t>> > rows;
        size_t k = 0; // Index to track current image
        for (size_t i = 0; i < cols; ++i) {
            std::vector<std::vector<uint8_t>>  row;
            for (size_t j = 0; j < cols; ++j) {
                std::vector<std::vector<uint8_t>>  im;
                if (k < images.size()) {
                    im = images[k];
                } else {
                    im = npzero(dim);
                }

                if (row.empty()) {
                    row = im;
                } else {
                    row = npconcatenate(row, im);
                }
                ++k;
            }
            rows.push_back(row);
        }

        std::vector<std::vector<uint8_t>> tiled = rows[0];

        for (size_t i = 1; i < rows.size(); ++i) {
            tiled.insert(tiled.end(), rows[i].begin(), rows[i].end());
        }
        return tiled;
    }
};
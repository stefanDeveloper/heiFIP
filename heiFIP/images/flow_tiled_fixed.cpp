#include <iostream>
#include <vector>
#include <cmath>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <iterator>
#include <cstring>
#include <cstdint>
#include <crafter.h>
#include <memory>
#include <array>
#include "heiFIBPacketImage.cpp"
#include "packetHelper.cpp"
#include "NetworkTrafficImage.hpp"

class FlowImageTiledFixed : public NetworkTrafficImage {

public:
    FlowImageTiledFixed(const std::vector<heiFIBPacketImage>& packets, int dim = 16, int fill = 0, int cols = 3)
        : NetworkTrafficImage(fill, dim), packets(packets), cols(cols) {
            std::pair<std::vector<std::vector<uint8_t>>, std::vector<std::vector<uint8_t>>>  result = get_matrix_tiled(fill, dim, packets);
            matrix = result.first;
            binaries = result.second;    }
    
    std::vector<std::vector<uint8_t>>& get_matrix() {
        return matrix;
    }

    std::vector<std::vector<uint8_t>>& get_binaries() {
        return binaries;
    }
private:
    std::vector<heiFIBPacketImage> packets;
    int cols;
    std::vector<std::vector<uint8_t>> matrix;
    std::vector<std::vector<uint8_t>> binaries;

    std::pair<std::vector<std::vector<uint8_t>>, std::vector<std::vector<uint8_t>>> get_matrix_tiled(int fill, int dim, const std::vector<heiFIBPacketImage>& packets) {
        std::vector<std::vector<uint8_t>> binaries;

        for (const heiFIBPacketImage& packet : packets) {
            std::vector<uint8_t> hexData = packet.getHexData();
            binaries.push_back(hexData);
        }

        std::vector<std::vector<std::vector<uint8_t>>> result;
        for (const std::vector<uint8_t>& x : binaries) {
            std::vector<std::vector<uint8_t>> reshaped(dim, std::vector<uint8_t>(dim, fill));
            size_t k = 0;
            for(size_t i = 0; dim > i && k < x.size(); ++i) {
                for(size_t j = 0; dim > j && k < x.size(); ++j) {
                    reshaped[i][j] = x[k];
                    ++k;
                }
            }
            result.push_back(reshaped);
        }

        std::vector<std::vector<uint8_t>> fh = tile_images(result, cols, dim);
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
        
        std::vector<std::vector<std::vector<uint8_t>>> rows;
        size_t k = 0; // Index to track current image
        for (size_t i = 0; i < cols; ++i) {
            std::vector<std::vector<uint8_t>> row;
            for (size_t j = 0; j < cols; ++j) {
                std::vector<std::vector<uint8_t>> im;
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

    std::vector<uint8_t> hexlify(const Crafter::Packet& packet) {

        // Create a vector to store the bytes as decimal integers
        std::vector<uint8_t> hex_data;

        // Use copy of packet to avoid modification
        Crafter::Packet copied_packet = packet;
        
        // Access the raw bytes of the crafted packet
        const uint8_t* raw_bytes = copied_packet.GetRawPtr();
        size_t packet_size = copied_packet.GetSize();

        // Push each byte individually into the vector
        for (size_t i = 0; i < packet_size; ++i) {
            hex_data.push_back(static_cast<uint8_t>(raw_bytes[i]));
        }

        return hex_data;
    }

};
#include "NetworkTrafficImage.hpp"

#include <iostream>
#include <vector>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <cstdint>
#include <memory>
#include <list>
#include <string>
#include "heiFIBPacketImage.cpp"
#include "packetHelper.cpp"

class FlowImage : public NetworkTrafficImage {
public:
    FlowImage(std::vector<heiFIBPacketImage> packets, int dim = 16, int fill = 0, bool append = false)
        : NetworkTrafficImage(fill, dim), packets(packets), append(append) {
        auto result = getMatrix(dim, append, fill, packets);
        matrix = result.first;
        binaries = result.second;
    }

    std::vector<std::vector<uint8_t>>& get_binaries() {
        return binaries;
    }

    std::vector<std::vector<uint8_t>>& get_matrix() {
        return matrix;
    }

private:
    std::vector<heiFIBPacketImage> packets;
    bool append;
    std::vector<std::vector<uint8_t>> matrix;
    std::vector<std::vector<uint8_t>> binaries;

    std::pair<std::vector<std::vector<uint8_t>>, std::vector<std::vector<uint8_t>>> getMatrix(int dim, bool append, int fill, const std::vector<heiFIBPacketImage>& packets) {
        std::vector<std::vector<uint8_t>> binaries;

        for (heiFIBPacketImage packet : packets) {
            std::vector<uint8_t> hexData = packet.getHexData();
            binaries.push_back(hexData);
        }

        std::vector<uint8_t> fh;
        if (append) {
            for (const auto& binary : binaries) {
                fh.insert(fh.end(), binary.begin(), binary.end());
            }
            int rn = fh.size() / dim + (fh.size() % dim > 0);
            fh.resize(rn * dim, static_cast<uint8_t>(0));
            std::vector<std::vector<uint8_t>> reshaped(rn, std::vector<uint8_t>(dim));
            for (int i = 0; i < rn; ++i) {
                std::copy(fh.begin() + i * dim, fh.begin() + (i + 1) * dim, reshaped[i].begin());
            }
            return {reshaped, binaries};
        } else {
            size_t length = 0;
            for (const auto& binary : binaries) {
                length = std::max(length, binary.size());
            }
            std::vector<std::vector<uint8_t>> reshaped;
            for (const auto& binary : binaries) {
                std::vector<uint8_t> row = binary;
                row.resize(length, static_cast<uint8_t>(fill));
                reshaped.push_back(row);
            }
            return {reshaped, binaries};
        }
    }
};
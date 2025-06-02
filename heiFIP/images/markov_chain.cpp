#include <memory>
#include <string>
#include <vector>
#include <sstream>

#include "heiFIPPacketImage.cpp"
#include "packetHelper.cpp"

#include "NetworkTrafficImage.hpp"

class MarkovTransitionMatrix : public NetworkTrafficImage {

public:
    MarkovTransitionMatrix(): NetworkTrafficImage(){}
    
    std::vector<std::vector<uint8_t>> transition_matrix(const std::vector<uint8_t>& transitions) {
        size_t n = 16;
        std::vector<std::vector<uint8_t>> uintMatrix(n, std::vector<uint8_t>(n, 0));
        
        for (size_t k = 0; k < transitions.size() - 1; ++k) {
            size_t i = transitions[k];
            size_t j = transitions[k + 1];
            uintMatrix[i][j] += 1;
        }

        for (std::vector<uint8_t>& row : uintMatrix) {
            double sum = 0;
            uint8_t element = 0;
            for (double value : row) {
                sum += value;
            }
            if (sum > 0) {
                for (uint8_t& value : row) {
                    value = static_cast<uint8_t>(std::clamp(((value/sum) * 255.0), 0.0, 255.0));
                }
            }
        }        
        return uintMatrix;
    }
};

class MarkovTransitionMatrixFlow : public MarkovTransitionMatrix {
    public:
        MarkovTransitionMatrixFlow(const std::vector<heiFIPPacketImage>& packets, uint cols = 4) : packets(packets), cols(cols) {

            std::vector<std::vector<std::vector<uint8_t>>> result;
            transitionMatrix = MarkovTransitionMatrix();

            for (heiFIPPacketImage packet: packets) {
                std::vector<uint8_t> transition = packet.bit_array();
                std::vector<std::vector<uint8_t>> m = transition_matrix(transition);
                result.push_back(m);
            }

            matrix = tile_images(result, cols, 16);

        }

        std::vector<heiFIPPacketImage> packets;
        uint cols;
        MarkovTransitionMatrix transitionMatrix;

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

        std::vector<std::vector<uint8_t>>& get_matrix() {
            return matrix;
        }

    private:

    std::vector<std::vector<uint8_t>> matrix;
};

class MarkovTransitionMatrixPacket: public MarkovTransitionMatrix {
public:
    MarkovTransitionMatrixPacket(const heiFIPPacketImage packet) : packet(packet) {
        std::vector<uint8_t> transition = packet.bit_array();
        matrix = transition_matrix(transition);
    }

    std::vector<std::vector<uint8_t>>& get_matrix() {
        return matrix;
    }

private:
    heiFIPPacketImage packet;
    std::vector<std::vector<uint8_t>> matrix;
};
#include <memory>
#include <string>
#include <vector>
#include <sstream>

#include "heiFIBPacketImage.cpp"
#include "packetHelper.cpp"

#include "NetworkTrafficImage.hpp"

class MarkovTransitionMatrix : public NetworkTrafficImage {

public:
    MarkovTransitionMatrix(): NetworkTrafficImage(){}
    
    std::vector<std::vector<double>> transition_matrix(const std::vector<uint8_t>& transitions) {
        size_t n = 16;
        std::vector<std::vector<double>> M(n, std::vector<double>(n, 0));
        
        for (size_t k = 0; k < transitions.size() - 1; ++k) {
            size_t i = transitions[k];
            size_t j = transitions[k + 1];
            M[i][j] += 1;
        }

        for (std::vector<double>& row : M) {
            double sum = 0;
            for (double value : row) {
                sum += value;
            }
            if (sum > 0) {
                for (double& value : row) {
                    value /= sum;
                }
            }
        }        
        return M;
    }
};

class MarkovTransitionMatrixFlow : public MarkovTransitionMatrix {
    public:
        MarkovTransitionMatrixFlow(const std::vector<heiFIBPacketImage>& packets, uint cols = 4) : packets(packets), cols(cols) {

            std::vector<std::vector<std::vector<double>>> result;
            transitionMatrix = MarkovTransitionMatrix();

            for (heiFIBPacketImage packet: packets) {
                std::vector<uint8_t> transition = packet.bit_array();
                std::vector<std::vector<double>> m = transition_matrix(transition);
                result.push_back(m);
            }

            matrix = tile_images(result, cols, 16);

        }

        std::vector<heiFIBPacketImage> packets;
        uint cols;
        MarkovTransitionMatrix transitionMatrix;

        std::vector<std::vector<double>> npzero(size_t dim) {
            return std::vector<std::vector<double>>(dim, std::vector<double>(dim, 0));
        }

        std::vector<std::vector<double>> npconcatenate(const std::vector<std::vector<double>>& img1, const std::vector<std::vector<double>>& img2) {
            if (img1.empty()) return img2;
            if (img2.empty()) return img1;

            if (img1.size() != img2.size()) {
                throw std::invalid_argument("Images must have the same number of rows to concatenate horizontally.");
            }

            std::vector<std::vector<double>> result = img1;
            for (size_t i = 0; i < result.size(); ++i) {
                result[i].insert(result[i].end(), img2[i].begin(), img2[i].end());
            }
            return result;
        }

        std::vector<std::vector<double>> tile_images(const std::vector<std::vector<std::vector<double>>>& images, const uint cols, const uint dim) {
            
            std::vector<std::vector<std::vector<double>>> rows;
            size_t k = 0; // Index to track current image
            for (size_t i = 0; i < cols; ++i) {
                std::vector<std::vector<double>> row;
                for (size_t j = 0; j < cols; ++j) {
                    std::vector<std::vector<double>> im;
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

            std::vector<std::vector<double>> tiled = rows[0];

            for (size_t i = 1; i < rows.size(); ++i) {
                tiled.insert(tiled.end(), rows[i].begin(), rows[i].end());
            }
            return tiled;
        }

        std::vector<std::vector<double>>& get_matrix() {
            return matrix;
        }

    private:

    std::vector<std::vector<double>> matrix;
};

class MarkovTransitionMatrixPacket: public MarkovTransitionMatrix {
public:
    MarkovTransitionMatrixPacket(const heiFIBPacketImage packet) : packet(packet) {
        std::vector<uint8_t> transition = packet.bit_array();
        matrix = transition_matrix(transition);
    }

    std::vector<std::vector<double>>& get_matrix() {
        return matrix;
    }

private:
    heiFIBPacketImage packet;
    std::vector<std::vector<double>> matrix;
};
#pragma once

#include <iostream>
#include <cmath>
#include "PcapHeaders.h"
#include <vector>
#include <iomanip>
#include <bitset>
#include <memory>
#include <sstream>

class heiFIPPacketImage {
    public:
        heiFIPPacketImage(std::vector<uint8_t> data, uint32_t cap_length) : _data(data), _cap_length(cap_length) {}

        heiFIPPacketImage(std::vector<uint8_t> data) : _data(data) {
            PcapPacketHeader packetHeader;
            _cap_length = packetHeader.caplen;  
        }
        
        heiFIPPacketImage(std::vector<uint8_t> data, int dim, int fill, bool auto_dim) : _data(data) {
            PcapPacketHeader packetHeader;
            _cap_length = packetHeader.caplen;
            std::pair<std::vector<std::vector<uint8_t>>, std::vector<std::vector<uint8_t>>>  result = heiFIPPacketImage::get_matrix_tiled(fill, dim, auto_dim);
            heiFIPPacketImage::matrix = result.first;
            heiFIPPacketImage::binaries = result.second;   
        }
        
        ~heiFIPPacketImage() {}
        
        void printHexData() const {
            std::cout << std::dec << "Packet has size" << " (Size: " << get_cap_length() << " bytes):\n";
            for (size_t i = 0; i < _data.size(); i++) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(_data[i]) << " ";
            }
            std::cout << std::endl;
        }
        
        std::vector<uint8_t> getHexData() const {
            std::vector<uint8_t> hexData;
            size_t packetSize = _data.size();
            for (size_t i = 0; i < packetSize; ++i) {
                hexData.push_back(static_cast<uint8_t>(_data[i]));
            }
            return hexData;
        }
        
        std::vector<uint8_t> bit_array() const {
        
            // Use copy of packet to avoid modification
            std::vector<uint8_t> data;
            // Push each byte individually into the vector
            for (uint8_t bit: _data) {
                data.push_back(static_cast<unsigned char>(bit));
            }
            std::string bytes_as_bits;
            for (unsigned char byte : data) {
                bytes_as_bits += std::bitset<8>(byte).to_string();
            }
            
            std::vector<uint8_t> transition;
            for (size_t i = 0; i < bytes_as_bits.length(); i += 4) {
                transition.push_back(std::stoi(bytes_as_bits.substr(i, 4), nullptr, 2));
            }
            return transition;
        }
        
        std::pair<std::vector<std::vector<uint8_t>>, std::vector<std::vector<uint8_t>>> get_matrix_tiled(int fill, int dim, bool auto_dim) {
            std::vector<std::vector<uint8_t>> binaries;
        
            std::vector<uint8_t> hexData = (*this).getHexData();
            binaries.push_back(hexData);
        
            size_t length = 0;
            for (const std::vector<uint8_t>& b : binaries) {
                length = std::max(length, b.size());
            }
        
            if (auto_dim) {
                dim = static_cast<int>(std::ceil(std::sqrt(length)));
            }
        
            int total = dim * dim;
            std::vector<uint8_t> flat;
            flat.reserve(total);
        
            // 1) Flatten the double-vector
            for (const auto& row : binaries) {
                flat.insert(flat.end(), row.begin(), row.end());
            }
        
            // 2) Pad with `fill` if too short
            if (flat.size() < total) {
                flat.insert(flat.end(), total - flat.size(), fill);
            }
            // 3) Or truncate if too long
            else if (flat.size() > total) {
                flat.resize(total);
            }
        
            // 4) Reshape into dim × dim
            std::vector<std::vector<uint8_t>> result(dim, std::vector<uint8_t>(dim));
            for (size_t idx = 0; idx < total; ++idx) {
                size_t i = idx / dim;
                size_t j = idx % dim;
                result[i][j] = flat[idx];
            }
        
            return {result, binaries};
        }
        
        std::vector<uint8_t> get_data() const {
            return _data;
        }
        
        void set_data(std::vector<uint8_t> data) {
            _data = data;
        }
        
        uint32_t get_cap_length() const {
            return _cap_length;
        }
        
        void set_cap_length(uint32_t cap_length) {
            _cap_length = cap_length;
        }
        
        std::vector<std::vector<uint8_t>>& get_matrix() {
            return matrix;
        }

    private:
        std::vector<uint8_t> _data;
        uint32_t _cap_length;
        std::vector<std::vector<uint8_t>> binaries;
        std::vector<std::vector<uint8_t>> matrix;
};
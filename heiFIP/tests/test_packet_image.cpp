#include <gtest/gtest.h>
#include "assets/heiFIPPacketImage.hpp"

TEST(PacketImageTest, Construction) {
    std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
    heiFIPPacketImage pkt(data);
    
    EXPECT_EQ(pkt.get_cap_length(), 4);
    EXPECT_EQ(pkt.getHexData(), data);
}

TEST(PacketImageTest, BitArray) {
    // 0xAB = 1010 1011
    // Bit array should give 10 and 11
    std::vector<uint8_t> data = {0xAB};
    heiFIPPacketImage pkt(data);
    
    auto bits = pkt.bit_array();
    ASSERT_EQ(bits.size(), 2);
    EXPECT_EQ(bits[0], 10); // 1010
    EXPECT_EQ(bits[1], 11); // 1011
}

TEST(PacketImageTest, TiledMatrix) {
    // 4 bytes, dim 2 -> should be 2x2 matrix
    std::vector<uint8_t> data = {1, 2, 3, 4};
    heiFIPPacketImage pkt(data, 2, 0, false);
    
    auto matrix = pkt.get_matrix();
    ASSERT_EQ(matrix.size(), 2);
    EXPECT_EQ(matrix[0], (std::vector<uint8_t>{1, 2}));
    EXPECT_EQ(matrix[1], (std::vector<uint8_t>{3, 4}));
}

TEST(PacketImageTest, TiledMatrixPadding) {
    // 2 bytes, dim 2 -> should be 2x2 matrix padded with 255
    std::vector<uint8_t> data = {1, 2};
    heiFIPPacketImage pkt(data, 2, 255, false);
    
    auto matrix = pkt.get_matrix();
    ASSERT_EQ(matrix.size(), 2);
    EXPECT_EQ(matrix[0], (std::vector<uint8_t>{1, 2}));
    EXPECT_EQ(matrix[1], (std::vector<uint8_t>{255, 255}));
}

TEST(PacketImageTest, AutoDim) {
    // 10 bytes -> ceil(sqrt(10)) = 4
    std::vector<uint8_t> data(10, 1);
    heiFIPPacketImage pkt(data, 0, 0, true);
    
    auto matrix = pkt.get_matrix();
    ASSERT_EQ(matrix.size(), 4);
    EXPECT_EQ(matrix[0].size(), 4);
    EXPECT_EQ(matrix[0][0], 1);
}

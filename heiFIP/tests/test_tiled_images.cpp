#include <gtest/gtest.h>
#include "images/flow_tiled_fixed.hpp"
#include "images/flow_tiled_auto.hpp"
#include "assets/heiFIPPacketImage.hpp"

TEST(TiledImagesTest, FixedGrid) {
    std::vector<heiFIPPacketImage> packets;
    // 1 packet, dim 2, grid 2x2
    packets.emplace_back(std::vector<uint8_t>{1, 2, 3, 4});
    
    FlowImageTiledFixed tiled(packets, 2, 0, 2);
    
    auto matrix = tiled.get_matrix();
    // Grid 2x2, tile dim 2 -> final 4x4
    ASSERT_EQ(matrix.size(), 4);
    EXPECT_EQ(matrix[0], (std::vector<uint8_t>{1, 2, 0, 0}));
    EXPECT_EQ(matrix[2], (std::vector<uint8_t>{0, 0, 0, 0}));
}

TEST(TiledImagesTest, AutoGrid) {
    std::vector<heiFIPPacketImage> packets;
    // 2 packets, dim 2 -> grid 2x2
    packets.emplace_back(std::vector<uint8_t>{1, 2, 3, 4});
    packets.emplace_back(std::vector<uint8_t>{5, 6, 7, 8});
    
    FlowImageTiledAuto tiled(packets, 2, 0, false);
    
    auto matrix = tiled.get_matrix();
    ASSERT_EQ(matrix.size(), 4);
    EXPECT_EQ(matrix[0], (std::vector<uint8_t>{1, 2, 5, 6}));
    EXPECT_EQ(matrix[2], (std::vector<uint8_t>{0, 0, 0, 0}));
}

#include <gtest/gtest.h>
#include "images/flow.hpp"
#include "assets/heiFIPPacketImage.hpp"

TEST(FlowImageTest, NonAppendMode) {
    std::vector<heiFIPPacketImage> packets;
    packets.emplace_back(std::vector<uint8_t>{1, 2, 3});
    packets.emplace_back(std::vector<uint8_t>{4, 5});
    
    // dim 4, fill 0, append false
    FlowImage flow(packets, 4, 0, false);
    
    auto matrix = flow.get_matrix();
    ASSERT_EQ(matrix.size(), 2);
    EXPECT_EQ(matrix[0], (std::vector<uint8_t>{1, 2, 3, 0}));
    EXPECT_EQ(matrix[1], (std::vector<uint8_t>{4, 5, 0, 0}));
}

TEST(FlowImageTest, AppendMode) {
    std::vector<heiFIPPacketImage> packets;
    packets.emplace_back(std::vector<uint8_t>{1, 2});
    packets.emplace_back(std::vector<uint8_t>{3, 4});
    
    // dim 2, fill 0, append true
    // [1, 2, 3, 4] reshaped to 2x2
    FlowImage flow(packets, 2, 0, true);
    
    auto matrix = flow.get_matrix();
    ASSERT_EQ(matrix.size(), 2);
    EXPECT_EQ(matrix[0], (std::vector<uint8_t>{1, 2}));
    EXPECT_EQ(matrix[1], (std::vector<uint8_t>{3, 4}));
}

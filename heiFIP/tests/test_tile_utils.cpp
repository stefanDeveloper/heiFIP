#include <gtest/gtest.h>
#include "images/tile_utils.hpp"

using namespace tile_utils;

TEST(TileUtilsTest, NpZero) {
    size_t dim = 4;
    auto zero = npzero(dim);
    EXPECT_EQ(zero.size(), dim);
    for (const auto& row : zero) {
        EXPECT_EQ(row.size(), dim);
        for (uint8_t val : row) {
            EXPECT_EQ(val, 0);
        }
    }
}

TEST(TileUtilsTest, NpConcatenate) {
    std::vector<std::vector<uint8_t>> img1 = {{1, 2}, {3, 4}};
    std::vector<std::vector<uint8_t>> img2 = {{5, 6}, {7, 8}};
    
    auto concat = npconcatenate(img1, img2);
    
    ASSERT_EQ(concat.size(), 2);
    EXPECT_EQ(concat[0], (std::vector<uint8_t>{1, 2, 5, 6}));
    EXPECT_EQ(concat[1], (std::vector<uint8_t>{3, 4, 7, 8}));
}

TEST(TileUtilsTest, NpConcatenateEmpty) {
    std::vector<std::vector<uint8_t>> img1 = {{1, 2}};
    std::vector<std::vector<uint8_t>> empty;
    
    EXPECT_EQ(npconcatenate(img1, empty), img1);
    EXPECT_EQ(npconcatenate(empty, img1), img1);
}

TEST(TileUtilsTest, NpConcatenateMismatchedHeight) {
    std::vector<std::vector<uint8_t>> img1 = {{1, 2}};
    std::vector<std::vector<uint8_t>> img2 = {{5, 6}, {7, 8}};
    
    EXPECT_THROW(npconcatenate(img1, img2), std::invalid_argument);
}

TEST(TileUtilsTest, TileImages) {
    std::vector<std::vector<uint8_t>> t1 = {{1, 1}, {1, 1}};
    std::vector<std::vector<uint8_t>> t2 = {{2, 2}, {2, 2}};
    std::vector<std::vector<std::vector<uint8_t>>> tiles = {t1, t2};
    
    // Grid 2x2, tile dim 2
    auto tiled = tile_images(tiles, 2, 2);
    
    ASSERT_EQ(tiled.size(), 4);
    EXPECT_EQ(tiled[0], (std::vector<uint8_t>{1, 1, 2, 2}));
    EXPECT_EQ(tiled[1], (std::vector<uint8_t>{1, 1, 2, 2}));
    EXPECT_EQ(tiled[2], (std::vector<uint8_t>{0, 0, 0, 0}));
    EXPECT_EQ(tiled[3], (std::vector<uint8_t>{0, 0, 0, 0}));
}

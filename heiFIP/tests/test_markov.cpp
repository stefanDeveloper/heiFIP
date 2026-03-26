#include <gtest/gtest.h>
#include "images/markov_chain.hpp"
#include "assets/heiFIPPacketImage.hpp"

TEST(MarkovTest, TransitionMatrixComputation) {
    MarkovTransitionMatrix mtm;
    // Transitions: 0->1, 1->0, 0->1
    std::vector<uint8_t> transitions = {0, 1, 0, 1};
    
    auto matrix = mtm.transition_matrix(transitions);
    ASSERT_EQ(matrix.size(), 16);
    
    // Row 0: two 0->1 transitions. Sum = 2. 0->1 prob = 1.0 (255)
    EXPECT_EQ(matrix[0][1], 255);
    // Row 1: one 1->0 transition. Sum = 1. 1->0 prob = 1.0 (255)
    EXPECT_EQ(matrix[1][0], 255);
    // Others 0
    EXPECT_EQ(matrix[0][0], 0);
}

TEST(MarkovTest, PacketMarkov) {
    std::vector<uint8_t> data = {0xAB}; // 1010 1011 -> nibbles 10, 11
    heiFIPPacketImage pkt(data);
    
    MarkovTransitionMatrixPacket mtmp(pkt);
    auto matrix = mtmp.get_matrix();
    ASSERT_EQ(matrix.size(), 16);
    // One transition 10->11
    EXPECT_EQ(matrix[10][11], 255);
}

TEST(MarkovTest, FlowMarkov) {
    std::vector<heiFIPPacketImage> packets;
    packets.emplace_back(std::vector<uint8_t>{0xAB});
    packets.emplace_back(std::vector<uint8_t>{0xCD});
    
    // 2 packets, grid 2x2, tile dim 16 -> final 32x32
    MarkovTransitionMatrixFlow mtmf(packets, 2);
    auto matrix = mtmf.get_matrix();
    ASSERT_EQ(matrix.size(), 32);
}

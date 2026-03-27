#include <gtest/gtest.h>
#include "extractor.hpp"
#include <filesystem>

TEST(ExtractorTest, LoadPcap) {
    // dns53.pcap exists in tests/pcaps/
    std::string pcapPath = "../../tests/pcaps/dns53.pcap";
    if (!std::filesystem::exists(pcapPath)) {
        GTEST_SKIP() << "Test PCAP file not found at " << pcapPath;
    }
    
    FIPExtractor extractor;
    // Test direct extraction
    PacketProcessorType procType = PacketProcessorType::HEADER;
    // dns53.pcap has 2 packets
    auto packets = extractor.getPackets(pcapPath, procType, false, 0);
    
    EXPECT_FALSE(packets.empty());
    EXPECT_EQ(packets.size(), 1);
}

TEST(ExtractorTest, CreateMatrix) {
    std::string pcapPath = "../../tests/pcaps/dns53.pcap";
    if (!std::filesystem::exists(pcapPath)) {
        GTEST_SKIP() << "Test PCAP file not found";
    }
    
    FIPExtractor extractor;
    PacketProcessorType procType = PacketProcessorType::HEADER;
    
    // PacketImageArgs {dim, fill, auto_dim}
    PacketImageArgs args{16, 0, true};
    
    auto images = extractor.createImageFromFile(
        pcapPath,
        args,
        procType,
        ImageType::PacketImage,
        1, 100, 1, 100, false
    );
    
    EXPECT_FALSE(images.empty());
    // Check first image dimensions
    EXPECT_GE(images[0].size(), 16);
    EXPECT_GE(images[0][0].size(), 16);
}

TEST(ExtractorTest, InvalidFileThrows) {
    FIPExtractor extractor;
    PacketImageArgs args{16, 0, true};
    
    EXPECT_THROW({
        extractor.createImageFromFile(
            "non_existent.pcap",
            args,
            PacketProcessorType::HEADER,
            ImageType::PacketImage,
            1, 100, 1, 100, false
        );
    }, std::runtime_error);
}

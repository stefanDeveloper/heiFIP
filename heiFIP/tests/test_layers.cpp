#include <gtest/gtest.h>
#include "layers/init.hpp"
#include <filesystem>
#include <PcapFileDevice.h>

TEST(LayerTest, IPPacketAddressMapping) {
    std::string pcapPath = "../../tests/pcaps/dns53.pcap";
    if (!std::filesystem::exists(pcapPath)) {
        GTEST_SKIP() << "Test PCAP file not found";
    }

    PacketProcessor processor;
    auto packets = processor.readPacketsFile(pcapPath, PacketProcessorType::NONE);
    ASSERT_FALSE(packets.empty());

    auto& pkt = packets[0];
    auto mapping = pkt->getAdressMapping();

    // dns53.pcap: 207.158.192.40 > 10.20.1.31
    // The keys are the ORIGINAL addresses
    EXPECT_TRUE(mapping.count("207.158.192.40"));
    EXPECT_TRUE(mapping.count("10.20.1.31"));
    
    // The values should be DIFFERENT (anonymized)
    EXPECT_NE(mapping["207.158.192.40"], "207.158.192.40");
    EXPECT_NE(mapping["10.20.1.31"], "10.20.1.31");
}

TEST(LayerTest, TransportPacketPorts) {
    std::string pcapPath = "../../tests/pcaps/dns53.pcap";
    if (!std::filesystem::exists(pcapPath)) {
        GTEST_SKIP() << "Test PCAP file not found";
    }

    PacketProcessor processor;
    auto packets = processor.readPacketsFile(pcapPath, PacketProcessorType::NONE);
    ASSERT_FALSE(packets.empty());

    auto* transPkt = dynamic_cast<TransportPacket*>(packets[0].get());
    ASSERT_NE(transPkt, nullptr);
    
    auto mapping = transPkt->getAdressMapping();

    // DNS uses port 53. TransportPacket maps "53" -> "53" (currently no port anonymization)
    EXPECT_TRUE(mapping.count("53"));
    EXPECT_EQ(mapping["53"], "53");
}

TEST(LayerTest, DNSPacketFields) {
    std::string pcapPath = "../../tests/pcaps/dns53.pcap";
    if (!std::filesystem::exists(pcapPath)) {
        GTEST_SKIP() << "Test PCAP file not found";
    }

    PacketProcessor processor;
    auto packets = processor.readPacketsFile(pcapPath, PacketProcessorType::NONE);
    ASSERT_FALSE(packets.empty());

    auto* dnsPkt = dynamic_cast<DNSPacket*>(packets[0].get());
    ASSERT_NE(dnsPkt, nullptr);

    auto layerMap = dnsPkt->getLayerMap();
    EXPECT_TRUE(layerMap["DNS"]);
}

TEST(LayerTest, HeaderPreprocessingMasking) {
    std::string pcapPath = "../../tests/pcaps/dns53.pcap";
    if (!std::filesystem::exists(pcapPath)) {
        GTEST_SKIP() << "Test PCAP file not found";
    }

    PacketProcessor processor;
    auto pktsNone = processor.readPacketsFile(pcapPath, PacketProcessorType::NONE);
    auto pktsHeader = processor.readPacketsFile(pcapPath, PacketProcessorType::HEADER);

    ASSERT_EQ(pktsNone.size(), pktsHeader.size());
    
    size_t lenNone = pktsNone[0]->getRawPacket()->getRawDataLen();
    // Use the raw packet from the parsed Packet object to ensure we see modifications
    size_t lenHeader = pktsHeader[0]->getPacket().getRawPacket()->getRawDataLen();

    bool foundCustom = false;
    for (pcpp::Layer* l = pktsHeader[0]->getPacket().getFirstLayer(); l; l = l->getNextLayer()) {
        if (l->toString().find("Custom") != std::string::npos) {
            foundCustom = true;
        }
    }
    
    EXPECT_TRUE(foundCustom) << "No 'Custom' layer found in preprocessed packet";
    
    // If it fails, report the layers for debugging
    if (lenHeader >= lenNone) {
        std::cout << "DEBUG: lenNone=" << lenNone << " lenHeader=" << lenHeader << std::endl;
        for (pcpp::Layer* l = pktsHeader[0]->getPacket().getFirstLayer(); l; l = l->getNextLayer()) {
            std::cout << "  Layer: " << l->toString() << " HeaderLen: " << l->getHeaderLen() << std::endl;
        }
    }

    EXPECT_LT(lenHeader, lenNone) << "Packet length did not decrease after header preprocessing";
}

TEST(LayerTest, HTTPRequestPreprocessing) {
    std::string pcapPath = "../../tests/pcaps/http/206_example_b.pcap";
    if (!std::filesystem::exists(pcapPath)) {
        GTEST_SKIP() << "Test PCAP file not found";
    }

    PacketProcessor processor;
    // Load with HEADER preprocessing
    auto packets = processor.readPacketsFile(pcapPath, PacketProcessorType::HEADER);
    ASSERT_FALSE(packets.empty());

    // Look for CustomHTTPRequest layer
    bool foundCustomHTTP = false;
    for (auto& p : packets) {
        const pcpp::Packet& pkt = p->getPacket();
        for (pcpp::Layer* layer = pkt.getFirstLayer(); layer; layer = layer->getNextLayer()) {
            if (layer->toString().find("HTTP Request Layer") != std::string::npos) {
                foundCustomHTTP = true;
                break;
            }
        }
        if (foundCustomHTTP) break;
    }

    EXPECT_TRUE(foundCustomHTTP) << "CustomHTTPRequest layer not found in preprocessed HTTP packets";
}

TEST(LayerTest, HTTPResponsePreprocessing) {
    std::string pcapPath = "../../tests/pcaps/http/206_example_b.pcap";
    if (!std::filesystem::exists(pcapPath)) {
        GTEST_SKIP() << "Test PCAP file not found";
    }

    PacketProcessor processor;
    // Load with HEADER preprocessing
    auto packets = processor.readPacketsFile(pcapPath, PacketProcessorType::HEADER);
    ASSERT_FALSE(packets.empty());

    // Look for CustomHTTPResponse layer
    bool foundCustomHTTP = false;
    for (auto& p : packets) {
        const pcpp::Packet& pkt = p->getPacket();
        for (pcpp::Layer* layer = pkt.getFirstLayer(); layer; layer = layer->getNextLayer()) {
            if (layer->toString().find("HTTP Response Layer") != std::string::npos) {
                foundCustomHTTP = true;
                break;
            }
        }
        if (foundCustomHTTP) break;
    }

    EXPECT_TRUE(foundCustomHTTP) << "CustomHTTPResponse layer not found in preprocessed HTTP packets";
}



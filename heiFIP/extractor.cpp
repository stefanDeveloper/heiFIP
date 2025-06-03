#pragma once

#include "init.cpp"
#include "NetworkTrafficImage.hpp"
#include "flow.cpp"
#include "flow_tiled_auto.cpp"
#include "flow_tiled_fixed.cpp"
#include "markov_chain.cpp"
#include "heiFIPPacketImage.cpp"
#include <filesystem>
#include <algorithm>
#include <opencv2/opencv.hpp>
#include <string>
#include <iostream>

struct FlowImageArgs {
    size_t dim;
    bool append;
    size_t fill;
};

struct FlowImageTiledFixedArgs {
    size_t dim;
    size_t fill;
    size_t cols;
};

struct FlowImageTiledAutoArgs {
    size_t dim;
    size_t fill;
    bool auto_dim;
};

struct PacketImageArgs {
    size_t dim;
    bool auto_dim;
    size_t fill;
};

struct MarkovTransitionMatrixFlowArgs {
    size_t cols;
};

struct MarkovTransitionMatrixPacketArgs {
}; 

using ImageArgsVariant = std::variant<
    std::monostate, 
    FlowImageArgs,
    FlowImageTiledFixedArgs,
    FlowImageTiledAutoArgs,
    PacketImageArgs,
    MarkovTransitionMatrixFlowArgs,
    MarkovTransitionMatrixPacketArgs
>;

using UInt8Matrix = std::vector<std::vector<std::vector<uint8_t>>>;

enum class ImageType {
    FlowImage,
    FlowImageTiledFixed,
    FlowImageTiledAuto,
    PacketImage,
    MarkovTransitionMatrixFlow,
    MarkovTransitionMatrixPacket
};

/**
 * FIPExtractor orchestrates packet processing and image generation.
 */
class FIPExtractor {
    public:
        /**
         * Verify generated image dimensions and optional duplicate removal.
         * ImgType must provide getHeight(), getWidth(), data(), dataSize().
         */
        template<typename ImgType>
        bool verify(const ImgType& image, size_t minImageDim, size_t maxImageDim, bool removeDuplicates) {
            size_t height = image.size();
            size_t width = image[0].size();
            if (height < minImageDim || width < minImageDim) {
                std::cout << "[!] Image not created due to minumum height or width restriction" << std::endl;
                return false;
            }
            
            if (maxImageDim != 0 && (height > maxImageDim || width > maxImageDim)) {
                std::cout << "[!] Image not created due to maximum height or width restriction" << std::endl;
                return false;
            }
            // if (removeDuplicates) {
            //     std::string raw(reinterpret_cast<const char*>(image.data()), image.dataSize());
            //     if (imagesCreatedSet.count(raw))
            //         return false;
            //     imagesCreatedSet.insert(raw);
            // }
            return true;
        }
    public:
        FIPExtractor()
            : processor() {}

        UInt8Matrix createImageFromFile(
            const std::string& input_file,
            const ImageArgsVariant& args,
            PacketProcessorType preprocessing_type = PacketProcessorType::NONE,
            ImageType image_type = ImageType::PacketImage,
            int min_image_dim = 0,
            int max_image_dim = 0,
            int min_packets_per_flow = 0,
            int max_packets_per_flow = 0,
            bool remove_duplicates = false
        ) {
            if (!std::filesystem::exists(input_file)) {
                throw std::runtime_error("Input file does not exist");
            }
            
            std::vector<std::unique_ptr<FIPPacket>> processed_packets = processor.readPacketsFile(input_file, preprocessing_type, remove_duplicates, max_packets_per_flow);
            return createMatrix(
                processed_packets,
                preprocessing_type,
                image_type,
                min_image_dim,
                max_image_dim,
                min_packets_per_flow,
                max_packets_per_flow,
                remove_duplicates,
                args
            );
        }

        UInt8Matrix createImageFromPacket(
            std::vector<std::unique_ptr<pcpp::RawPacket>>& packets,
            const ImageArgsVariant& args,
            PacketProcessorType preprocessing_type = PacketProcessorType::NONE,
            ImageType image_type = ImageType::PacketImage,
            size_t min_image_dim = 0,
            size_t max_image_dim = 0,
            size_t min_packets_per_flow = 0,
            size_t max_packets_per_flow = 0,
            bool remove_duplicates = false
        ) {

            // Process packets using the PacketProcessor 
            std::vector<std::unique_ptr<FIPPacket>> processed_packets = processor.readPacketsList(packets, preprocessing_type, remove_duplicates);    
            // Create images using the __create_matrix method
            return createMatrix(
                processed_packets,
                preprocessing_type,
                image_type,
                min_image_dim,
                max_image_dim,
                min_packets_per_flow,
                max_packets_per_flow,
                remove_duplicates,
                args
            );
        }

    /**
     * Create image matrices from FIPPacket flows or packets.
     * Template on ImgType: one of FlowImage, FlowImageTiledFixed, FlowImageTiledAuto,
     * PacketImage, MarkovTransitionMatrixFlow, MarkovTransitionMatrixPacket.
     */
    // Instead of a single variadic template, provide overloads for each image type
    // FlowImage: takes packets and a flow-specific parameter, e.g., time window
    UInt8Matrix createMatrix(
        std::vector<std::unique_ptr<FIPPacket>>& packets,
        PacketProcessorType preprocessing_type,
        ImageType image_type,
        size_t min_image_dim,
        size_t max_image_dim,
        size_t min_packets_per_flow,
        size_t max_packets_per_flow,
        bool remove_duplicates,
        const ImageArgsVariant& args
    ) {
        if (std::holds_alternative<std::monostate>(args)) {
            throw std::runtime_error("Image arguments not initialized.");
        }

        if (max_packets_per_flow && packets.size() > static_cast<size_t>(max_packets_per_flow)) {
            packets.resize(max_packets_per_flow);
        }

        std::vector<heiFIPPacketImage> packets_copy;
        for (const std::unique_ptr<FIPPacket>& packet: packets) {
            const uint8_t* packetData = packet->getRawPacket()->getRawData();
            size_t packetLen = packet->getRawPacket()->getRawDataLen();
            std::vector<uint8_t> rawData;
            for (size_t i = 0; i < packetLen; ++i) {
                rawData.push_back(packetData[i]); // Add each element to the vector
            }
            packets_copy.push_back(heiFIPPacketImage(rawData));
        }

        switch (image_type) {
            case ImageType::FlowImage: {
                if (packets.size() < static_cast<size_t>(min_packets_per_flow)) {
                    return {};
                }

                UInt8Matrix images;
                auto actualArgs = std::get<FlowImageArgs>(args);
                FlowImage image(packets_copy, actualArgs.dim, actualArgs.fill, actualArgs.append);
                if (verify(image.get_matrix(), min_image_dim, max_image_dim, remove_duplicates)) {
                    images.push_back(image.get_matrix());
                }
                return images;
            }
    
            case ImageType::FlowImageTiledFixed: {
                if (packets.size() < static_cast<size_t>(min_packets_per_flow)) {
                    return {};
                }
                
                UInt8Matrix images;
                auto actualArgs = std::get<FlowImageTiledFixedArgs>(args);
                FlowImageTiledFixed image(packets_copy, actualArgs.dim, actualArgs.fill, actualArgs.cols);
                
                if (verify(image.get_matrix(), min_image_dim, max_image_dim, remove_duplicates)) {
                    images.push_back(image.get_matrix());
                }
                return images;
            }
    
            case ImageType::FlowImageTiledAuto: {
                                std::cout << std::to_string(packets_copy.size()) << std::endl;

                if (packets.size() < static_cast<size_t>(min_packets_per_flow)) {
                    return {};
                }

                UInt8Matrix images;
                auto actualArgs = std::get<FlowImageTiledAutoArgs>(args);
                FlowImageTiledAuto image(packets_copy, actualArgs.dim, actualArgs.fill, actualArgs.auto_dim);

                if (verify(image.get_matrix(), min_image_dim, max_image_dim, remove_duplicates)) {
                    images.push_back(image.get_matrix());
                }
                return images;
            }
    
            case ImageType::PacketImage: {

                auto actualArgs = std::get<PacketImageArgs>(args);
                UInt8Matrix images;

                for (const std::unique_ptr<FIPPacket>& pkt : packets) {
                    const uint8_t* packetData = pkt->getRawPacket()->getRawData();
                    int packetLen = pkt->getRawPacket()->getRawDataLen();
                    std::vector<uint8_t> rawData;
        
                    for (size_t i = 0; i < packetLen; ++i) {
                        rawData.push_back(packetData[i]); // Add each element to the vector
                    }
        
                    heiFIPPacketImage image = heiFIPPacketImage(rawData, actualArgs.dim, actualArgs.fill, actualArgs.auto_dim);
                    std::vector<std::vector<uint8_t>> matrix = image.get_matrix();
                    if (verify(matrix, min_image_dim, max_image_dim, remove_duplicates))
                        images.push_back(matrix);
                }
                return images;
            }
    
            case ImageType::MarkovTransitionMatrixFlow: {

                if (packets.size() < static_cast<size_t>(min_packets_per_flow)) {
                    return {};
                }

                UInt8Matrix images;
                auto actualArgs = std::get<MarkovTransitionMatrixFlowArgs>(args);
                MarkovTransitionMatrixFlow image(packets_copy, actualArgs.cols);

                if (verify(image.get_matrix(), min_image_dim, max_image_dim, remove_duplicates)) {
                    images.push_back(image.get_matrix());
                }
                return images;
            }
    
            case ImageType::MarkovTransitionMatrixPacket: {

                auto actualArgs = std::get<MarkovTransitionMatrixPacketArgs>(args);
                UInt8Matrix images;
                const uint8_t* packetData;
                std::vector<uint8_t> rawData;
                int packetLen;

                for (const std::unique_ptr<FIPPacket>& pkt : packets) {
                    packetData = pkt->getRawPacket()->getRawData();
                    packetLen = pkt->getRawPacket()->getRawDataLen();
                    for (size_t i = 0; i < packetLen; ++i) {
                        rawData.push_back(packetData[i]); // Add each element to the vector
                    }
                    heiFIPPacketImage rawImage = heiFIPPacketImage(rawData);
                    MarkovTransitionMatrixPacket image = MarkovTransitionMatrixPacket(rawImage);
                    std::vector<std::vector<uint8_t>> matrix = image.get_matrix();
                    if (verify(matrix, min_image_dim, max_image_dim, remove_duplicates))
                        images.push_back(matrix);
                }
                return images;
            }
    
            default:
                throw std::runtime_error("Wrong Parameter passed");
        }
    
        return {}; // Empty
    }

    void save_image(const UInt8Matrix& img, const std::string& output_path_base) {
        if (img.empty() || img[0].empty() || img[0][0].empty()) {
            std::cerr << "Empty image, cannot save." << std::endl;
            return;
        }

        // Expecting shape: [1][height][width]
        const auto& grayscale_image = img[0]; // Only the first 2D slice

        int height = static_cast<int>(grayscale_image.size());
        int width = static_cast<int>(grayscale_image[0].size());

        cv::Mat mat(height, width, CV_8UC1);

        for (size_t i = 0; i < height; ++i) {
            uint8_t* row_ptr = mat.ptr<uint8_t>(i);
            for (size_t j = 0; j < width; ++j) {
                row_ptr[j] = grayscale_image[i][j];
            }
        }

        std::filesystem::path outp(output_path_base + "_processed.png");
        std::filesystem::create_directories(outp.parent_path());
        cv::imwrite(outp.string(), mat);
    }

    private:
    PacketProcessor processor;
};
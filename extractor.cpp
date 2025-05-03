#pragma once

#include "init.cpp"
#include "NetworkTrafficImage.hpp"
#include "flow.cpp"
#include "flow_tiled_auto.cpp"
#include "flow_tiled_fixed.cpp"
#include "markov_chain.cpp"
#include "heiFIBPacketImage.cpp"
#include <filesystem>
#include <algorithm>        // for std::clamp
#include <opencv2/opencv.hpp>
#include <string>

struct FlowImageArgs {
    int dim;
    bool append;
    int fill;
};

struct FlowImageTiledFixedArgs {
    int dim;
    int fill;
    int cols;
};

struct FlowImageTiledAutoArgs {
    int dim;
    int fill;
    bool auto_dim;
};

struct PacketImageArgs {
    int dim;
    bool auto_dim;
    int fill;
};

struct MarkovTransitionMatrixFlowArgs {
    int cols;
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
using DoubleMatrix = std::vector<std::vector<std::vector<double>>>;

using MatrixVariant = std::variant<UInt8Matrix, DoubleMatrix>;

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
        bool verify(const ImgType& image, int minImageDim, int maxImageDim, bool removeDuplicates) {
            int height = image.size();
            int width = image[0].size();
            if (height < minImageDim || width < minImageDim)
                return false;
            if (maxImageDim != 0 && (height > maxImageDim || width > maxImageDim))
                return false;
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
    
        ~FIPExtractor() {
            for (auto img : imagesCreated) {
                delete img;
            }
        }

        MatrixVariant createImageFromFile(
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
        
            std::vector<FIPPacket*> processed_packets = processor.readPacketsFile(input_file, preprocessing_type);

        
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

        MatrixVariant createImageFromPacket(
            const std::vector<pcpp::Packet*>& packets,
            const ImageArgsVariant& args,
            PacketProcessorType preprocessing_type = PacketProcessorType::NONE,
            ImageType image_type = ImageType::PacketImage,
            int min_image_dim = 0,
            int max_image_dim = 0,
            int min_packets_per_flow = 0,
            int max_packets_per_flow = 0,
            bool remove_duplicates = false
        ) {

            // Process packets using the PacketProcessor
            std::vector<FIPPacket*> processed_packets = processor.readPacketsList(packets, preprocessing_type);
    
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
    MatrixVariant createMatrix(
        std::vector<FIPPacket*>& packets,
        PacketProcessorType preprocessing_type,
        ImageType image_type,
        int min_image_dim,
        int max_image_dim,
        int min_packets_per_flow,
        int max_packets_per_flow,
        bool remove_duplicates,
        const ImageArgsVariant& args
    ) {
        if (std::holds_alternative<std::monostate>(args)) {
            throw std::runtime_error("Image arguments not initialized.");
        }

        std::vector<FIPPacket*>& truncated = packets;
        if (max_packets_per_flow && truncated.size() > static_cast<size_t>(max_packets_per_flow)) {
            truncated.resize(max_packets_per_flow);
        }

        std::vector<heiFIBPacketImage> packets_copy;
        for (FIPPacket* packet: truncated) {
            const uint8_t* packetData = packet->getPacket()->getRawPacket()->getRawData();
            int packetLen = packet->getPacket()->getRawPacket()->getRawDataLen();
            std::vector<uint8_t> rawData;
            for (size_t i = 0; i < packetLen; ++i) {
                rawData.push_back(packetData[i]); // Add each element to the vector
            }
            packets_copy.push_back(heiFIBPacketImage(rawData));
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
                std::vector<std::vector<std::vector<uint8_t>>> images;

                for (FIPPacket* pkt : packets) {
                    const uint8_t* packetData = pkt->getPacket()->getRawPacket()->getRawData();
                    int packetLen = pkt->getPacket()->getRawPacket()->getRawDataLen();
                    std::vector<uint8_t> rawData;
        
                    for (size_t i = 0; i < packetLen; ++i) {
                        rawData.push_back(packetData[i]); // Add each element to the vector
                    }
        
                    heiFIBPacketImage image = heiFIBPacketImage(rawData, actualArgs.dim, actualArgs.fill, actualArgs.dim);
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

                DoubleMatrix images;
                auto actualArgs = std::get<MarkovTransitionMatrixFlowArgs>(args);
                MarkovTransitionMatrixFlow image(packets_copy, actualArgs.cols);

                if (verify(image.get_matrix(), min_image_dim, max_image_dim, remove_duplicates)) {
                    images.push_back(image.get_matrix());
                }
                return images;
            }
    
            case ImageType::MarkovTransitionMatrixPacket: {

                auto actualArgs = std::get<MarkovTransitionMatrixPacketArgs>(args);
                std::vector<std::vector<std::vector<double>>>images;
                const uint8_t* packetData;
                std::vector<uint8_t> rawData;
                int packetLen;

                for (FIPPacket* pkt : packets) {
                    packetData = pkt->getPacket()->getRawPacket()->getRawData();
                    packetLen = pkt->getPacket()->getRawPacket()->getRawDataLen();
                    for (size_t i = 0; i < packetLen; ++i) {
                        rawData.push_back(packetData[i]); // Add each element to the vector
                    }
                    heiFIBPacketImage rawImage = heiFIBPacketImage(rawData);
                    MarkovTransitionMatrixPacket image = MarkovTransitionMatrixPacket(rawImage);
                    std::vector<std::vector<double>> matrix = image.get_matrix();
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

    void save_image(const MatrixVariant& img_variant, const std::string& output_path_base) {
        std::visit([&](const auto& img) {
            if (img.empty() || img[0].empty() || img[0][0].empty()) {
                std::cerr << "Empty image, cannot save." << std::endl;
                return;
            }
    
            // Expecting shape: [1][height][width]
            const auto& grayscale_image = img[0]; // Only the first 2D slice
    
            int height = static_cast<int>(grayscale_image.size());
            int width = static_cast<int>(grayscale_image[0].size());
    
            cv::Mat mat(height, width, CV_8UC1);
    
            for (int i = 0; i < height; ++i) {
                uint8_t* row_ptr = mat.ptr<uint8_t>(i);
                for (int j = 0; j < width; ++j) {
                    if constexpr (std::is_same_v<std::decay_t<decltype(img)>, UInt8Matrix>) {
                        row_ptr[j] = grayscale_image[i][j];
                    } else {
                        double v = grayscale_image[i][j] * 255.0;
                        row_ptr[j] = static_cast<uint8_t>(std::clamp(v, 0.0, 255.0));
                    }
                }
            }
    
            std::filesystem::path outp(output_path_base + "_processed.png");
            std::filesystem::create_directories(outp.parent_path());
            cv::imwrite(outp.string(), mat);
        }, img_variant);
    }

    private:
    PacketProcessor processor;
    std::vector<NetworkTrafficImage*> imagesCreated;
};
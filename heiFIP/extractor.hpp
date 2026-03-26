#pragma once

#include <filesystem>
#include <algorithm>
#include <opencv2/opencv.hpp>
#include <string>
#include <iostream>
#include <concepts>

#include "init.hpp"
#include "flow.hpp"
#include "flow_tiled_auto.hpp"
#include "flow_tiled_fixed.hpp"
#include "markov_chain.hpp"
#include "heiFIPPacketImage.hpp"
#include "logging.hpp"


/**
 * @struct FlowImageArgs
 * @brief Parameters for creating a simple flow-based image.
 * @param dim       The target dimension (width and height) for the square output image.
 * @param append    If true, append new flow data to existing rows/columns rather than overwriting.
 * @param fill      Fill value to use when a flow has fewer packets than `dim` (padding).
 */
struct FlowImageArgs {
    size_t dim;
    bool append;
    size_t fill;
};

/**
 * @struct FlowImageTiledFixedArgs
 * @brief Parameters for creating a tiled flow image with a fixed number of columns.
 * @param dim   The dimension (width and height) of each tile (sub-image).
 * @param fill  Fill value used to pad tiles that have fewer packets than `dim * dim`.
 * @param cols  The number of columns of tiles to arrange horizontally.
 */
struct FlowImageTiledFixedArgs {
    size_t dim;
    size_t fill;
    size_t cols;
};

/**
 * @struct FlowImageTiledAutoArgs
 * @brief Parameters for creating a tiled flow image where the number of tiles per row is determined automatically.
 * @param dim       The approximate dimension (width/height) of each tile.
 * @param fill      Fill value for padding each tile.
 * @param auto_dim  If true, adapt the actual tile size at runtime based on packet count and other heuristics.
 */
struct FlowImageTiledAutoArgs {
    size_t dim;
    size_t fill;
    bool auto_dim;
};

/**
 * @struct PacketImageArgs
 * @brief Parameters for creating an image out of raw packet bytes (one image per packet).
 * @param dim       The dimension (width/height) of the output packet image.
 * @param auto_dim  If true, allow the image to grow/shrink based on packet length (otherwise force `dim x dim`).
 * @param fill      Fill value to pad packet data if it is shorter than `dim * dim`.
 */
struct PacketImageArgs {
    size_t dim;
    bool auto_dim;
    size_t fill;
};

/**
 * @struct MarkovTransitionMatrixFlowArgs
 * @brief Parameters for creating a flow-level Markov transition matrix image.
 * @param cols  The number of columns (and rows) in the square transition matrix (state space size).
 */
struct MarkovTransitionMatrixFlowArgs {
    size_t cols;
};

/**
 * @struct MarkovTransitionMatrixPacketArgs
 * @brief No parameters needed for packet‐level Markov transition matrix (state space inferred from packet features).
 */
struct MarkovTransitionMatrixPacketArgs {};

/**
 * @typedef ImageArgsVariant
 * @brief A std::variant that can hold any of the argument structures above, or std::monostate if not initialized.
 *
 * Usage: use std::get<SpecificArgsType>(args) once you know which ImageType you are generating.
 */
using ImageArgsVariant = std::variant<
    std::monostate,
    FlowImageArgs,
    FlowImageTiledFixedArgs,
    FlowImageTiledAutoArgs,
    PacketImageArgs,
    MarkovTransitionMatrixFlowArgs,
    MarkovTransitionMatrixPacketArgs
>;

/**
 * @typedef UInt8Matrix
 * @brief A 3D vector representing one or more grayscale images.
 *        Dimensions: [num_images][height][width], where each pixel is a uint8_t (0–255).
 */
using UInt8Matrix = std::vector<std::vector<std::vector<uint8_t>>>;

// This concept checks on thing on ImgType:
//  1) `image.get_matrix()` must be valid and return something convertible to
//     const std::vector<std::vector<uint8_t>>&
template<typename ImgType>
concept IsFlowImage = requires(const ImgType& image) {
    // Require `get_matrix() -> std::vector<std::vector<uint8_t>>&`
    { image.get_matrix() } -> std::convertible_to<const std::vector<std::vector<uint8_t>>&>;
};

/**
 * @enum ImageType
 * @brief Enumeration of supported image‐generation modes.
 *
 * - FlowImage:              One image per entire flow, packets arranged sequentially.
 * - FlowImageTiledFixed:    Splits each flow into fixed-size tiles and arranges them in a grid.
 * - FlowImageTiledAuto:     Similar to tiled fixed, but determines tile layout dynamically.
 * - PacketImage:            One image per packet, each packet’s raw bytes laid out row‐major.
 * - MarkovTransitionMatrixFlow:   Build a transition matrix between flow states (e.g., protocol flags).
 * - MarkovTransitionMatrixPacket: Build a transition matrix between packet‐level states (e.g., byte patterns).
 */
enum class ImageType {
    FlowImage,
    FlowImageTiledFixed,
    FlowImageTiledAuto,
    PacketImage,
    MarkovTransitionMatrixFlow,
    MarkovTransitionMatrixPacket
};

/**
 * @class FIPExtractor
 * @brief Coordinates reading pcap data, preprocessing, creating various image formats, and saving results.
 *
 * Responsibilities:
 *   1. Read packets from a file or in-memory list via PacketProcessor.
 *   2. Convert packet/flow data into one of several image types (FlowImage, PacketImage, etc.).
 *   3. Validate image dimensions and optionally suppress duplicates.
 *   4. Save the generated grayscale image(s) to disk as PNG.
 */
class FIPExtractor {
public:
    /**
     * @brief Verify that an image matrix meets size constraints and (optionally) isn’t a duplicate.
     *
     * @tparam ImgType    A type providing:
     *                        size() → number of rows (height),
     *                        operator.size() → number of columns (width),
     *                        data() → raw pointer or contiguous data buffer,
     *                        dataSize() → total number of bytes.
     * @param image           The 2D (or 3D) matrix returned by ImgType::get_matrix().
     * @param minImageDim     Minimum allowed dimension (height or width). Reject if smaller.
     * @param maxImageDim     Maximum allowed dimension (height or width). Reject if larger; zero → no limit.
     * @param removeDuplicates If true, compare this image’s raw bytes to a set of previously created images,
     *                         and reject if it already exists. (Currently commented out; future feature.)
     * @return true if image passes all checks, false otherwise.
     */

    template<IsFlowImage ImgType>
    bool verify(const ImgType& image,
                size_t minImageDim,
                size_t maxImageDim,
                bool removeDuplicates) 
    {
        if (image.get_matrix().empty() || image.get_matrix()[0].empty()) {
            LWARN("Image not created: empty matrix.");
            return false;
        }

        size_t height = image.get_matrix().size();
        size_t width  = image.get_matrix()[0].size();

        // Enforce minimum dimension constraint:
        if (height < minImageDim || width < minImageDim) {
            LWARN("Image not created: dimensions smaller than minimum (" << minImageDim << ").");
            return false;
        }

        // Enforce maximum dimension constraint (if nonzero):
        if (maxImageDim != 0 && (height > maxImageDim || width > maxImageDim)) {
            LWARN("Image not created: dimensions exceed maximum (" << maxImageDim << ").");
            return false;
        }

        if (removeDuplicates) {
            std::vector<std::vector<uint8_t>> matrix = image.get_matrix();
            if (imagesCreatedSet.count(matrix)) {
                LDEBUG("Image not created: duplicate detected.");
                return false;
            }
            imagesCreatedSet.insert({matrix, true});
        }

        return true; 
    }

    /**
     * @brief Default constructor initializes internal PacketProcessor.
     */
    FIPExtractor()
        : processor() 
    {}

    /**
     * @brief Read packets from a pcap file, preprocess, convert to image(s), and return as matrices.
     *
     * @param input_file           Path to the .pcap file. Must exist on disk.
     * @param args                 Variant containing the specific parameters for the chosen ImageType.
     * @param preprocessing_type   NONE or HEADER: whether to strip non-header bytes, etc.
     * @param image_type           Which type of image(s) to create (see ImageType enum).
     * @param min_image_dim        Minimum image dimension; images smaller will be discarded.
     * @param max_image_dim        Maximum image dimension; images larger will be discarded.
     * @param min_packets_per_flow Minimum packet count for a flow to produce an image (only relevant to flow modes).
     * @param max_packets_per_flow Maximum packet count per flow; extra packets are dropped.
     * @param remove_duplicates    If true, drop identical packets/flows during preprocessing.
     * @return UInt8Matrix         A vector of 2D matrices ([num_images][height][width]) ready for saving.
     * @throws std::runtime_error if input_file doesn’t exist or args aren’t initialized.
     */
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
        // Verify existence of the pcap file before proceeding:
        if (!std::filesystem::exists(input_file)) {
            LERROR("Input file does not exist: " << input_file);
            throw std::runtime_error("Input file does not exist: " + input_file);
        }

        LINFO("Processing PCAP file: " << input_file);

        // Read and preprocess packets from the file:
        //   - If remove_duplicates is true, duplicates are dropped here.
        //   - If max_packets_per_flow > 0, stop reading after that many packets.
        std::vector<std::unique_ptr<FIPPacket>> processed_packets =
            processor.readPacketsFile(
                input_file,
                preprocessing_type,
                remove_duplicates,
                max_packets_per_flow
            );

        LINFO("Read " << processed_packets.size() << " packets from file.");

        // Delegate to createMatrix, passing along preprocessing/filtering criteria
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
     * @brief Public access to packet reading functionality.
     */
    std::vector<std::unique_ptr<FIPPacket>> getPackets(
        const std::string& input_file,
        PacketProcessorType preprocessing_type = PacketProcessorType::NONE,
        bool remove_duplicates = false,
        size_t maxCount = 64
    ) {
        if (!std::filesystem::exists(input_file)) {
            return {};
        }
        return processor.readPacketsFile(input_file, preprocessing_type, remove_duplicates, maxCount);
    }

    /**
     * @brief Convert an in-memory list of RawPacket pointers to image(s).
     *
     * @param packets              A vector of unique_ptr<pcpp::RawPacket> containing raw packet data.
     * @param args                 Variant of parameters for the desired ImageType.
     * @param preprocessing_type   NONE/HEADER: how to preprocess each RawPacket.
     * @param image_type           Which image mode to use.
     * @param min_image_dim        Minimum image dimension threshold.
     * @param max_image_dim        Maximum image dimension threshold.
     * @param min_packets_per_flow Minimum packet count to form a flow (flow-based modes only).
     * @param max_packets_per_flow Maximum packet count per flow; extra packets are dropped.
     * @param remove_duplicates    If true, drop duplicate packets in preprocessing.
     * @return UInt8Matrix         A list of 2D matrices representing generated image(s).
     */
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
        // First, convert RawPacket vector into FIPPacket (which wraps RawPacket and extracts features):
        std::vector<std::unique_ptr<FIPPacket>> processed_packets =
            processor.readPacketsList(packets, preprocessing_type, remove_duplicates);

        // Delegate to createMatrix to produce the actual image(s):
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
     * @brief Core dispatcher that builds one or more images from FIPPacket data, based on ImageType.
     *
     * @param packets              Preprocessed packets wrapped in unique_ptr<FIPPacket>.
     * @param preprocessing_type   Repeats the chosen preprocessing strategy (just for bookkeeping).
     * @param image_type           Determines which case in the switch to execute.
     * @param min_image_dim        Reject images smaller than this dimension.
     * @param max_image_dim        Reject images larger than this dimension; zero → no limit.
     * @param min_packets_per_flow For flow-based modes: skip flows with fewer than this many packets.
     * @param max_packets_per_flow For flow-based modes: truncate flows to this many packets.
     * @param remove_duplicates    If true, drop duplicates in `verify()`.
     * @param args                 A variant containing exactly one of the argument structs required by the chosen ImageType.
     * @return UInt8Matrix         A list of image matrices; possibly empty if no image passed `verify()`.
     * @throws std::runtime_error  If `args` is std::monostate or ImageType is invalid.
     */
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
        // Ensure the caller provided a valid argument struct for the chosen image type:
        if (std::holds_alternative<std::monostate>(args)) {
            throw std::runtime_error("Image arguments not initialized for ImageType.");
        }

        // If we have a maximum packet‐per‐flow limit, cut the packet list down now:
        if (max_packets_per_flow && packets.size() > max_packets_per_flow) {
            LDEBUG("Truncating packet list from " << packets.size() << " to " << max_packets_per_flow);
            packets.resize(max_packets_per_flow);
        }

        // Convert each FIPPacket into a heiFIPPacketImage (byte vector). 
        // We do this early so that flow‐based or packet‐based modes can all operate on the same type.
        std::vector<heiFIPPacketImage> packets_copy;
        packets_copy.reserve(packets.size());
        for (const auto& packetPtr : packets) {
            // Extract raw bytes from the FIPPacket’s underlying RawPacket
            const uint8_t* packetData = packetPtr->getRawPacket()->getRawData();
            size_t packetLen = packetPtr->getRawPacket()->getRawDataLen();

            // Copy bytes into a std::vector<uint8_t>
            std::vector<uint8_t> rawData;
            rawData.reserve(packetLen);
            for (size_t i = 0; i < packetLen; ++i) {
                rawData.push_back(packetData[i]);
            }

            // Construct a packet‐image wrapper from rawData
            packets_copy.emplace_back(rawData);
        }

        // Now switch on the image type; each case returns either 1 image (as a single‐element vector)
        // or multiple images (e.g., a separate PacketImage for each packet).
        switch (image_type) {
            case ImageType::FlowImage: {
                // If a flow doesn’t have enough packets, skip entirely:
                if (packets.size() < min_packets_per_flow) {
                    return {};  // Return empty vector
                }

                // Extract the arguments specific to FlowImage:
                auto flowArgs = std::get<FlowImageArgs>(args);

                // Construct a FlowImage: uses packets_copy, desired dimension, fill value, and append flag
                FlowImage image(packets_copy, flowArgs.dim, flowArgs.fill, flowArgs.append);

                // Validate the resulting 2D matrix, then return it in a 1-element vector if valid:
                if (verify(image, min_image_dim, max_image_dim, remove_duplicates)) {
                    return { image.get_matrix() };
                }
                return {};
            }

            case ImageType::FlowImageTiledFixed: {
                if (packets.size() < min_packets_per_flow) {
                    return {};
                }

                auto tiledArgs = std::get<FlowImageTiledFixedArgs>(args);
                FlowImageTiledFixed image(packets_copy, tiledArgs.dim, tiledArgs.fill, tiledArgs.cols);

                if (verify(image, min_image_dim, max_image_dim, remove_duplicates)) {
                    return { image.get_matrix() };
                }
                return {};
            }

            case ImageType::FlowImageTiledAuto: {
                if (packets.size() < min_packets_per_flow) {
                    return {};
                }

                auto autoArgs = std::get<FlowImageTiledAutoArgs>(args);
                FlowImageTiledAuto image(packets_copy, autoArgs.dim, autoArgs.fill, autoArgs.auto_dim);

                if (verify(image, min_image_dim, max_image_dim, remove_duplicates)) {
                    return { image.get_matrix() };
                }
                return {};
            }

            case ImageType::PacketImage: {
                // Extract parameters for packet‐level images:
                auto packetArgs = std::get<PacketImageArgs>(args);
                UInt8Matrix images;  // We may generate one image per packet

                // Loop through each packet’s raw data, building a packet image:
                for (const auto& pktPtr : packets) {
                    const uint8_t* data = pktPtr->getRawPacket()->getRawData();
                    size_t len = pktPtr->getRawPacket()->getRawDataLen();

                    std::vector<uint8_t> rawData;
                    rawData.reserve(len);
                    for (size_t i = 0; i < len; ++i) {
                        rawData.push_back(data[i]);
                    }

                    // Create a packet‐level image (dim × dim or auto‐sized):
                    heiFIPPacketImage image(rawData, packetArgs.dim, packetArgs.fill, packetArgs.auto_dim);
                    auto matrix = image.get_matrix();

                    // Only include if it passes dimension checks:
                    if (verify(image, min_image_dim, max_image_dim, remove_duplicates)) {
                        images.push_back(matrix);
                    }
                }

                return images;
            }

            case ImageType::MarkovTransitionMatrixFlow: {
                if (packets.size() < min_packets_per_flow) {
                    return {};
                }

                auto markovFlowArgs = std::get<MarkovTransitionMatrixFlowArgs>(args);
                MarkovTransitionMatrixFlow image(packets_copy, markovFlowArgs.cols);

                if (verify(image, min_image_dim, max_image_dim, remove_duplicates)) {
                    return { image.get_matrix() };
                }
                return {};
            }

            case ImageType::MarkovTransitionMatrixPacket: {
                // Packet-level Markov: each packet produces one transition matrix image
                UInt8Matrix images;

                for (const auto& pktPtr : packets) {
                    const uint8_t* data = pktPtr->getRawPacket()->getRawData();
                    size_t len = pktPtr->getRawPacket()->getRawDataLen();

                    // Build a raw packet image (byte vector) first:
                    std::vector<uint8_t> rawData;
                    rawData.reserve(len);
                    for (size_t i = 0; i < len; ++i) {
                        rawData.push_back(data[i]);
                    }
                    heiFIPPacketImage packetImage(rawData);

                    // Now build Markov transition matrix from that packetImage:
                    MarkovTransitionMatrixPacket image(packetImage);
                    auto matrix = image.get_matrix();

                    if (verify(image, min_image_dim, max_image_dim, remove_duplicates)) {
                        images.push_back(matrix);
                    }
                }

                return images;
            }

            default:
                throw std::runtime_error("Unsupported ImageType passed to createMatrix");
        }

        // Should never get here because each switch-case returns or throws
        return {};
    }

    /**
     * @brief Write 2D image in a UInt8Matrix vector to disk as a PNG file.
     *
     * @param img          A vector of 2D matrices. Only `img[0]` is used (grayscale).
     * @param output_path  The desired file path (without extension). A ".png" is appended.
     *
     * Steps:
     *   1. Check that img is non-empty and contains at least one image.
     *   2. Interpret img[0] as a grayscale pixel grid: height × width, each pixel 0–255.
     *   3. Allocate an OpenCV Mat of type CV_8UC1 (single channel, 8-bit).
     *   4. Copy each pixel from the 2D vector into the Mat’s row‐major buffer.
     *   5. Ensure parent directory exists by calling std::filesystem::create_directories().
     *   6. Write the Mat to disk using cv::imwrite(..., path + ".png").
     */
    void save_image(const UInt8Matrix& img, const std::string& output_path) {
        // Quick sanity check: must have at least one image, and that image must be non-empty
        if (img.empty() || img[0].empty() || img[0][0].empty()) {
            LWARN("Empty image, cannot save: " << output_path);
            return;
        }

        // Ensure parent directory exists
        std::filesystem::path outp(output_path);
        std::filesystem::create_directories(outp.parent_path());

        // Save each image slice (assuming grayscale)
        for (size_t k = 0; k < img.size(); ++k) {
            const auto& grayscale_image = img[k];
            if (grayscale_image.empty() || grayscale_image[0].empty()) continue;

            int height = static_cast<int>(grayscale_image.size());
            int width  = static_cast<int>(grayscale_image[0].size());

            // Create an OpenCV Mat of the correct size and type (8-bit unsigned, single channel)
            cv::Mat mat(height, width, CV_8UC1);

            // Copy pixel values row by row
            for (int i = 0; i < height; ++i) {
                uint8_t* row_ptr = mat.ptr<uint8_t>(i);
                for (int j = 0; j < width; ++j) {
                    row_ptr[j] = grayscale_image[i][j];
                }
            }

            std::string final_path;
            if (img.size() == 1) {
                final_path = output_path + ".png";
            } else {
                final_path = output_path + "_" + std::to_string(k) + ".png";
            }

            // Write the PNG file to disk
            cv::imwrite(final_path, mat);
            LINFO("Image saved to: " << final_path);
        }
    }

private:
    PacketProcessor processor; ///< Responsible for reading pcap data, handling preprocessing, and converting RawPacket → FIPPacket
    std::map<std::vector<std::vector<uint8_t>>, bool> imagesCreatedSet;
};
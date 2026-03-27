#pragma once

#include <variant>
#include <string>

#include "extractor.hpp"

// Runner class orchestrates multithreaded image generation using FIPExtractor
class Runner {
private:
    int thread_number;          // Number of threads available for processing
    FIPExtractor extractor;     // Core packet/image extraction logic

public:
    // Constructor initializes thread count and extractor
    Runner(int thread_number) : thread_number(thread_number), extractor() {}

    /**
     * Generates an image from a pcap file and saves it to the output directory.
     *
     * @param output_name           Name of the saved image file (without extension)
     * @param input_file            Path to the input .pcap file
     * @param output_dir            Directory to store the resulting image
     * @param args                  Variant type containing parameters specific to the selected ImageType
     * @param preprocessing_type    Type of preprocessing to apply (e.g., NONE or HEADER-based)
     * @param image_type            The selected image generation mode
     * @param min_image_dim         Minimum dimension of the generated image
     * @param max_image_dim         Maximum dimension of the generated image
     * @param min_packets_per_flow  Lower bound on packets per flow for inclusion
     * @param max_packets_per_flow  Upper bound on packets per flow for inclusion
     * @param remove_duplicates     Whether to remove duplicate packets/flows before processing
     */
    void create_image(
        const std::string& output_name,
        const std::string& input_file,
        const std::string& output_dir,
        const ImageArgsVariant& args,
        PacketProcessorType preprocessing_type = PacketProcessorType::NONE,
        ImageType image_type = ImageType::PacketImage,
        int min_image_dim = 0,
        int max_image_dim = 0,
        int min_packets_per_flow = 0,
        int max_packets_per_flow = 0,
        bool remove_duplicates = false
    ) {
        // Create an image matrix from the input .pcap file using provided arguments
        UInt8Matrix img = extractor.createImageFromFile(
            input_file, 
            args,
            preprocessing_type, 
            image_type, 
            min_image_dim, 
            max_image_dim, 
            min_packets_per_flow, 
            max_packets_per_flow, 
            remove_duplicates
        );

        // Ensure output path is properly formed before saving
        if (!output_dir.empty() && output_dir.back() == '/') {
            extractor.save_image(img, output_dir + output_name);
        } else {
            extractor.save_image(img, output_dir + "/" + output_name);
        }
    }
};
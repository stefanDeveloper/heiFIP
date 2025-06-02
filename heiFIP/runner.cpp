#include <iostream>
#include <vector>
#include <variant>
#include <string>
#include <cassert>
#include <filesystem>
#include <thread>
#include <atomic>
#include <filesystem>

#include "extractor.cpp"

class Runner {
private:
    int thread_number;
    FIPExtractor extractor;

public:
    Runner(int thread_number) : thread_number(thread_number), extractor() {}

    void create_image(
        const std::string& output_name,
        const std::string& input_file,
        const std::string& output_dir,
        const ImageArgsVariant& args,
        std::atomic<int>& pbar,
        PacketProcessorType preprocessing_type = PacketProcessorType::NONE,
        ImageType image_type = ImageType::PacketImage,
        int min_image_dim = 0,
        int max_image_dim = 0,
        int min_packets_per_flow = 0,
        int max_packets_per_flow = 0,
        bool remove_duplicates = false
    ) {
        // Read and process the packets
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

        // Update progress bar
        pbar++;
        extractor.save_image(img, output_dir + output_name);
    }
};
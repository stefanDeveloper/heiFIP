#include "runner.hpp"
#include <filesystem>
#include <vector>

/// @brief Lists all `.pcap` file paths in a given directory.
/// @param dirString The path to the directory to scan.
/// @return A vector containing full paths to `.pcap` files in the directory.
std::vector<std::string> listPcapFilePathsInDir(const std::string& dirString) {
    std::vector<std::string> pcapFilePaths;
    std::filesystem::path dirPath{dirString};

    // Return empty if the path does not exist or is not a directory
    if (!std::filesystem::exists(dirPath) || !std::filesystem::is_directory(dirPath)) {
        return pcapFilePaths;
    }

    // Iterate through all files in the directory
    for (auto const& entry : std::filesystem::directory_iterator(dirPath)) {
        if (!entry.is_regular_file()) 
            continue;  // Skip directories or special files

        std::filesystem::path filepath = entry.path();
        if (filepath.extension() == ".pcap") {
            pcapFilePaths.push_back(filepath.string());  // Store full file path
        }
    }

    return pcapFilePaths;
}

/// @brief Extracts the filename without extension from a full file path.
/// @param fullPath The complete file path.
/// @return The filename without its extension.
std::string filenameWithoutExtension(const std::string& fullPath) {
    std::filesystem::path p{fullPath};
    return p.filename().stem().string();
}

/// @brief Entry point of the application.
/// Demonstrates loading `.pcap` files and generating images using a Runner object.
int main() {
    // Paths to input `.pcap` directory and output image directory
    std::string output_dir = "./";
    std::string input_dir = "../tests/pcaps/http";

    // Retrieve all `.pcap` files from the input directory
    std::vector<std::string> files = listPcapFilePathsInDir(input_dir);
    
    Runner runner(4);          // Runner with a thread pool of size 4

    // Predefined argument sets for various image generation strategies
    FlowImageArgs args{16, true, 0};
    FlowImageTiledFixedArgs args2{16, 0, 3};
    FlowImageTiledAutoArgs args3{16, 0, true};
    MarkovTransitionMatrixFlowArgs args4{3};
    MarkovTransitionMatrixPacketArgs args5{};
    PacketImageArgs args6{16, 0, true};

    // Process each `.pcap` file and generate an image
    for (const std::string& filepath : files) {
        runner.create_image(
            filenameWithoutExtension(filepath),  // Image name based on filename
            filepath,                            // Path to `.pcap` input file
            output_dir,                          // Where to save output image
            args3,                               // Argument set (select one appropriate for image type)
            PacketProcessorType::HEADER,         // Use HEADER for packet processing
            ImageType::FlowImageTiledAuto,       // Type of image to generate
            1,                                   // Minimum image dimension
            2000,                                // Maximum image dimension
            1,                                   // Minimum packets per flow
            2000,                                // Maximum packets per flow
            false                                // Whether to remove duplicate packets
        );
    }

    // return 0 indicates successful execution
    return 0;
}
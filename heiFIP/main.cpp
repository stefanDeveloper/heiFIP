#include "runner.cpp"

std::vector<std::string> listPcapFilePathsInDir(const std::string& dirString) {
    std::vector<std::string> pcapFilePaths;
    std::filesystem::path dirPath{dirString};

    if (!std::filesystem::exists(dirPath) || !std::filesystem::is_directory(dirPath)) {
        return pcapFilePaths;  // empty if not a directory
    }

    for (auto const& entry : std::filesystem::directory_iterator(dirPath)) {
        if (!entry.is_regular_file()) 
            continue;  // skip non‐files

        std::filesystem::path filepath = entry.path();
        if (filepath.extension() == ".pcap") {
            // Push the full path (as a string)
            pcapFilePaths.push_back(filepath.string());
        }
    }

    return pcapFilePaths;
}

std::string filenameWithoutExtension(const std::string& fullPath) {
    std::filesystem::path p{fullPath};
    return p.filename().stem().string();
}

// Main function to demonstrate the usage of the Runner
int main() {

    std::string output_dir = "/Users/henrirebitzky/Documents/BachelorDerInformatikAnDerUniversitätHeidelberg/IFPGit/heiFIP/build/";  // Update with actual output path
    std::string input_dir = "/Users/henrirebitzky/Documents/BachelorDerInformatikAnDerUniversitätHeidelberg/IFPGit/tests/pcaps/http";
    std::vector<std::string> files = listPcapFilePathsInDir(input_dir);
    
    std::atomic<int> pbar(0);
    Runner runner(4);

    FlowImageArgs args{16, true, 0};
    FlowImageTiledFixedArgs args2{16, 0, 3};
    FlowImageTiledAutoArgs args3{16, 0, true};
    MarkovTransitionMatrixFlowArgs args4{3};
    MarkovTransitionMatrixPacketArgs args5{};
    PacketImageArgs args6{16, 0, true};

    for (std::string filepath: files) {
        // Simulate calling the method with appropriate parameters
        runner.create_image(
            filenameWithoutExtension(filepath),
            filepath, 
            output_dir,
            args3,  // args placeholder
            pbar,
            PacketProcessorType::HEADER,  // Example of using HEADER processing
            ImageType::FlowImageTiledAuto,  // Example: pass nullptr for NetworkTrafficImage
            1,  // min_image_dim
            2000,  // max_image_dim
            1,  // min_packets_per_flow
            100,  // max_packets_per_flow
            false  // remove_duplicates
        );
    }
    
    // std::cout << "Process completed." << std::endl;
    return 0;
}
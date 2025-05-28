#include "runner.cpp"

// Main function to demonstrate the usage of the Runner
int main() {

    std::string input_file = "/Users/henrirebitzky/Documents/BachelorDerInformatikAnDerUniversitätHeidelberg/IFP/heiFIPCpp/tests/pcaps/http/http-11-request-then-cruft.pcap";  // Update with actual path
    std::string output_dir = "/Users/henrirebitzky/Documents/BachelorDerInformatikAnDerUniversitätHeidelberg/IFPGit/heiFIP/build";  // Update with actual output path

    std::atomic<int> pbar(0);
    Runner runner(4);

    FlowImageArgs args{16, true, 0};
    FlowImageTiledFixedArgs args2{16, 0, 3};
    FlowImageTiledAutoArgs args3{16, 0, true};
    MarkovTransitionMatrixFlowArgs args4{3};
    MarkovTransitionMatrixPacketArgs args5{};
    PacketImageArgs args6{16, 0, true};

    
    // Simulate calling the method with appropriate parameters
    runner.create_image(
        input_file, 
        output_dir,
        args3,  // args placeholder
        pbar,
        PacketProcessorType::HEADER,  // Example of using HEADER processing
        ImageType::FlowImageTiledAuto,  // Example: pass nullptr for NetworkTrafficImage
        3,  // min_image_dim
        2000,  // max_image_dim
        2,  // min_packets_per_flow
        100,  // max_packets_per_flow
        false  // remove_duplicates
    );
    
    // std::cout << "Process completed." << std::endl;
    return 0;
}
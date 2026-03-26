#include <iostream>
#include <variant>
#include <string>
#include <getopt.h>

#include "extractor.hpp"
#include "runner.hpp"

/// @brief Prints usage/help information for the CLI tool.
void print_usage(const char* progName) {
    std::cout << "Usage: " << progName << " [options]\n"
              << "  -i, --input FILE           input pcap file path\n"
              << "  -o, --output DIR           output directory\n"
              << "  -t, --threads N            number of threads (default 1)\n"
              << "  -p, --processor TYPE       preprocessing type: NONE or HEADER\n"
              << "  -m, --mode MODE            image type: FlowImage, FlowImageTiledFixed, FlowImageTiledAuto,\n"
              << "                             MarkovTransitionMatrixFlow, MarkovTransitionMatrixPacket, PacketImage\n"
              << "  --dim N                    image dimension\n"
              << "  --fill N                   fill value for missing data\n"
              << "  --cols N                   number of columns (used in some modes)\n"
              << "  --auto-dim                 enable auto-dimension (FlowImageTiledAuto, etc.)\n"
              << "  --append                   append mode for FlowImage\n"
              << "  --min-dim N                minimum image dimension\n"
              << "  --max-dim N                maximum image dimension\n"
              << "  --min-pkts N               minimum packets per flow\n"
              << "  --max-pkts N               maximum packets per flow\n"
              << "  --remove-dup               remove duplicate packets/flows\n"
              << "  --name                     name of processed image\n "
              << "  -h, --help                 display this help and exit\n";
}

int main(int argc, char* argv[]) {
    // CLI parameter variables
    std::string input_file;
    std::string output_dir;
    int thread_count = 1;
    PacketProcessorType proc_type = PacketProcessorType::NONE;
    ImageType img_type = ImageType::PacketImage;

    // Optional parameters with defaults
    std::string image_name = "heiFIPGeneratedImage";
    size_t dim = 0, fill = 0, cols = 0;
    bool auto_dim = false, append = false;
    size_t min_dim = 0, max_dim = 0;
    size_t min_pkts = 0, max_pkts = 0;
    bool remove_dup = false;

    // Long options for getopt
    static struct option long_opts[] = {
        {"name",        required_argument, 0,  0 },
        {"input",       required_argument, 0, 'i'},
        {"output",      required_argument, 0, 'o'},
        {"threads",     required_argument, 0, 't'},
        {"processor",   required_argument, 0, 'p'},
        {"mode",        required_argument, 0, 'm'},
        {"dim",         required_argument, 0,  0 },
        {"fill",        required_argument, 0,  0 },
        {"cols",        required_argument, 0,  0 },
        {"auto-dim",    no_argument,       0,  0 },
        {"append",      no_argument,       0,  0 },
        {"min-dim",     required_argument, 0,  0 },
        {"max-dim",     required_argument, 0,  0 },
        {"min-pkts",    required_argument, 0,  0 },
        {"max-pkts",    required_argument, 0,  0 },
        {"remove-dup",  no_argument,       0,  0 },
        {"help",        no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    // Parse command-line arguments
    int opt;
    int long_index = 0;
    while ((opt = getopt_long(argc, argv, "i:o:t:p:m:h", long_opts, &long_index)) != -1) {
        switch (opt) {
            case 'i': input_file = optarg; break;
            case 'o': output_dir = optarg; break;
            case 't': thread_count = std::stoi(optarg); break;
            case 'p':
                if (std::string(optarg) == "NONE") proc_type = PacketProcessorType::NONE;
                else if (std::string(optarg) == "HEADER") proc_type = PacketProcessorType::HEADER;
                else { std::cerr << "Unknown processor type\n"; return 1; }
                break;
            case 'm':
                if (std::string(optarg) == "PacketImage")               img_type = ImageType::PacketImage;
                else if (std::string(optarg) == "FlowImage")            img_type = ImageType::FlowImage;
                else if (std::string(optarg) == "FlowImageTiledFixed")  img_type = ImageType::FlowImageTiledFixed;
                else if (std::string(optarg) == "FlowImageTiledAuto")   img_type = ImageType::FlowImageTiledAuto;
                else if (std::string(optarg) == "MarkovFlow")           img_type = ImageType::MarkovTransitionMatrixFlow;
                else if (std::string(optarg) == "MarkovPacket")         img_type = ImageType::MarkovTransitionMatrixPacket;
                else { std::cerr << "Unknown mode\n"; return 1; }
                break;
            case 0:
                if (strcmp(long_opts[long_index].name, "dim") == 0)            dim = std::stoi(optarg);
                else if (strcmp(long_opts[long_index].name, "fill") == 0)      fill = std::stoi(optarg);
                else if (strcmp(long_opts[long_index].name, "cols") == 0)      cols = std::stoi(optarg);
                else if (strcmp(long_opts[long_index].name, "auto-dim") == 0)  auto_dim = true;
                else if (strcmp(long_opts[long_index].name, "append") == 0)    append = true;
                else if (strcmp(long_opts[long_index].name, "min-dim") == 0)   min_dim = std::stoi(optarg);
                else if (strcmp(long_opts[long_index].name, "max-dim") == 0)   max_dim = std::stoi(optarg);
                else if (strcmp(long_opts[long_index].name, "min-pkts") == 0)  min_pkts = std::stoi(optarg);
                else if (strcmp(long_opts[long_index].name, "max-pkts") == 0)  max_pkts = std::stoi(optarg);
                else if (strcmp(long_opts[long_index].name, "remove-dup") == 0) remove_dup = true;
                else if (strcmp(long_opts[long_index].name, "name") == 0) image_name = optarg;
                break;
            case 'h': print_usage(argv[0]); return 0;
            default:  print_usage(argv[0]); return 1;
        }
    }

    // Input and output are required
    if (input_file.empty() || output_dir.empty()) {
        print_usage(argv[0]);
        return 1;
    }

    Runner runner(thread_count);  // Create runner with specified thread count

    // Select argument type based on image type
    ImageArgsVariant args;
    switch (img_type) {
        case ImageType::FlowImage:
            args = FlowImageArgs{dim, append, fill};
            break;
        case ImageType::FlowImageTiledFixed:
            args = FlowImageTiledFixedArgs{dim, fill, cols};
            break;
        case ImageType::FlowImageTiledAuto:
            args = FlowImageTiledAutoArgs{dim, fill, auto_dim};
            break;
        case ImageType::MarkovTransitionMatrixFlow:
            args = MarkovTransitionMatrixFlowArgs{cols};
            break;
        case ImageType::MarkovTransitionMatrixPacket:
            args = MarkovTransitionMatrixPacketArgs{};
            break;
        case ImageType::PacketImage:
            args = PacketImageArgs{dim, auto_dim, fill};
            break;
    }

    // Main image generation call using the configured arguments
    runner.create_image(
        image_name,   // Output image name
        input_file,               // Input `.pcap` file
        output_dir,               // Output directory
        args,                     // Variant holding image arguments
        proc_type,                // Packet preprocessing strategy
        img_type,                 // Image generation mode
        min_dim,                  // Minimum image dimension
        max_dim,                  // Maximum image dimension
        min_pkts,                 // Minimum packets per flow
        max_pkts,                 // Maximum packets per flow
        remove_dup                // Whether to remove duplicate flows
    );

    return 0;
}
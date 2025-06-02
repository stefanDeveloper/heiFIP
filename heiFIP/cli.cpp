#include <iostream>
#include <vector>
#include <variant>
#include <string>
#include <cassert>
#include <thread>
#include <atomic>
#include <getopt.h>

#include "extractor.cpp"
#include "runner.cpp"

void print_usage(const char* progName) {
    std::cout << "Usage: " << progName << " [options]\n"
              << "  -i, --input FILE           input pcap file path\n"
              << "  -o, --output DIR           output directory\n"
              << "  -t, --threads N            number of threads (default 1)\n"
              << "  -p, --processor TYPE       preprocessing type: NONE or HEADER\n"
              << "  -m, --mode MODE            image type: FlowImage, FlowImageTiledFixed, FlowImageTiledAuto, MarkovTransitionMatrixFlow, MarkovTransitionMatrixPacket, PacketImage\n"
              << "  --dim N                    dimension (size_t)\n"
              << "  --fill N                   fill value (size_t)\n"
              << "  --cols N                   number of columns (size_t)\n"
              << "  --auto-dim                 auto-dimension flag (bool)\n"
              << "  --append                   append mode image (bool)\n"
              << "  --max-dim M                minimum dimension (size_t)\n"
              << "  --max-dim N                maximum dimension (size_t)\n"
              << "  --min-pkts N               minimum packets per flow (size_t)\n"
              << "  --max-pkts N               maximum packets per flow (size_t)\n"
              << "  --remove-dup               remove duplicate flows/packets\n"
              << "  -h, --help                 display this help and exit\n";
}

int main(int argc, char* argv[]) {
    std::string input_file;
    std::string output_dir;
    int thread_count = 1;
    PacketProcessorType proc_type = PacketProcessorType::NONE;
    ImageType img_type = ImageType::PacketImage;
    size_t dim = 0;
    size_t fill = 0;
    size_t cols = 0;
    bool auto_dim = false;
    bool append = false;
    size_t min_dim = 0;
    size_t max_dim = 0;
    size_t min_pkts = 0;
    size_t max_pkts = 0;
    bool remove_dup = false;

    static struct option long_opts[] = {
        {"input",       required_argument, 0, 'i'},
        {"output",      required_argument, 0, 'o'},
        {"threads",     required_argument, 0, 't'},
        {"processor",   required_argument, 0, 'p'},
        {"mode",        required_argument, 0, 'm'},
        {"dim",         required_argument, 0,  0 },
        {"fill",        required_argument, 0,  0 },
        {"cols",        required_argument, 0,  0 },
        {"auto-dim",    no_argument,       0,  0 },
        {"append",    no_argument,       0,  0 },
        {"min-dim",     required_argument, 0,  0 },
        {"max-dim",     required_argument, 0,  0 },
        {"min-pkts",    required_argument, 0,  0 },
        {"max-pkts",    required_argument, 0,  0 },
        {"remove-dup",  no_argument,       0,  0 },
        {"help",        no_argument,       0, 'h'},
        {0,0,0,0}
    };

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
                if (strcmp(long_opts[long_index].name, "dim") == 0)       dim       = std::stoi(optarg);
                else if (strcmp(long_opts[long_index].name, "fill") == 0)  fill      = std::stoi(optarg);
                else if (strcmp(long_opts[long_index].name, "cols") == 0)  cols      = std::stoi(optarg);
                else if (strcmp(long_opts[long_index].name, "auto-dim") == 0) auto_dim  = true;
                else if (strcmp(long_opts[long_index].name, "max-dim") == 0) max_dim   = std::stoi(optarg);
                else if (strcmp(long_opts[long_index].name, "min-pkts") == 0) min_pkts  = std::stoi(optarg);
                else if (strcmp(long_opts[long_index].name, "max-pkts") == 0) max_pkts  = std::stoi(optarg);
                else if (strcmp(long_opts[long_index].name, "remove-dup") == 0) remove_dup = true;
                break;
            case 'h': print_usage(argv[0]); return 0;
            default:  print_usage(argv[0]); return 1;
        }
    }

    if (input_file.empty() || output_dir.empty()) {
        print_usage(argv[0]);
        return 1;
    }

    std::atomic<int> pbar{0};
    Runner runner(thread_count);

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

    runner.create_image(
        "heiFIPGeneratedImage",
        input_file,
        output_dir,
        args,
        pbar,
        proc_type,
        img_type,
        dim,
        max_dim,
        min_pkts,
        max_pkts,
        remove_dup
    );

    std::cout << "Progress: " << pbar.load() << std::endl;
    return 0;
}

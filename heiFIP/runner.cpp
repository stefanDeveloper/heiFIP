#include <iostream>
#include <vector>
#include <variant>
#include <string>
#include <cassert>
#include <filesystem>
#include <thread>
#include <atomic>

#include "extractor.cpp"


class Runner {
private:
    int thread_number;
    FIPExtractor extractor;

    size_t getMatrixCount(const MatrixVariant& mv) {
        return std::visit([](auto const& mat) {
            return mat.size();
        }, mv);
    }

    // Function to return the element at index 'x' in the matrix
    std::optional<std::variant<std::vector<std::vector<uint8_t>>, std::vector<std::vector<double>>>>
    getVectorAtIndex(const MatrixVariant& matrix, size_t x) {
        if (auto u8 = std::get_if<UInt8Matrix>(&matrix)) {
            if (x < u8->size()) {
                return (*u8)[x];
            }
        } else if (auto dbl = std::get_if<DoubleMatrix>(&matrix)) {
            if (x < dbl->size()) {
                return (*dbl)[x];
            }
        }
        return std::nullopt;
    }

public:
    Runner(int thread_number) : thread_number(thread_number), extractor() {}

    void create_image(
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
        MatrixVariant img = extractor.createImageFromFile(
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
        extractor.save_image(img, output_dir + "/image_");
    }
};
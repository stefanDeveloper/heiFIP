#pragma once

#include <vector>
#include <cstdint>
#include <stdexcept>

/**
 * @file tile_utils.hpp
 * @brief Shared utility functions for tiling 2D image matrices into grids.
 *
 * Used by FlowImageTiledAuto, FlowImageTiledFixed, and MarkovTransitionMatrixFlow
 * to avoid code duplication.
 */
namespace tile_utils {

/**
 * @brief Create a dim×dim tile filled with zeros.
 * @param dim Dimension for both width and height.
 * @return 2D vector<uint8_t> of size [dim][dim], all elements = 0.
 */
inline std::vector<std::vector<uint8_t>> npzero(size_t dim) {
    return std::vector<std::vector<uint8_t>>(dim, std::vector<uint8_t>(dim, 0));
}

/**
 * @brief Horizontally concatenate two same-height images (2D arrays).
 * @param img1 First image: vector of rows.
 * @param img2 Second image: must have same number of rows as img1.
 * @return Concatenated image: each row is img1[row] followed by img2[row].
 * @throws std::invalid_argument if img1 and img2 have different heights.
 */
inline std::vector<std::vector<uint8_t>> npconcatenate(
    const std::vector<std::vector<uint8_t>>& img1,
    const std::vector<std::vector<uint8_t>>& img2)
{
    if (img1.empty()) return img2;
    if (img2.empty()) return img1;

    if (img1.size() != img2.size()) {
        throw std::invalid_argument(
            "Images must have the same number of rows to concatenate horizontally.");
    }

    std::vector<std::vector<uint8_t>> result = img1;
    for (size_t i = 0; i < result.size(); ++i) {
        result[i].insert(result[i].end(), img2[i].begin(), img2[i].end());
    }
    return result;
}

/**
 * @brief Arrange a list of tiles into a single large square image.
 * @param images 3D vector: [numTiles][dim][dim], each is a dim×dim tile.
 * @param cols   Number of tiles per row/column in the final grid.
 * @param dim    Dimension of each tile (width = height = dim).
 * @return 2D vector<uint8_t> of size [cols*dim][cols*dim], the tiled image.
 */
inline std::vector<std::vector<uint8_t>> tile_images(
    const std::vector<std::vector<std::vector<uint8_t>>>& images,
    unsigned int cols, unsigned int dim)
{
    std::vector<std::vector<std::vector<uint8_t>>> rows;
    size_t k = 0;

    for (size_t i = 0; i < cols; ++i) {
        std::vector<std::vector<uint8_t>> row;
        for (size_t j = 0; j < cols; ++j) {
            std::vector<std::vector<uint8_t>> im;
            if (k < images.size()) {
                im = images[k];
            } else {
                im = npzero(dim);
            }

            if (row.empty()) {
                row = std::move(im);
            } else {
                row = npconcatenate(row, im);
            }
            ++k;
        }
        rows.push_back(std::move(row));
    }

    std::vector<std::vector<uint8_t>> tiled = std::move(rows[0]);
    for (size_t i = 1; i < rows.size(); ++i) {
        tiled.insert(tiled.end(), rows[i].begin(), rows[i].end());
    }
    return tiled;
}

} // namespace tile_utils

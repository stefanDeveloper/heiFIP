#pragma once

/**
 * @class NetworkTrafficImage
 * @brief Base class for all traffic‐based image generators.
 *
 * Responsibilities:
 *   - Store common image parameters: a fill value and a base dimension.
 *   - Provide a common interface (via inheritance) for more specialized traffic image classes
 *     (e.g., FlowImage, MarkovTransitionMatrixFlow) to share these parameters.
 *
 * Members:
 *   _fill : Byte value (0–255) used to pad empty pixels when constructing images.
 *   _dim  : Base dimension (e.g., tile size) used by derived classes as a starting value.
 *
 * Why:
 *   - Derived classes may need a default padding value and dimension for their image‐construction logic.
 *   - By centralizing these fields here, all traffic‐image types can uniformly receive and store them.
 */
class NetworkTrafficImage {
private:
    int _fill;  ///< Value to pad empty or unused pixels when building images
    int _dim;   ///< Base dimension (e.g., tile width/height) for derived‐class image logic

public:
    /**
     * @brief Constructor: initialize default fill value and dimension.
     *
     * @param fill  Byte value used for padding (default = 0).
     * @param dim   Base dimension (default = 8). Derived classes may override or use this.
     *
     * Workflow:
     *   1. Store `fill` in _fill.
     *   2. Store `dim` in _dim.
     *   3. Derived classes inherit these settings for use in their image‐building routines.
     */
    NetworkTrafficImage(int fill = 0, int dim = 8)
        : _fill(fill), _dim(dim)
    {}
};
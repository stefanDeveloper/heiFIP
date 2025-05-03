#pragma once

class NetworkTrafficImage {
    private:
        int _fill;
        int _dim;
    
    public:
        NetworkTrafficImage(int fill = 0, int dim = 8) : _fill(fill), _dim(dim) {};
};
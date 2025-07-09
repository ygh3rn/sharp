#pragma once

#include <mcl/bn.hpp>
#include <vector>

using namespace mcl;
using namespace std;

class NTT {
public:
    // Forward NTT transform
    static vector<Fr> transform(const vector<Fr>& a, const Fr& root, size_t n);
    
    // Inverse NTT transform
    static vector<Fr> inverse_transform(const vector<Fr>& a, const Fr& root, size_t n);
    
    // Find primitive nth root of unity
    static Fr find_primitive_root(size_t n);
    
    // Check if n is power of 2
    static bool is_power_of_2(size_t n);
    
    // Bit reverse permutation for NTT
    static void bit_reverse(vector<Fr>& a);

private:
    // Compute modular inverse
    static Fr mod_inverse(const Fr& a);
    
    // Bit reverse of integer
    static size_t bit_reverse(size_t x, size_t bits);
};
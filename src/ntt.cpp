#include "ntt.h"
#include <stdexcept>
#include <algorithm>
#include <cmath>

vector<Fr> NTT::transform(const vector<Fr>& a, const Fr& root, size_t n) {
    if (!is_power_of_2(n)) {
        throw invalid_argument("NTT size must be power of 2");
    }
    
    vector<Fr> result = a;
    result.resize(n, Fr(0));
    
    // Bit-reversal permutation
    bit_reverse(result);
    
    // Cooley-Tukey NTT
    for (size_t len = 2; len <= n; len <<= 1) {
        Fr wlen;
        Fr exponent = Fr(n / len);
        Fr::pow(wlen, root, exponent);
        
        for (size_t i = 0; i < n; i += len) {
            Fr w = Fr(1);
            
            for (size_t j = 0; j < len / 2; j++) {
                Fr u = result[i + j];
                Fr v;
                Fr::mul(v, result[i + j + len / 2], w);
                
                Fr::add(result[i + j], u, v);
                Fr::sub(result[i + j + len / 2], u, v);
                Fr::mul(w, w, wlen);
            }
        }
    }
    
    return result;
}

vector<Fr> NTT::inverse_transform(const vector<Fr>& a, const Fr& root, size_t n) {
    Fr inv_root = mod_inverse(root);
    vector<Fr> result = transform(a, inv_root, n);
    
    Fr inv_n = mod_inverse(Fr(n));
    for (auto& x : result) {
        Fr::mul(x, x, inv_n);
    }
    
    return result;
}

Fr NTT::find_primitive_root(size_t n) {
    if (!is_power_of_2(n)) {
        throw invalid_argument("n must be power of 2");
    }
    if (n == 1) {
        return Fr(1);
    }
    
    // For BN curves, we use -1 as starting point and take repeated square roots
    Fr root = Fr(-1);
    size_t current_order = 2;
    
    while (current_order < n) {
        Fr::squareRoot(root, root);
        current_order *= 2;
    }
    
    return root;
}

bool NTT::is_power_of_2(size_t n) {
    return n > 0 && (n & (n - 1)) == 0;
}

void NTT::bit_reverse(vector<Fr>& a) {
    size_t n = a.size();
    if (!is_power_of_2(n)) return;
    
    size_t bits = 0;
    size_t temp = n;
    while (temp > 1) {
        temp >>= 1;
        bits++;
    }
    
    for (size_t i = 0; i < n; i++) {
        size_t j = bit_reverse(i, bits);
        if (i < j) {
            swap(a[i], a[j]);
        }
    }
}

Fr NTT::mod_inverse(const Fr& a) {
    Fr result;
    Fr::inv(result, a);
    return result;
}

size_t NTT::bit_reverse(size_t x, size_t bits) {
    size_t result = 0;
    for (size_t i = 0; i < bits; i++) {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    return result;
}
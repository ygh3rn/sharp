#pragma once

#include <mcl/bn.hpp>
#include <vector>
#include <random>

using namespace mcl;
using namespace std;

class Utils {
public:
    // Random number generation
    static Fr random_fr();
    static vector<Fr> random_fr_vector(size_t size);
    static G1 random_g1();
    
    // Masking for zero-knowledge
    static Fr mask_value(const Fr& value, const Fr& mask);
    static bool rejection_sampling(const Fr& masked_value, const Fr& bound);
    
    // Hash function (simplified)
    static Fr hash_to_fr(const vector<uint8_t>& data);
    static Fr hash_transcript(const vector<G1>& commitments, const vector<Fr>& challenges);
    
    // Serialization helpers
    static vector<uint8_t> serialize_g1(const G1& point);
    static vector<uint8_t> serialize_fr(const Fr& element);
    static G1 deserialize_g1(const vector<uint8_t>& data);
    static Fr deserialize_fr(const vector<uint8_t>& data);
    
    // Range checking
    static bool in_range(const Fr& value, const Fr& min_val, const Fr& max_val);
    
    // Convert to/from integers
    static Fr from_int(uint64_t value);
    static uint64_t to_int(const Fr& value);
    
    // Print helpers for debugging
    static void print_fr(const Fr& x, const string& label = "");
    static void print_g1(const G1& p, const string& label = "");
    
    // Get random number generator
    static mt19937& get_rng();

private:
    static mt19937 rng;
};
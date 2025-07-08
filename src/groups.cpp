#include "groups.h"
#include "utils.h"
#include <stdexcept>
#include <iostream>
#include <cmath>
#include <sstream>

namespace sharp_gs {

GroupManager::GroupParams::GroupParams(size_t batch_size) 
    : max_batch_size(batch_size) {
    // Reserve space for generators
    // G0 (randomness), G1...GN (values), G1,1...GN,3 (decomposition)
    size_t total_generators = 1 + batch_size + batch_size * 3;
    generators.reserve(total_generators);
}

GroupManager::GroupManager() : initialized_(false) {
    // Initialize MCL pairing
    mcl::initPairing(mcl::BN_SNARK1);
}

bool GroupManager::initialize(size_t security_bits, 
                             size_t range_bits, 
                             size_t max_batch_size,
                             size_t challenge_bits) {
    try {
        // Compute required group sizes based on SharpGS security requirements
        auto [p_bits, q_bits] = utils::params::compute_group_sizes(security_bits, range_bits, challenge_bits, max_batch_size);
        
        std::cout << "Initializing groups with:" << std::endl;
        std::cout << "  Gcom (p): " << p_bits << " bits" << std::endl;
        std::cout << "  G3sq (q): " << q_bits << " bits" << std::endl;
        std::cout << "  Batch size: " << max_batch_size << std::endl;

        // Initialize group parameters
        gcom_params_ = GroupParams(max_batch_size);
        g3sq_params_ = GroupParams(max_batch_size);

        // Set group orders (for SharpGS we use the same curve but conceptually different moduli)
        gcom_params_.modulus = compute_group_order(p_bits);
        g3sq_params_.modulus = compute_group_order(q_bits);

        // Generate generators for both groups
        setup_gcom_generators(max_batch_size);
        setup_g3sq_generators(max_batch_size);

        initialized_ = true;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Group initialization failed: " << e.what() << std::endl;
        return false;
    }
}

void GroupManager::setup_gcom_generators(size_t batch_size) {
    // Generate generators for Gcom group
    // G0 for randomness, G1...GN for values
    gcom_params_.generators.clear();
    gcom_params_.generators.reserve(1 + batch_size);
    
    for (size_t i = 0; i <= batch_size; ++i) {
        G1 generator;
        // FIX: Use proper MCL random generation method
        std::string seed = "generator_gcom_" + std::to_string(i);
        generator.setHashOf(seed.c_str(), seed.length());
        gcom_params_.generators.push_back(generator);
    }
}

void GroupManager::setup_g3sq_generators(size_t batch_size) {
    // Generate generators for G3sq group  
    // For three-square decomposition: G1,1...GN,3 (3 generators per value)
    g3sq_params_.generators.clear();
    g3sq_params_.generators.reserve(1 + batch_size * 3);
    
    // Randomness generator
    G1 g0;
    std::string seed0 = "generator_g3sq_0";
    g0.setHashOf(seed0.c_str(), seed0.length());
    g3sq_params_.generators.push_back(g0);
    
    // Decomposition generators (3 per value)
    for (size_t i = 0; i < batch_size * 3; ++i) {
        G1 generator;
        std::string seed = "generator_g3sq_" + std::to_string(i + 1);
        generator.setHashOf(seed.c_str(), seed.length());
        g3sq_params_.generators.push_back(generator);
    }
}

Fr GroupManager::compute_group_order(size_t required_bits) const {
    // For MCL BN curves, we use the field order
    // This is a placeholder - real implementation would use proper order computation
    Fr order;
    order.setByCSPRNG(); // Generate a random element as placeholder
    return order;
}

Fr GroupManager::random_scalar(bool use_g3sq) const {
    // Generate random scalar in appropriate field
    Fr scalar;
    scalar.setByCSPRNG();
    return scalar;
}

G1 GroupManager::get_generator(size_t index, bool use_g3sq) const {
    const auto& generators = use_g3sq ? g3sq_params_.generators : gcom_params_.generators;
    
    if (index >= generators.size()) {
        throw std::out_of_range("Generator index out of range");
    }
    
    return generators[index];
}

// Group utility functions implementation
namespace group_utils {

G1 multi_scalar_mult(const std::vector<Fr>& scalars, const std::vector<G1>& points) {
    if (scalars.size() != points.size() || scalars.empty()) {
        throw std::invalid_argument("Scalar and point vectors must have same non-zero size");
    }
    
    G1 result;
    result.clear(); // Initialize to zero
    
    // FIX: Manual implementation to avoid const issues with MCL's mulVec
    for (size_t i = 0; i < scalars.size(); ++i) {
        G1 temp;
        G1::mul(temp, points[i], scalars[i]);
        G1::add(result, result, temp);
    }
    
    return result;
}

bool is_scalar_bounded(const Fr& scalar, const Fr& bound) {
    // Compare scalar with bound
    // This is a simplified implementation - real version needs proper comparison
    return !scalar.isZero() && field_less_than(scalar, bound);
}

Fr int_to_field(int64_t value) {
    Fr result;
    
    // FIX: Use proper MCL API for setting integer values
    if (value >= 0) {
        std::string str_val = std::to_string(static_cast<uint64_t>(value));
        result.setStr(str_val, 10);
    } else {
        // Handle negative values
        std::string str_val = std::to_string(static_cast<uint64_t>(-value));
        result.setStr(str_val, 10);
        Fr::neg(result, result);
    }
    
    return result;
}

int64_t field_to_int(const Fr& element) {
    // Convert field element to integer (for small values)
    // This is simplified - real implementation needs proper conversion
    std::string str = element.getStr(10);
    try {
        return std::stoll(str);
    } catch (...) {
        return 0; // Return 0 if conversion fails
    }
}

Fr secure_random() {
    Fr result;
    result.setByCSPRNG(); // FIX: Use proper MCL random generation
    return result;
}

bool is_small_integer(const Fr& element, int64_t max_value) {
    // Check if field element represents a small integer
    try {
        int64_t value = field_to_int(element);
        return value >= 0 && value <= max_value;
    } catch (...) {
        return false;
    }
}

bool field_less_than(const Fr& a, const Fr& b) {
    // Field comparison - simplified implementation
    // Real implementation needs proper field arithmetic comparison
    std::string a_str = a.getStr(10);
    std::string b_str = b.getStr(10);
    
    // Simple string-based comparison for same-length strings
    if (a_str.length() != b_str.length()) {
        return a_str.length() < b_str.length();
    }
    
    return a_str < b_str;
}

} // namespace group_utils

} // namespace sharp_gs
#include "groups.h"
#include "utils.h"
#include <stdexcept>
#include <iostream>
#include <cmath>

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
        auto [p_bits, q_bits] = compute_group_sizes(security_bits, range_bits, challenge_bits);
        
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

std::pair<size_t, size_t> GroupManager::compute_group_sizes(
    size_t security_bits, 
    size_t range_bits, 
    size_t challenge_bits,
    size_t masking_overhead) {
    
    // SharpGS requirements from the paper:
    // For Gcom: p ≥ 2(BΓ² + 1)L  
    // For G3sq: q ≥ 18((BΓ + 1)L)²

    size_t B = 1ULL << range_bits;           // Range bound
    size_t Gamma = 1ULL << challenge_bits;   // Challenge space size
    size_t L = 1ULL << masking_overhead;     // Masking overhead

    // Compute minimum bits for Gcom  
    size_t gcom_min = 2 * (B * Gamma * Gamma + 1) * L;
    size_t p_bits = std::max(256UL, static_cast<size_t>(std::log2(gcom_min)) + security_bits);

    // Compute minimum bits for G3sq
    size_t K = (B * Gamma + 1) * L;
    size_t g3sq_min = 18 * K * K;
    size_t q_bits = std::max(256UL, static_cast<size_t>(std::log2(g3sq_min)) + security_bits);

    return {p_bits, q_bits};
}

void GroupManager::setup_gcom_generators(size_t batch_size) {
    gcom_params_.generators.clear();
    
    // Generate G0 for randomness
    G1 G0;
    hashAndMapToG1(G0, "SharpGS_Gcom_G0", 16);
    gcom_params_.generators.push_back(G0);

    // Generate G1, ..., GN for values
    for (size_t i = 1; i <= batch_size; ++i) {
        G1 Gi;
        std::string label = "SharpGS_Gcom_G" + std::to_string(i);
        hashAndMapToG1(Gi, label.c_str(), label.length());
        gcom_params_.generators.push_back(Gi);
    }

    // Generate Gi,j for decomposition values (i=1..N, j=1..3)
    for (size_t i = 1; i <= batch_size; ++i) {
        for (size_t j = 1; j <= 3; ++j) {
            G1 Gij;
            std::string label = "SharpGS_Gcom_G" + std::to_string(i) + "_" + std::to_string(j);
            hashAndMapToG1(Gij, label.c_str(), label.length());
            gcom_params_.generators.push_back(Gij);
        }
    }

    std::cout << "Generated " << gcom_params_.generators.size() << " generators for Gcom" << std::endl;
}

void GroupManager::setup_g3sq_generators(size_t batch_size) {
    g3sq_params_.generators.clear();
    
    // Generate H0 for randomness
    G1 H0;
    hashAndMapToG1(H0, "SharpGS_G3sq_H0", 16);
    g3sq_params_.generators.push_back(H0);

    // Generate H1, ..., HN for polynomial coefficients
    for (size_t i = 1; i <= batch_size; ++i) {
        G1 Hi;
        std::string label = "SharpGS_G3sq_H" + std::to_string(i);
        hashAndMapToG1(Hi, label.c_str(), label.length());
        g3sq_params_.generators.push_back(Hi);
    }

    std::cout << "Generated " << g3sq_params_.generators.size() << " generators for G3sq" << std::endl;
}

Fr GroupManager::compute_group_order(size_t required_bits) const {
    // For BN curves, we use the curve order
    // In practice, this would be set based on the specific curve parameters
    Fr order;
    order.setStr("21888242871839275222246405745257275088548364400416034343698204186575808495617");
    return order;
}

Fr GroupManager::random_scalar(bool use_g3sq) const {
    if (!initialized_) {
        throw std::runtime_error("GroupManager not initialized");
    }
    
    Fr result;
    result.setByCSPRNG();
    return result;
}

namespace group_utils {

G1 multi_scalar_mult(const std::vector<Fr>& scalars, const std::vector<G1>& points) {
    if (scalars.size() != points.size()) {
        throw std::invalid_argument("Scalar and point vectors must have same size");
    }
    
    if (scalars.empty()) {
        G1 result;
        result.clear();
        return result;
    }

    // Use MCL's efficient multi-scalar multiplication
    G1 result;
    G1::mulVec(result, points.data(), scalars.data(), scalars.size());
    return result;
}

bool is_scalar_bounded(const Fr& scalar, const Fr& bound) {
    // Convert to integers for comparison (assuming small values)
    try {
        std::string scalar_str = scalar.getStr();
        std::string bound_str = bound.getStr();
        
        // Simple string comparison for now - could be optimized
        return scalar_str.length() <= bound_str.length();
    } catch (...) {
        return false;
    }
}

Fr int_to_field(int64_t value) {
    if (value < 0) {
        throw std::invalid_argument("Negative values not supported");
    }
    
    Fr result;
    result.setInt(static_cast<uint64_t>(value));
    return result;
}

int64_t field_to_int(const Fr& element) {
    std::string str = element.getStr();
    try {
        return std::stoll(str);
    } catch (...) {
        throw std::invalid_argument("Field element too large to convert to int64");
    }
}

Fr secure_random() {
    Fr result;
    result.setByCSPRNG();
    return result;
}

bool is_small_integer(const Fr& element, int64_t max_value) {
    try {
        int64_t value = field_to_int(element);
        return value >= 0 && value <= max_value;
    } catch (...) {
        return false;
    }
}

} // namespace group_utils

} // namespace sharp_gs
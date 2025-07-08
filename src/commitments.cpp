#include "commitments.h"
#include "utils.h"
#include <stdexcept>
#include <algorithm>

namespace sharp_gs {

// Commitment operations
PedersenMultiCommit::Commitment PedersenMultiCommit::Commitment::operator+(const Commitment& other) const {
    G1 result;
    G1::add(result, this->value, other.value);
    return Commitment(result);
}

PedersenMultiCommit::Commitment PedersenMultiCommit::Commitment::operator*(const Fr& scalar) const {
    G1 result;
    G1::mul(result, this->value, scalar);
    return Commitment(result);
}

bool PedersenMultiCommit::Commitment::operator==(const Commitment& other) const {
    return this->value == other.value;
}

bool PedersenMultiCommit::Commitment::operator!=(const Commitment& other) const {
    return !(*this == other);
}

// PedersenMultiCommit implementation
PedersenMultiCommit::PedersenMultiCommit(const GroupManager& groups, bool use_g3sq) 
    : is_g3sq_group_(use_g3sq) {
    
    if (use_g3sq) {
        params_ = &groups.get_g3sq_params();
    } else {
        params_ = &groups.get_gcom_params();
    }
    
    if (!groups.is_initialized()) {
        throw std::runtime_error("GroupManager not initialized");
    }
}

std::pair<PedersenMultiCommit::Commitment, PedersenMultiCommit::Opening> 
PedersenMultiCommit::commit(const std::vector<Fr>& values, const Fr& randomness) const {
    
    if (values.empty()) {
        throw std::invalid_argument("Cannot commit to empty vector");
    }
    
    if (values.size() > max_vector_size()) {
        throw std::invalid_argument("Vector size exceeds maximum supported size");
    }
    
    // Generate randomness if not provided
    Fr r = randomness;
    if (randomness.isZero()) {
        r = group_utils::secure_random();
    }
    
    // Get appropriate generators
    auto generators = get_generators_for_size(values.size());
    
    // Compute commitment: C = r*G0 + Σ xi*Gi
    std::vector<Fr> scalars;
    scalars.reserve(values.size() + 1);
    
    // Add randomness term
    scalars.push_back(r);
    
    // Add value terms
    scalars.insert(scalars.end(), values.begin(), values.end());
    
    // Compute multi-scalar multiplication
    G1 commitment_value = group_utils::multi_scalar_mult(scalars, generators);
    
    return {Commitment(commitment_value), Opening(values, r)};
}

std::pair<PedersenMultiCommit::Commitment, PedersenMultiCommit::Opening>
PedersenMultiCommit::commit_single(const Fr& value, const Fr& randomness) const {
    return commit({value}, randomness);
}

bool PedersenMultiCommit::verify(const Commitment& commitment, const Opening& opening) const {
    try {
        // Recompute commitment and compare
        auto recomputed = recompute_commitment(opening);
        return commitment == recomputed;
    } catch (...) {
        return false;
    }
}

PedersenMultiCommit::Commitment 
PedersenMultiCommit::recompute_commitment(const Opening& opening) const {
    
    if (opening.values.empty()) {
        throw std::invalid_argument("Opening has no values");
    }
    
    // Get generators for this vector size
    auto generators = get_generators_for_size(opening.values.size());
    
    // Prepare scalars: [randomness, value1, value2, ...]
    std::vector<Fr> scalars;
    scalars.reserve(opening.values.size() + 1);
    scalars.push_back(opening.randomness);
    scalars.insert(scalars.end(), opening.values.begin(), opening.values.end());
    
    // Compute commitment
    G1 result = group_utils::multi_scalar_mult(scalars, generators);
    return Commitment(result);
}

size_t PedersenMultiCommit::max_vector_size() const {
    // Maximum is determined by number of available generators
    // We need G0 (randomness) + Gi for each value
    return params_->generators.size() > 0 ? params_->generators.size() - 1 : 0;
}

std::pair<PedersenMultiCommit::Commitment, PedersenMultiCommit::Opening>
PedersenMultiCommit::commit_indexed(
    const std::vector<std::vector<Fr>>& value_matrix,
    const Fr& randomness) const {
    
    // This is used for committing to decomposition values yi,j
    // where value_matrix[i][j] represents yi,j for value i, decomposition component j
    
    if (value_matrix.empty()) {
        throw std::invalid_argument("Value matrix cannot be empty");
    }
    
    size_t batch_size = value_matrix.size();
    size_t decomp_size = value_matrix[0].size();
    
    // Validate matrix dimensions
    for (const auto& row : value_matrix) {
        if (row.size() != decomp_size) {
            throw std::invalid_argument("Inconsistent matrix dimensions");
        }
    }
    
    // Generate randomness if needed
    Fr r = randomness;
    if (randomness.isZero()) {
        r = group_utils::secure_random();
    }
    
    // For SharpGS decomposition: need generators G0, Gi,j where i ∈ [1,N], j ∈ [1,3]
    std::vector<Fr> scalars;
    std::vector<G1> generators;
    
    // Add randomness term
    scalars.push_back(r);
    generators.push_back(params_->generators[0]); // G0
    
    // Add indexed terms: yi,j with generator Gi,j
    for (size_t i = 0; i < batch_size; ++i) {
        for (size_t j = 0; j < decomp_size; ++j) {
            scalars.push_back(value_matrix[i][j]);
            
            // Calculate generator index: 1 + N + i*3 + j
            // Layout: G0, G1...GN, G1,1, G1,2, G1,3, G2,1, G2,2, G2,3, ...
            size_t gen_index = 1 + batch_size + i * decomp_size + j;
            if (gen_index >= params_->generators.size()) {
                throw std::out_of_range("Generator index out of range");
            }
            generators.push_back(params_->generators[gen_index]);
        }
    }
    
    // Compute commitment
    G1 commitment_value = group_utils::multi_scalar_mult(scalars, generators);
    
    // Flatten matrix for opening
    std::vector<Fr> flat_values;
    for (const auto& row : value_matrix) {
        flat_values.insert(flat_values.end(), row.begin(), row.end());
    }
    
    return {Commitment(commitment_value), Opening(flat_values, r)};
}

std::vector<G1> PedersenMultiCommit::get_generators_for_size(size_t vector_size) const {
    if (vector_size == 0) {
        throw std::invalid_argument("Vector size must be positive");
    }
    
    // Need G0 + G1...Gn generators
    size_t required_generators = vector_size + 1;
    if (required_generators > params_->generators.size()) {
        throw std::invalid_argument("Not enough generators for requested vector size");
    }
    
    std::vector<G1> result;
    result.reserve(required_generators);
    
    // Copy required generators
    for (size_t i = 0; i < required_generators; ++i) {
        result.push_back(params_->generators[i]);
    }
    
    return result;
}

// Commitment utility functions
namespace commit_utils {

PedersenMultiCommit::Commitment combine_commitments(
    const std::vector<Fr>& coefficients,
    const std::vector<PedersenMultiCommit::Commitment>& commitments) {
    
    if (coefficients.size() != commitments.size()) {
        throw std::invalid_argument("Coefficient and commitment vectors must have same size");
    }
    
    if (commitments.empty()) {
        G1 zero;
        zero.clear();
        return PedersenMultiCommit::Commitment(zero);
    }
    
    // Compute Σ coeffs[i] * commitments[i]
    std::vector<G1> points;
    points.reserve(commitments.size());
    
    for (const auto& commitment : commitments) {
        points.push_back(commitment.value);
    }
    
    G1 result = group_utils::multi_scalar_mult(coefficients, points);
    return PedersenMultiCommit::Commitment(result);
}

PedersenMultiCommit::Commitment add_commitments(
    const PedersenMultiCommit::Commitment& c1,
    const PedersenMultiCommit::Commitment& c2) {
    
    return c1 + c2;
}

PedersenMultiCommit::Commitment subtract_commitments(
    const PedersenMultiCommit::Commitment& c1,
    const PedersenMultiCommit::Commitment& c2) {
    
    G1 result;
    G1::sub(result, c1.value, c2.value);
    return PedersenMultiCommit::Commitment(result);
}

PedersenMultiCommit::Commitment scale_commitment(
    const Fr& scalar,
    const PedersenMultiCommit::Commitment& commitment) {
    
    return commitment * scalar;
}

bool is_identity_commitment(const PedersenMultiCommit::Commitment& commitment) {
    return commitment.value.isZero();
}

} // namespace commit_utils

} // namespace sharp_gs
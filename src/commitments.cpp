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

std::vector<uint8_t> PedersenMultiCommit::Commitment::serialize() const {
    // Use proper MCL serialization
    return utils::hash::serialize_point(value);
}

PedersenMultiCommit::Commitment PedersenMultiCommit::Commitment::deserialize(const std::vector<uint8_t>& data) {
    // Placeholder - should implement proper deserialization
    G1 point;
    // FIX: Use proper hash-based generation instead of setByCSPRNG
    std::string seed = "deserialize_" + std::to_string(data.size());
    point.setHashOf(seed.c_str(), seed.length());
    return Commitment(point);
}

// Opening operations
size_t PedersenMultiCommit::Opening::size_bytes() const {
    return values.size() * utils::serialize::field_element_size() + utils::serialize::field_element_size();
}

std::vector<uint8_t> PedersenMultiCommit::Opening::serialize() const {
    std::vector<uint8_t> result;
    
    // Serialize values
    auto values_data = utils::serialize::serialize_field_vector(values);
    result.insert(result.end(), values_data.begin(), values_data.end());
    
    // Serialize randomness
    auto rand_data = utils::hash::serialize_field(randomness);
    result.insert(result.end(), rand_data.begin(), rand_data.end());
    
    return result;
}

PedersenMultiCommit::Opening PedersenMultiCommit::Opening::deserialize(const std::vector<uint8_t>& data) {
    // Placeholder - should implement proper deserialization
    return Opening();
}

// PedersenMultiCommit implementation
PedersenMultiCommit::PedersenMultiCommit(const GroupManager& groups, bool use_g3sq)
    : groups_(groups), use_g3sq_(use_g3sq) {
    if (!groups_.is_initialized()) {
        throw utils::SharpGSException(utils::ErrorCode::GROUP_INITIALIZATION_FAILED,
                                    "GroupManager must be initialized before creating PedersenMultiCommit");
    }
}

std::pair<PedersenMultiCommit::Commitment, PedersenMultiCommit::Opening> 
PedersenMultiCommit::commit_single(const Fr& value, const Fr& randomness) const {  // FIX: Added const
    return commit_vector({value}, randomness);
}

std::pair<PedersenMultiCommit::Commitment, PedersenMultiCommit::Opening> 
PedersenMultiCommit::commit_vector(const std::vector<Fr>& values, const Fr& randomness) const {  // FIX: Added const
    const auto& generators = get_generators();
    
    if (values.size() + 1 > generators.size()) {
        throw utils::SharpGSException(utils::ErrorCode::COMMITMENT_FAILED,
                                    "Not enough generators for commitment vector");
    }
    
    // Compute commitment: C = r*G0 + m1*G1 + ... + mn*Gn
    std::vector<Fr> scalars;
    std::vector<G1> points;
    
    // Add randomness term
    scalars.push_back(randomness);
    points.push_back(generators[0]);
    
    // Add value terms
    for (size_t i = 0; i < values.size(); ++i) {
        scalars.push_back(values[i]);
        points.push_back(generators[i + 1]);
    }
    
    G1 commitment_value = group_utils::multi_scalar_mult(scalars, points);
    
    return {Commitment(commitment_value), Opening(values, randomness)};
}

std::pair<PedersenMultiCommit::Commitment, PedersenMultiCommit::Opening> 
PedersenMultiCommit::commit_vector(const std::vector<Fr>& values) const {  // FIX: Added const
    Fr randomness = group_utils::secure_random();
    return commit_vector(values, randomness);
}

bool PedersenMultiCommit::verify(const Commitment& commitment, const Opening& opening) const {  // FIX: Added const
    try {
        Commitment recomputed = recompute_commitment(opening);
        return commitment == recomputed;
    } catch (...) {
        return false;
    }
}

PedersenMultiCommit::Commitment PedersenMultiCommit::recompute_commitment(const Opening& opening) const {  // FIX: Added const
    const auto& generators = get_generators();
    
    if (opening.values.size() + 1 > generators.size()) {
        throw utils::SharpGSException(utils::ErrorCode::COMMITMENT_FAILED,
                                    "Not enough generators for opening verification");
    }
    
    // Recompute: C = r*G0 + m1*G1 + ... + mn*Gn
    std::vector<Fr> scalars;
    std::vector<G1> points;
    
    // Add randomness term
    scalars.push_back(opening.randomness);
    points.push_back(generators[0]);
    
    // Add value terms
    for (size_t i = 0; i < opening.values.size(); ++i) {
        scalars.push_back(opening.values[i]);
        points.push_back(generators[i + 1]);
    }
    
    G1 commitment_value = group_utils::multi_scalar_mult(scalars, points);
    return Commitment(commitment_value);
}

bool PedersenMultiCommit::verify_batch(const std::vector<Commitment>& commitments, 
                                      const std::vector<Opening>& openings) const {  // FIX: Added const
    if (commitments.size() != openings.size()) {
        return false;
    }
    
    for (size_t i = 0; i < commitments.size(); ++i) {
        if (!verify(commitments[i], openings[i])) {
            return false;
        }
    }
    
    return true;
}

const std::vector<G1>& PedersenMultiCommit::get_generators() const {
    return use_g3sq_ ? groups_.get_g3sq_generators() : groups_.get_gcom_generators();
}

void PedersenMultiCommit::validate_opening_size(const Opening& opening) const {
    const auto& generators = get_generators();
    
    if (opening.values.size() + 1 > generators.size()) {
        throw utils::SharpGSException(utils::ErrorCode::COMMITMENT_FAILED,
                                    "Opening has too many values for available generators");
    }
}

} // namespace sharp_gs
#include "commitments.h"
#include <iostream>
#include <cstring>

namespace sharp_gs {

std::vector<uint8_t> PedersenCommitment::serialize() const {
    std::vector<uint8_t> data(48);  // BN254 G1 point size
    commitment.serialize(data.data(), data.size());
    return data;
}

bool PedersenCommitment::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() != 48) return false;
    return commitment.deserialize(data.data(), data.size());
}

bool PedersenCommitment::is_valid() const {
    return !commitment.isZero();
}

PedersenCommitment CommitmentOps::commit_single(const Fr& value, const Fr& randomness,
                                               const GroupManager::CommitmentKey& ck) {
    if (ck.G_i.empty()) {
        throw std::invalid_argument("Commitment key has no value generators");
    }
    
    // Compute C = r*G0 + x*G1
    G1 result, temp;
    G1::mul(result, ck.G0, randomness);        // r*G0
    G1::mul(temp, ck.G_i[0], value);           // x*G1
    G1::add(result, result, temp);             // r*G0 + x*G1
    
    return PedersenCommitment(result);
}

PedersenCommitment CommitmentOps::commit_multi(const std::vector<Fr>& values, const Fr& randomness,
                                              const GroupManager::CommitmentKey& ck) {
    if (values.size() > ck.G_i.size()) {
        throw std::invalid_argument("Too many values for commitment key");
    }
    
    // Compute C = r*G0 + Σ x_i*G_i
    G1 result, temp;
    G1::mul(result, ck.G0, randomness);        // r*G0
    
    for (size_t i = 0; i < values.size(); ++i) {
        G1::mul(temp, ck.G_i[i], values[i]);   // x_i*G_i
        G1::add(result, result, temp);          // Add to running sum
    }
    
    return PedersenCommitment(result);
}

PedersenCommitment CommitmentOps::commit_decomposition(
    const std::vector<std::vector<Fr>>& decomposition,
    const Fr& randomness,
    const GroupManager::CommitmentKey& ck) {
    
    if (decomposition.size() > ck.G_ij.size()) {
        throw std::invalid_argument("Too many decomposition rows for commitment key");
    }
    
    // Compute C = r*G0 + Σ Σ y_{i,j}*G_{i,j}
    G1 result, temp;
    G1::mul(result, ck.G0, randomness);        // r*G0
    
    for (size_t i = 0; i < decomposition.size(); ++i) {
        if (decomposition[i].size() != 3) {
            throw std::invalid_argument("Each decomposition row must have exactly 3 elements");
        }
        
        if (i >= ck.G_ij.size() || ck.G_ij[i].size() != 3) {
            throw std::invalid_argument("Commitment key missing generators for decomposition");
        }
        
        for (size_t j = 0; j < 3; ++j) {
            G1::mul(temp, ck.G_ij[i][j], decomposition[i][j]);  // y_{i,j}*G_{i,j}
            G1::add(result, result, temp);                       // Add to running sum
        }
    }
    
    return PedersenCommitment(result);
}

PedersenCommitment CommitmentOps::commit_linearization(
    const std::vector<Fr>& alpha_values,
    const Fr& randomness,
    const GroupManager::LinearizationKey& lk) {
    
    if (alpha_values.size() > lk.H_i.size()) {
        throw std::invalid_argument("Too many alpha values for linearization key");
    }
    
    // Compute C = r*H0 + Σ α_i*H_i
    G1 result, temp;
    G1::mul(result, lk.H0, randomness);        // r*H0
    
    for (size_t i = 0; i < alpha_values.size(); ++i) {
        G1::mul(temp, lk.H_i[i], alpha_values[i]);  // α_i*H_i
        G1::add(result, result, temp);               // Add to running sum
    }
    
    return PedersenCommitment(result);
}

PedersenCommitment CommitmentOps::add(const PedersenCommitment& c1, const PedersenCommitment& c2) {
    G1 result;
    G1::add(result, c1.commitment, c2.commitment);
    return PedersenCommitment(result);
}

PedersenCommitment CommitmentOps::scalar_mul(const Fr& scalar, const PedersenCommitment& c) {
    G1 result;
    G1::mul(result, c.commitment, scalar);
    return PedersenCommitment(result);
}

bool CommitmentOps::verify_opening(const PedersenCommitment& commitment,
                                  const std::vector<Fr>& values,
                                  const Fr& randomness,
                                  const GroupManager::CommitmentKey& ck) {
    try {
        // Recompute commitment with given values and randomness
        PedersenCommitment recomputed;
        
        if (values.size() == 1) {
            recomputed = commit_single(values[0], randomness, ck);
        } else {
            recomputed = commit_multi(values, randomness, ck);
        }
        
        // Check if recomputed commitment matches the original
        return commitment.commitment == recomputed.commitment;
        
    } catch (const std::exception&) {
        return false;
    }
}

bool CommitmentOps::batch_verify_openings(const std::vector<PedersenCommitment>& commitments,
                                         const std::vector<std::vector<Fr>>& values,
                                         const std::vector<Fr>& randomness,
                                         const GroupManager::CommitmentKey& ck) {
    if (commitments.size() != values.size() || commitments.size() != randomness.size()) {
        return false;
    }
    
    // Verify each commitment individually
    for (size_t i = 0; i < commitments.size(); ++i) {
        if (!verify_opening(commitments[i], values[i], randomness[i], ck)) {
            return false;
        }
    }
    
    return true;
}

} // namespace sharp_gs
#pragma once

#include <mcl/bn.hpp>
#include <vector>
#include "groups.h"

using namespace mcl;

namespace sharp_gs {

/**
 * @brief Pedersen commitment implementation for SharpGS
 * 
 * Supports both single commitments and multi-commitments as used in the protocol
 */
class PedersenCommitment {
public:
    G1 commitment;  // The commitment value
    
    PedersenCommitment() = default;
    PedersenCommitment(const G1& c) : commitment(c) {}
    
    bool operator==(const PedersenCommitment& other) const {
        return commitment == other.commitment;
    }
    
    bool operator!=(const PedersenCommitment& other) const {
        return !(*this == other);
    }
    
    /**
     * @brief Serialize commitment to bytes
     */
    std::vector<uint8_t> serialize() const;
    
    /**
     * @brief Deserialize commitment from bytes
     */
    bool deserialize(const std::vector<uint8_t>& data);
    
    /**
     * @brief Check if commitment is valid (not zero)
     */
    bool is_valid() const;
};

/**
 * @brief Commitment operations using group keys
 */
class CommitmentOps {
public:
    /**
     * @brief Commit to single value: C = r*G0 + x*G1
     */
    static PedersenCommitment commit_single(const Fr& value, const Fr& randomness,
                                           const GroupManager::CommitmentKey& ck);

    /**
     * @brief Commit to multiple values: C = r*G0 + Σ x_i*G_i
     */
    static PedersenCommitment commit_multi(const std::vector<Fr>& values, const Fr& randomness,
                                          const GroupManager::CommitmentKey& ck);

    /**
     * @brief Commit to decomposition: C = r*G0 + Σ Σ y_{i,j}*G_{i,j}
     */
    static PedersenCommitment commit_decomposition(
        const std::vector<std::vector<Fr>>& decomposition,
        const Fr& randomness,
        const GroupManager::CommitmentKey& ck);

    /**
     * @brief Commit in linearization group: C = r*H0 + Σ α_i*H_i
     */
    static PedersenCommitment commit_linearization(
        const std::vector<Fr>& alpha_values,
        const Fr& randomness,
        const GroupManager::LinearizationKey& lk);

    /**
     * @brief Add two commitments: C3 = C1 + C2
     */
    static PedersenCommitment add(const PedersenCommitment& c1, const PedersenCommitment& c2);

    /**
     * @brief Scalar multiply commitment: C' = scalar * C
     */
    static PedersenCommitment scalar_mul(const Fr& scalar, const PedersenCommitment& c);

    /**
     * @brief Verify commitment opens to given values
     */
    static bool verify_opening(const PedersenCommitment& commitment,
                              const std::vector<Fr>& values,
                              const Fr& randomness,
                              const GroupManager::CommitmentKey& ck);

    /**
     * @brief Batch verify multiple commitments
     */
    static bool batch_verify_openings(const std::vector<PedersenCommitment>& commitments,
                                     const std::vector<std::vector<Fr>>& values,
                                     const std::vector<Fr>& randomness,
                                     const GroupManager::CommitmentKey& ck);
};

} // namespace sharp_gs
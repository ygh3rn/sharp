#pragma once

#include "groups.h"
#include <vector>

namespace sharp_gs {

/**
 * @brief Pedersen Multi-Commitment implementation for SharpGS
 * 
 * Commits to vectors of values: C = r*G0 + Σ xi*Gi
 */
class PedersenMultiCommit {
public:
    struct Commitment {
        G1 value;
        
        Commitment() = default;
        explicit Commitment(const G1& val) : value(val) {}
        
        // Commitment arithmetic
        Commitment operator+(const Commitment& other) const;
        Commitment operator*(const Fr& scalar) const;
        
        bool operator==(const Commitment& other) const;
        bool operator!=(const Commitment& other) const;
    };

    struct Opening {
        std::vector<Fr> values;    // The committed values xi
        Fr randomness;             // The randomness r
        
        Opening() = default;
        Opening(const std::vector<Fr>& vals, const Fr& rand) 
            : values(vals), randomness(rand) {}
    };

private:
    const GroupManager::GroupParams* params_;
    bool is_g3sq_group_;  // Whether to use G3sq or Gcom parameters

public:
    explicit PedersenMultiCommit(const GroupManager& groups, bool use_g3sq = false);

    /**
     * @brief Commit to a vector of values
     * @param values Vector of values to commit to
     * @param randomness Random value for hiding (if empty, generates random)
     * @return Commitment and opening information
     */
    std::pair<Commitment, Opening> commit(const std::vector<Fr>& values, 
                                         const Fr& randomness = Fr()) const;

    /**
     * @brief Commit to a single value 
     */
    std::pair<Commitment, Opening> commit_single(const Fr& value, 
                                                const Fr& randomness = Fr()) const;

    /**
     * @brief Verify that a commitment opens to specified values
     */
    bool verify(const Commitment& commitment, 
               const Opening& opening) const;

    /**
     * @brief Recompute commitment from opening
     */
    Commitment recompute_commitment(const Opening& opening) const;

    /**
     * @brief Get maximum supported vector size
     */
    size_t max_vector_size() const;

    /**
     * @brief Commit with specific generator indices (for 3-square decomposition)
     * Used for committing yi,j values with generators Gi,j
     */
    std::pair<Commitment, Opening> commit_indexed(
        const std::vector<std::vector<Fr>>& value_matrix,  // values[i][j] for yi,j
        const Fr& randomness = Fr()) const;

private:
    std::vector<G1> get_generators_for_size(size_t vector_size) const;
};

/**
 * @brief Commitment operations and utilities
 */
namespace commit_utils {
    
    /**
     * @brief Combine multiple commitments with coefficients
     * Result = Σ coeffs[i] * commitments[i]
     */
    PedersenMultiCommit::Commitment combine_commitments(
        const std::vector<Fr>& coefficients,
        const std::vector<PedersenMultiCommit::Commitment>& commitments);

    /**
     * @brief Add commitments: C1 + C2
     */
    PedersenMultiCommit::Commitment add_commitments(
        const PedersenMultiCommit::Commitment& c1,
        const PedersenMultiCommit::Commitment& c2);

    /**
     * @brief Subtract commitments: C1 - C2  
     */
    PedersenMultiCommit::Commitment subtract_commitments(
        const PedersenMultiCommit::Commitment& c1,
        const PedersenMultiCommit::Commitment& c2);

    /**
     * @brief Scale commitment by scalar: s * C
     */
    PedersenMultiCommit::Commitment scale_commitment(
        const Fr& scalar,
        const PedersenMultiCommit::Commitment& commitment);

    /**
     * @brief Check if commitment is the identity (zero commitment)
     */
    bool is_identity_commitment(const PedersenMultiCommit::Commitment& commitment);
}

} // namespace sharp_gs
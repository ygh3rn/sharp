#pragma once

#include "groups.h"
#include <vector>
#include <optional>

namespace sharp_gs {

/**
 * @brief Pedersen multi-commitment scheme
 * 
 * Implements commitments of the form: Com(m1,...,mn; r) = r*G0 + m1*G1 + ... + mn*Gn
 * Used for both Gcom and G3sq groups in SharpGS protocol.
 */
class PedersenMultiCommit {
public:
    /**
     * @brief Commitment value
     */
    struct Commitment {
        G1 value;
        
        explicit Commitment(const G1& val = G1()) : value(val) {}
        
        // Arithmetic operations
        Commitment operator+(const Commitment& other) const;
        Commitment operator*(const Fr& scalar) const;
        bool operator==(const Commitment& other) const;
        bool operator!=(const Commitment& other) const;
        
        // Serialization
        size_t size_bytes() const { return 32; } // Compressed G1 point
        std::vector<uint8_t> serialize() const;
        static Commitment deserialize(const std::vector<uint8_t>& data);
        
        // Utility
        bool is_zero() const { return value.isZero(); }
    };
    
    /**
     * @brief Opening information for commitments
     */
    struct Opening {
        std::vector<Fr> values;
        Fr randomness;
        
        Opening() = default;
        Opening(const std::vector<Fr>& vals, const Fr& rand) 
            : values(vals), randomness(rand) {}
        
        // Serialization
        size_t size_bytes() const;
        std::vector<uint8_t> serialize() const;
        static Opening deserialize(const std::vector<uint8_t>& data);
    };

private:
    const GroupManager& groups_;
    bool use_g3sq_;

public:
    explicit PedersenMultiCommit(const GroupManager& groups, bool use_g3sq = false);
    
    /**
     * @brief Commit to a single value
     */
    std::pair<Commitment, Opening> commit_single(const Fr& value, const Fr& randomness) const;  // FIX: Added const
    
    /**
     * @brief Commit to a vector of values
     */
    std::pair<Commitment, Opening> commit_vector(const std::vector<Fr>& values, const Fr& randomness) const;  // FIX: Added const
    
    /**
     * @brief Commit with random randomness
     */
    std::pair<Commitment, Opening> commit_vector(const std::vector<Fr>& values) const;  // FIX: Added const
    
    /**
     * @brief Verify a commitment opening
     */
    bool verify(const Commitment& commitment, const Opening& opening) const;  // FIX: Added const
    
    /**
     * @brief Recompute commitment from opening
     */
    Commitment recompute_commitment(const Opening& opening) const;  // FIX: Added const
    
    /**
     * @brief Batch commitment verification
     */
    bool verify_batch(const std::vector<Commitment>& commitments, 
                     const std::vector<Opening>& openings) const;  // FIX: Added const
    
    /**
     * @brief Get the group being used
     */
    bool using_g3sq() const { return use_g3sq_; }
    
    /**
     * @brief Get reference to group manager
     */
    const GroupManager& groups() const { return groups_; }

private:
    const std::vector<G1>& get_generators() const;
    void validate_opening_size(const Opening& opening) const;
};

} // namespace sharp_gs
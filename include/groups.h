#pragma once

#include <mcl/bn.hpp>
#include <vector>

using namespace mcl;

namespace sharp_gs {

/**
 * @brief Group manager for SharpGS protocol with group switching
 * 
 * Manages two groups:
 * - G_com: Group for value commitments (typically smaller, ~256 bits)
 * - G_3sq: Group for three-square decomposition (typically larger, ~350 bits)
 */
class GroupManager {
public:
    /**
     * @brief Commitment key for G_com group
     */
    struct CommitmentKey {
        G1 G0;                           // Generator for randomness
        std::vector<G1> G_i;             // Generators for values x_i
        std::vector<std::vector<G1>> G_ij; // Generators for decomposition y_{i,j}
        size_t max_values;               // Maximum number of values N
        
        CommitmentKey() = default;
        CommitmentKey(size_t N);
        void setup(size_t N);
        bool is_valid() const;
    };

    /**
     * @brief Linearization key for G_3sq group  
     */
    struct LinearizationKey {
        G1 H0;                    // Generator for randomness
        std::vector<G1> H_i;      // Generators for linearization α*_{k,i}
        size_t max_values;        // Maximum number of values N
        
        LinearizationKey() = default;
        LinearizationKey(size_t N);
        void setup(size_t N);
        bool is_valid() const;
    };

private:
    CommitmentKey ck_com_;
    LinearizationKey ck_3sq_;
    size_t max_batch_size_;
    bool initialized_;

public:
    GroupManager() : max_batch_size_(0), initialized_(false) {}
    
    /**
     * @brief Initialize group manager with maximum batch size
     */
    void setup(size_t max_batch_size);

    /**
     * @brief Get commitment key for G_com
     */
    const CommitmentKey& get_commitment_key() const { return ck_com_; }

    /**
     * @brief Get linearization key for G_3sq
     */
    const LinearizationKey& get_linearization_key() const { return ck_3sq_; }

    /**
     * @brief Check if properly initialized
     */
    bool is_initialized() const { return initialized_; }

    /**
     * @brief Get maximum supported batch size
     */
    size_t get_max_batch_size() const { return max_batch_size_; }

    /**
     * @brief Generate random group element in G_com
     */
    static G1 random_g1_element();

    /**
     * @brief Hash to curve point (for Fiat-Shamir)
     */
    static G1 hash_to_curve(const std::string& input);

    /**
     * @brief Serialize commitment key
     */
    std::vector<uint8_t> serialize_commitment_key() const;

    /**
     * @brief Deserialize commitment key
     */
    bool deserialize_commitment_key(const std::vector<uint8_t>& data);
};

} // namespace sharp_gs
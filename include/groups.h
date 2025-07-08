#pragma once

#include <mcl/bn.hpp>
#include <vector>
#include <memory>

using namespace mcl;

namespace sharp_gs {

/**
 * @brief Group configuration and operations for SharpGS
 * 
 * SharpGS uses two groups:
 * - Gcom: for commitments (order p)
 * - G3sq: for 3-square decomposition proof (order q)
 */
class GroupManager {
public:
    struct GroupParams {
        std::vector<G1> generators;  // G0, G1, ..., GN, Gi,j for commitments
        Fr modulus;                  // Group order (p or q)
        size_t max_batch_size;       // Maximum supported batch size N
        
        GroupParams() = default;
        GroupParams(size_t batch_size);
    };

private:
    GroupParams gcom_params_;    // Parameters for Gcom group
    GroupParams g3sq_params_;    // Parameters for G3sq group
    bool initialized_;

public:
    GroupManager();
    ~GroupManager() = default;

    /**
     * @brief Initialize groups with specified parameters
     * @param security_bits Security parameter λ (e.g., 128)
     * @param range_bits Range size log₂(B)
     * @param max_batch_size Maximum number of values to prove simultaneously
     * @param challenge_bits Challenge space size log₂(Γ)
     */
    bool initialize(size_t security_bits, 
                   size_t range_bits, 
                   size_t max_batch_size = 1,
                   size_t challenge_bits = 128);

    /**
     * @brief Get commitment group parameters
     */
    const GroupParams& get_gcom_params() const { return gcom_params_; }

    /**
     * @brief Get 3-square group parameters  
     */
    const GroupParams& get_g3sq_params() const { return g3sq_params_; }

    /**
     * @brief Check if groups are properly initialized
     */
    bool is_initialized() const { return initialized_; }

    /**
     * @brief Generate random field element in specified group
     */
    Fr random_scalar(bool use_g3sq = false) const;

    /**
     * @brief Compute minimum group sizes based on parameters
     */
    static std::pair<size_t, size_t> compute_group_sizes(
        size_t security_bits, 
        size_t range_bits, 
        size_t challenge_bits,
        size_t masking_overhead = 40
    );

private:
    void setup_gcom_generators(size_t batch_size);
    void setup_g3sq_generators(size_t batch_size);
    Fr compute_group_order(size_t required_bits) const;
};

/**
 * @brief Utility functions for group operations
 */
namespace group_utils {
    
    /**
     * @brief Multi-scalar multiplication: Σ scalars[i] * points[i]
     */
    G1 multi_scalar_mult(const std::vector<Fr>& scalars, const std::vector<G1>& points);

    /**
     * @brief Check if a scalar is within specified bounds
     */
    bool is_scalar_bounded(const Fr& scalar, const Fr& bound);

    /**
     * @brief Convert integer to field element
     */
    Fr int_to_field(int64_t value);

    /**
     * @brief Convert field element to integer (for small values)
     */
    int64_t field_to_int(const Fr& element);

    /**
     * @brief Generate cryptographically secure random Fr
     */
    Fr secure_random();

    /**
     * @brief Check if field element represents a small integer
     */
    bool is_small_integer(const Fr& element, int64_t max_value);
}

} // namespace sharp_gs
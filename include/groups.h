#pragma once

#include "utils.h"
#include <vector>
#include <memory>

namespace sharp_gs {

/**
 * @brief Group manager for SharpGS protocol
 * 
 * Manages two groups: Gcom (for commitments) and G3sq (for decomposition)
 * as required by the SharpGS protocol.
 */
class GroupManager {
public:
    struct GroupParams {
        std::vector<G1> generators;
        Fr modulus;
        size_t max_batch_size;
        
        explicit GroupParams(size_t batch_size = 0);
    };

private:
    GroupParams gcom_params_;
    GroupParams g3sq_params_;
    bool initialized_;
    
public:
    GroupManager();
    
    bool initialize(size_t security_bits, size_t range_bits, 
                   size_t max_batch_size, size_t challenge_bits = 128);
    
    // Getters
    const GroupParams& gcom_params() const { return gcom_params_; }
    const GroupParams& g3sq_params() const { return g3sq_params_; }
    bool is_initialized() const { return initialized_; }
    
    // Group operations
    Fr random_scalar(bool use_g3sq = false) const;
    G1 get_generator(size_t index, bool use_g3sq = false) const;
    
    // Generator access for commitments
    const std::vector<G1>& get_gcom_generators() const { return gcom_params_.generators; }
    const std::vector<G1>& get_g3sq_generators() const { return g3sq_params_.generators; }
    
    // Size queries
    size_t gcom_generator_count() const { return gcom_params_.generators.size(); }
    size_t g3sq_generator_count() const { return g3sq_params_.generators.size(); }

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
    
    /**
     * @brief Compare two field elements for ordering
     */
    bool field_less_than(const Fr& a, const Fr& b);
}

} // namespace sharp_gs
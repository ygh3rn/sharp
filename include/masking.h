#pragma once

#include "groups.h"
#include <optional>

namespace sharp_gs {

/**
 * @brief Masking schemes for zero-knowledge in SharpGS
 * 
 * Implements uniform rejection sampling as described in the paper
 */
class MaskingScheme {
public:
    struct MaskingParams {
        Fr range_bound;      // V: maximum value to mask
        size_t overhead;     // L: masking overhead factor
        double abort_prob;   // Maximum abort probability
        
        MaskingParams(const Fr& bound, size_t ovh = 40) 
            : range_bound(bound), overhead(ovh), abort_prob(1.0 / (1 << ovh)) {}
    };

private:
    MaskingParams params_;
    Fr mask_range_max_;  // (V + 1) * L

public:
    explicit MaskingScheme(const MaskingParams& params);

    /**
     * @brief Generate a random mask
     * @return Random mask in range [0, (V+1)*L]
     */
    Fr generate_mask() const;

    /**
     * @brief Apply masking to a value
     * @param value Value to mask (must be in [0, V])
     * @param mask Random mask
     * @return Masked value or nullopt if rejected
     */
    std::optional<Fr> apply_mask(const Fr& value, const Fr& mask) const;

    /**
     * @brief Apply masking with auto-generated mask
     * @param value Value to mask
     * @return (masked_value, mask) or nullopt if rejected
     */
    std::optional<std::pair<Fr, Fr>> mask_value(const Fr& value) const;

    /**
     * @brief Check if a masked value is in the valid range
     */
    bool is_valid_masked_value(const Fr& masked_value) const;

    /**
     * @brief Get the valid range for masked values
     */
    std::pair<Fr, Fr> get_masked_range() const;

    /**
     * @brief Get maximum abort probability
     */
    double get_abort_probability() const { return params_.abort_prob; }

    /**
     * @brief Unmask a value (for testing purposes)
     */
    Fr unmask_value(const Fr& masked_value, const Fr& mask) const;
};

/**
 * @brief Specialized masking for different value types in SharpGS
 */
class SharpGSMasking {
public:
    struct MaskingConfiguration {
        MaskingScheme value_masking;      // For xi values  
        MaskingScheme randomness_masking; // For commitment randomness
        MaskingScheme decomp_masking;     // For decomposition coefficients
        
        MaskingConfiguration(size_t range_bits, size_t challenge_bits, size_t security_bits);
    };

private:
    std::unique_ptr<MaskingConfiguration> config_;

public:
    SharpGSMasking(size_t range_bits, size_t challenge_bits, size_t security_bits = 128);
    ~SharpGSMasking();

    /**
     * @brief Mask values xi with challenge γ: mask(γ * xi, mask)
     */
    std::optional<Fr> mask_challenged_value(const Fr& value, const Fr& challenge) const;

    /**
     * @brief Mask commitment randomness
     */
    std::optional<Fr> mask_randomness(const Fr& randomness, const Fr& challenge) const;

    /**
     * @brief Mask decomposition polynomial coefficients
     */
    std::optional<Fr> mask_decomposition_coeff(const Fr& coefficient, const Fr& challenge) const;

    /**
     * @brief Batch mask multiple values
     * @return Vector of masked values, or nullopt if any masking failed
     */
    std::optional<std::vector<Fr>> mask_values_batch(
        const std::vector<Fr>& values,
        const std::vector<Fr>& challenges) const;

    /**
     * @brief Get expected number of retries for successful masking
     */
    double expected_retries() const;

    /**
     * @brief Get overall success probability for a batch
     */
    double batch_success_probability(size_t batch_size, size_t num_repetitions) const;
};

/**
 * @brief Utility functions for masking operations
 */
namespace masking_utils {
    
    /**
     * @brief Compute optimal masking overhead for given security level
     */
    size_t compute_masking_overhead(size_t security_bits);

    /**
     * @brief Estimate abort probability for given parameters
     */
    double estimate_abort_probability(const Fr& range_bound, size_t overhead);

    /**
     * @brief Check if value is in specified range
     */
    bool is_in_range(const Fr& value, const Fr& min_val, const Fr& max_val);

    /**
     * @brief Generate uniform random value in range [0, bound]
     */
    Fr uniform_random(const Fr& bound);

    /**
     * @brief Compute masking bound: (V + 1) * L
     */
    Fr compute_masking_bound(const Fr& value_bound, size_t overhead);
}

} // namespace sharp_gs
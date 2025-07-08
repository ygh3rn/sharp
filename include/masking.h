#pragma once

#include "utils.h"
#include <optional>
#include <vector>

namespace sharp_gs {

/**
 * @brief Masking parameters for zero-knowledge
 */
struct MaskingParams {
    size_t overhead;           // L - masking overhead bits
    double abort_probability;  // Target abort probability
    size_t security_bits;      // λ - security parameter
    
    MaskingParams(size_t overhead = 40, double abort_prob = 0.5, size_t security = 128)
        : overhead(overhead), abort_probability(abort_prob), security_bits(security) {}
        
    bool validate() const;
};

/**
 * @brief Zero-knowledge masking scheme
 */
class MaskingScheme {
private:
    MaskingParams params_;
    Fr L_;  // 2^overhead
    
public:
    explicit MaskingScheme(const MaskingParams& params);
    
    /**
     * @brief Generate masking value for a given challenge and secret
     */
    Fr generate_mask(const Fr& challenge, const Fr& secret) const;
    
    /**
     * @brief Check if masking is valid (within bounds)
     */
    bool is_valid_mask(const Fr& mask, const Fr& bound) const;
    
    /**
     * @brief Estimate abort probability for given parameters
     */
    double estimate_abort_probability(const Fr& range_bound) const;
    
    /**
     * @brief Get masking bound (2^overhead)
     */
    const Fr& masking_bound() const { return L_; }
    
    /**
     * @brief Get parameters
     */
    const MaskingParams& params() const { return params_; }
    
    /**
     * @brief Generate random element within masking bound
     */
    Fr random_mask() const;
    
    /**
     * @brief Check if value is within masking range
     */
    bool within_mask_range(const Fr& value) const;
};

/**
 * @brief Value masking for specific applications
 */
class ValueMasking {
private:
    MaskingScheme scheme_;
    
public:
    explicit ValueMasking(const MaskingParams& params) : scheme_(params) {}
    
    /**
     * @brief Mask a value with rejection sampling
     */
    std::optional<std::pair<Fr, Fr>> mask_value(const Fr& value) const;
    
    /**
     * @brief Batch mask multiple values
     */
    std::vector<std::optional<std::pair<Fr, Fr>>> mask_batch(const std::vector<Fr>& values) const;
    
    /**
     * @brief Verify masked value is correct
     */
    bool verify_masked_value(const Fr& original, const Fr& masked, const Fr& randomness) const;
};

/**
 * @brief SharpGS-specific masking operations
 */
class SharpGSMasking {
private:
    std::unique_ptr<MaskingScheme> config_;
    
public:
    explicit SharpGSMasking(const MaskingParams& params);
    ~SharpGSMasking() = default;
    
    /**
     * @brief Generate masked challenge response: z = γx + r
     */
    std::optional<Fr> mask_challenged_value(const Fr& challenge, const Fr& value) const;
    
    /**
     * @brief Generate masked randomness
     */
    std::optional<Fr> mask_randomness(const Fr& challenge, const Fr& randomness) const;
    
    /**
     * @brief Batch masking for multiple challenges and values
     */
    std::vector<std::optional<Fr>> mask_batch_responses(
        const std::vector<Fr>& challenges,
        const std::vector<Fr>& values
    ) const;
    
    /**
     * @brief Verify masking is within acceptable bounds
     */
    bool verify_mask_bounds(const Fr& masked_value, const Fr& bound) const;
    
    /**
     * @brief Get abort probability for current configuration
     */
    double abort_probability() const;
    
    /**
     * @brief Adaptive masking based on value distribution
     */
    std::optional<Fr> adaptive_mask(const Fr& challenge, const Fr& value, const Fr& hint) const;
};

/**
 * @brief Masking utilities
 */
namespace masking_utils {
    
    /**
     * @brief Estimate optimal masking parameters
     */
    MaskingParams optimize_masking_params(
        size_t security_bits,
        double target_abort_prob,
        size_t range_bits
    );
    
    /**
     * @brief Compute theoretical abort probability
     */
    double estimate_abort_probability(const Fr& range_bound, size_t overhead);
    
    /**
     * @brief Generate uniform random element in range [0, bound)
     */
    Fr uniform_random(const Fr& bound);
    
    /**
     * @brief Compute masking bound for given overhead
     */
    Fr compute_masking_bound(const Fr& range_bound, size_t overhead);
    
    /**
     * @brief Statistical distance between distributions
     */
    double statistical_distance(const MaskingParams& params, const Fr& range_bound);
}

} // namespace sharp_gs
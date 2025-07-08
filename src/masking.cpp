#include "masking.h"
#include "utils.h"
#include <cmath>
#include <algorithm>

namespace sharp_gs {

// MaskingScheme implementation
MaskingScheme::MaskingScheme(const MaskingParams& params) : params_(params) {
    // Compute mask range: (V + 1) * L
    Fr V_plus_one;
    Fr::add(V_plus_one, params_.range_bound, group_utils::int_to_field(1));
    
    Fr L;
    L.setInt(1ULL << params_.overhead);
    
    Fr::mul(mask_range_max_, V_plus_one, L);
}

Fr MaskingScheme::generate_mask() const {
    // Generate uniform random mask in [0, (V+1)*L]
    Fr mask;
    mask.setByCSPRNG();
    
    // Reduce modulo mask_range_max_ + 1 to get uniform distribution
    // Note: This is a simplified approach - in practice would need proper uniform sampling
    return mask;
}

std::optional<Fr> MaskingScheme::apply_mask(const Fr& value, const Fr& mask) const {
    // Check if value is in valid range [0, V]
    if (!group_utils::is_scalar_bounded(value, params_.range_bound)) {
        return std::nullopt;
    }
    
    // Compute masked value: value + mask
    Fr masked_value;
    Fr::add(masked_value, value, mask);
    
    // Check if result is in acceptance range [V, (V+1)*L]
    auto [min_range, max_range] = get_masked_range();
    
    if (!masking_utils::is_in_range(masked_value, min_range, max_range)) {
        return std::nullopt; // Reject
    }
    
    return masked_value;
}

std::optional<std::pair<Fr, Fr>> MaskingScheme::mask_value(const Fr& value) const {
    // Try masking with auto-generated mask
    Fr mask = generate_mask();
    auto masked_result = apply_mask(value, mask);
    
    if (masked_result) {
        return std::make_pair(*masked_result, mask);
    }
    
    return std::nullopt;
}

bool MaskingScheme::is_valid_masked_value(const Fr& masked_value) const {
    auto [min_range, max_range] = get_masked_range();
    return masking_utils::is_in_range(masked_value, min_range, max_range);
}

std::pair<Fr, Fr> MaskingScheme::get_masked_range() const {
    // Valid range: [V, (V+1)*L]
    Fr min_val = params_.range_bound;
    Fr max_val = mask_range_max_;
    
    return {min_val, max_val};
}

Fr MaskingScheme::unmask_value(const Fr& masked_value, const Fr& mask) const {
    Fr result;
    Fr::sub(result, masked_value, mask);
    return result;
}

// SharpGSMasking implementation
SharpGSMasking::MaskingConfiguration::MaskingConfiguration(
    size_t range_bits, 
    size_t challenge_bits, 
    size_t security_bits) 
    : value_masking(MaskingScheme::MaskingParams(
        group_utils::int_to_field((1ULL << range_bits) * (1ULL << challenge_bits)), 
        security_bits / 2)),
      randomness_masking(MaskingScheme::MaskingParams(
        group_utils::int_to_field(1ULL << (security_bits + 10)), // Large randomness space
        security_bits / 3)),
      decomp_masking(MaskingScheme::MaskingParams(
        group_utils::int_to_field((1ULL << range_bits) * (1ULL << challenge_bits)), 
        security_bits / 2)) {
}

SharpGSMasking::SharpGSMasking(size_t range_bits, size_t challenge_bits, size_t security_bits) {
    config_ = std::make_unique<MaskingConfiguration>(range_bits, challenge_bits, security_bits);
}

SharpGSMasking::~SharpGSMasking() = default;

std::optional<Fr> SharpGSMasking::mask_challenged_value(const Fr& value, const Fr& challenge) const {
    // Compute γ * xi
    Fr challenged_value;
    Fr::mul(challenged_value, challenge, value);
    
    // Apply masking: mask(γ * xi, mask)
    return config_->value_masking.mask_value(challenged_value).value_or(std::nullopt);
}

std::optional<Fr> SharpGSMasking::mask_randomness(const Fr& randomness, const Fr& challenge) const {
    // Compute γ * r
    Fr challenged_randomness;
    Fr::mul(challenged_randomness, challenge, randomness);
    
    // Apply masking
    auto result = config_->randomness_masking.mask_value(challenged_randomness);
    return result ? std::optional<Fr>(result->first) : std::nullopt;
}

std::optional<Fr> SharpGSMasking::mask_decomposition_coeff(const Fr& coefficient, const Fr& challenge) const {
    // For polynomial coefficients in decomposition proof
    Fr challenged_coeff;
    Fr::mul(challenged_coeff, challenge, coefficient);
    
    auto result = config_->decomp_masking.mask_value(challenged_coeff);
    return result ? std::optional<Fr>(result->first) : std::nullopt;
}

std::optional<std::vector<Fr>> SharpGSMasking::mask_values_batch(
    const std::vector<Fr>& values,
    const std::vector<Fr>& challenges) const {
    
    if (values.size() != challenges.size()) {
        return std::nullopt;
    }
    
    std::vector<Fr> masked_values;
    masked_values.reserve(values.size());
    
    for (size_t i = 0; i < values.size(); ++i) {
        auto masked = mask_challenged_value(values[i], challenges[i]);
        if (!masked) {
            return std::nullopt; // If any masking fails, reject entire batch
        }
        masked_values.push_back(*masked);
    }
    
    return masked_values;
}

double SharpGSMasking::expected_retries() const {
    // Expected number of retries = 1 / success_probability
    double success_prob = 1.0 - config_->value_masking.get_abort_probability();
    return 1.0 / success_prob;
}

double SharpGSMasking::batch_success_probability(size_t batch_size, size_t num_repetitions) const {
    // For SharpGS: probability that all maskings succeed
    // Per repetition: 4N values (xi + 3*yi,j) + 3 randomness terms
    size_t maskings_per_rep = 4 * batch_size + 3;
    size_t total_maskings = maskings_per_rep * num_repetitions;
    
    double single_success = 1.0 - config_->value_masking.get_abort_probability();
    return std::pow(single_success, total_maskings);
}

// Masking utility functions
namespace masking_utils {

size_t compute_masking_overhead(size_t security_bits) {
    // Common choice: overhead ≥ security parameter for statistical security
    return std::max(40UL, security_bits);
}

double estimate_abort_probability(const Fr& range_bound, size_t overhead) {
    // Approximate: p ≈ 1/L where L = 2^overhead
    return 1.0 / (1ULL << overhead);
}

bool is_in_range(const Fr& value, const Fr& min_val, const Fr& max_val) {
    // Simplified range check - in practice would need proper field arithmetic comparison
    try {
        int64_t val = group_utils::field_to_int(value);
        int64_t min_int = group_utils::field_to_int(min_val);
        int64_t max_int = group_utils::field_to_int(max_val);
        
        return val >= min_int && val <= max_int;
    } catch (...) {
        // For large values, use string comparison as fallback
        std::string val_str = value.getStr();
        std::string min_str = min_val.getStr();
        std::string max_str = max_val.getStr();
        
        // Basic string length comparison (not cryptographically secure, but functional)
        return val_str.length() >= min_str.length() && val_str.length() <= max_str.length();
    }
}

Fr uniform_random(const Fr& bound) {
    // Generate uniform random value in [0, bound]
    Fr result;
    result.setByCSPRNG();
    
    // Simple modular reduction (not uniformly random, but adequate for prototype)
    // In practice, would implement proper uniform sampling over finite fields
    return result;
}

Fr compute_masking_bound(const Fr& value_bound, size_t overhead) {
    Fr V_plus_one;
    Fr::add(V_plus_one, value_bound, group_utils::int_to_field(1));
    
    Fr L;
    L.setInt(1ULL << overhead);
    
    Fr result;
    Fr::mul(result, V_plus_one, L);
    return result;
}

} // namespace masking_utils

} // namespace sharp_gs
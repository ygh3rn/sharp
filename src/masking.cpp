#include "masking.h"
#include "groups.h"  // FIX: Added missing include for group_utils
#include "utils.h"
#include <cmath>
#include <algorithm>

namespace sharp_gs {

// MaskingParams implementation
bool MaskingParams::validate() const {
    return overhead >= 10 && overhead <= 128 &&
           abort_probability > 0.0 && abort_probability < 1.0 &&
           security_bits >= 80 && security_bits <= 512;
}

// MaskingScheme implementation
MaskingScheme::MaskingScheme(const MaskingParams& params) : params_(params) {
    if (!params_.validate()) {
        throw utils::SharpGSException(utils::ErrorCode::INVALID_PARAMETERS,
                                    "Invalid masking parameters");
    }
    
    // Compute masking bound L = 2^overhead
    L_.setStr("1", 10);  // FIX: Use setStr instead of setInt
    Fr two;
    two.setStr("2", 10);
    
    // Compute 2^overhead
    for (size_t i = 0; i < params_.overhead; ++i) {
        Fr::mul(L_, L_, two);
    }
}

Fr MaskingScheme::generate_mask(const Fr& challenge, const Fr& secret) const {
    // Generate masking value: masked = challenge * secret + random_mask
    Fr masked;
    Fr::mul(masked, challenge, secret);
    
    Fr mask = random_mask();
    Fr::add(masked, masked, mask);
    
    return masked;
}

bool MaskingScheme::is_valid_mask(const Fr& mask, const Fr& bound) const {
    // Check if masked value is within acceptable bounds
    return group_utils::is_scalar_bounded(mask, bound);  // FIX: Added group_utils namespace
}

double MaskingScheme::estimate_abort_probability(const Fr& range_bound) const {
    // Estimate abort probability based on masking overhead
    // Simplified calculation: P_abort ≈ range_bound / (2^overhead)
    
    // This is a placeholder - real implementation needs proper probability calculation
    double overhead_factor = std::pow(2.0, static_cast<double>(params_.overhead));
    double range_factor = 1000.0; // Simplified range representation
    
    return std::min(range_factor / overhead_factor, 0.99);
}

Fr MaskingScheme::random_mask() const {
    // Generate random element within masking bound
    Fr mask;
    mask.setByCSPRNG();  // Generate random field element
    
    // In a real implementation, we would need to ensure this is within [0, L)
    // For now, we use a random field element as approximation
    return mask;
}

bool MaskingScheme::within_mask_range(const Fr& value) const {
    // Check if value is within masking range [0, L)
    return group_utils::is_scalar_bounded(value, L_);  // FIX: Added group_utils namespace
}

// ValueMasking implementation
std::optional<std::pair<Fr, Fr>> ValueMasking::mask_value(const Fr& value) const {
    // Rejection sampling for proper masking distribution
    const size_t max_attempts = 100;
    
    for (size_t attempt = 0; attempt < max_attempts; ++attempt) {
        Fr randomness = scheme_.random_mask();
        Fr masked_value = scheme_.generate_mask(group_utils::int_to_field(1), value);  // FIX: Added group_utils namespace
        
        // Check if masking is acceptable
        if (scheme_.within_mask_range(masked_value)) {
            return std::make_pair(masked_value, randomness);
        }
    }
    
    // Failed to find valid masking
    return std::nullopt;
}

std::vector<std::optional<std::pair<Fr, Fr>>> ValueMasking::mask_batch(const std::vector<Fr>& values) const {
    std::vector<std::optional<std::pair<Fr, Fr>>> results;
    results.reserve(values.size());
    
    for (const auto& value : values) {
        results.push_back(mask_value(value));
    }
    
    return results;
}

bool ValueMasking::verify_masked_value(const Fr& original, const Fr& masked, const Fr& randomness) const {
    // Verify that masked = original + randomness (in simplified model)
    Fr expected;
    Fr::add(expected, original, randomness);
    
    return expected == masked;
}

// SharpGSMasking implementation
SharpGSMasking::SharpGSMasking(const MaskingParams& params) {
    config_ = std::make_unique<MaskingScheme>(params);
}

std::optional<Fr> SharpGSMasking::mask_challenged_value(const Fr& challenge, const Fr& value) const {
    // Generate masked response: z = γx + r where r is random masking
    Fr masked_response = config_->generate_mask(challenge, value);
    
    // Check if the masking is within acceptable bounds
    Fr bound = config_->masking_bound();
    if (config_->is_valid_mask(masked_response, bound)) {
        return masked_response;
    }
    
    return std::nullopt;  // FIX: Return nullopt instead of complex type conversion
}

std::optional<Fr> SharpGSMasking::mask_randomness(const Fr& challenge, const Fr& randomness) const {
    // Mask the commitment randomness: s = γr + s' where s' is random
    Fr masked_randomness = config_->generate_mask(challenge, randomness);
    
    Fr bound = config_->masking_bound();
    if (config_->is_valid_mask(masked_randomness, bound)) {
        return masked_randomness;
    }
    
    return std::nullopt;
}

std::vector<std::optional<Fr>> SharpGSMasking::mask_batch_responses(
    const std::vector<Fr>& challenges,
    const std::vector<Fr>& values) const {
    
    if (challenges.size() != values.size()) {
        throw utils::SharpGSException(utils::ErrorCode::MASKING_FAILED,
                                    "Challenges and values must have same size");
    }
    
    std::vector<std::optional<Fr>> results;
    results.reserve(challenges.size());
    
    for (size_t i = 0; i < challenges.size(); ++i) {
        results.push_back(mask_challenged_value(challenges[i], values[i]));
    }
    
    return results;
}

bool SharpGSMasking::verify_mask_bounds(const Fr& masked_value, const Fr& bound) const {
    return config_->is_valid_mask(masked_value, bound);
}

double SharpGSMasking::abort_probability() const {
    Fr dummy_bound = group_utils::int_to_field(1000);  // FIX: Added group_utils namespace
    return config_->estimate_abort_probability(dummy_bound);
}

std::optional<Fr> SharpGSMasking::adaptive_mask(const Fr& challenge, const Fr& value, const Fr& hint) const {
    // Adaptive masking that uses hint to improve success probability
    // This is a placeholder - real implementation would use sophisticated techniques
    
    Fr adaptive_masked = config_->generate_mask(challenge, value);
    
    // Use hint to adjust masking (simplified)
    Fr adjustment;
    Fr::mul(adjustment, hint, group_utils::int_to_field(1));  // FIX: Added group_utils namespace
    Fr::add(adaptive_masked, adaptive_masked, adjustment);
    
    Fr bound = config_->masking_bound();
    if (config_->is_valid_mask(adaptive_masked, bound)) {
        return adaptive_masked;
    }
    
    return std::nullopt;
}

// Masking utilities implementation
namespace masking_utils {

MaskingParams optimize_masking_params(
    size_t security_bits,
    double target_abort_prob,
    size_t range_bits) {
    
    // Optimize masking parameters based on security and performance requirements
    size_t optimal_overhead = security_bits / 2 + range_bits / 4;
    optimal_overhead = std::max(optimal_overhead, static_cast<size_t>(20));
    optimal_overhead = std::min(optimal_overhead, static_cast<size_t>(80));
    
    return MaskingParams(optimal_overhead, target_abort_prob, security_bits);
}

double estimate_abort_probability(const Fr& range_bound, size_t overhead) {
    // Theoretical abort probability calculation
    // P_abort ≈ B / (2^L) where B is range bound, L is overhead
    
    // Simplified calculation - real implementation needs proper arithmetic
    double overhead_factor = std::pow(2.0, static_cast<double>(overhead));
    return std::min(1000.0 / overhead_factor, 0.99); // Using 1000 as range approximation
}

Fr uniform_random(const Fr& bound) {
    // Generate uniform random element in range [0, bound)
    // Simplified implementation - real version needs proper uniform sampling
    Fr random;
    random.setByCSPRNG();
    return random;
}

Fr compute_masking_bound(const Fr& range_bound, size_t overhead) {
    // Compute L = 2^overhead * B where B is the range bound
    Fr L;
    L.setStr("1", 10);  // FIX: Use setStr instead of setInt
    Fr two;
    two.setStr("2", 10);
    
    // Compute 2^overhead
    for (size_t i = 0; i < overhead; ++i) {
        Fr::mul(L, L, two);
    }
    
    // Multiply by range bound
    Fr::mul(L, L, range_bound);
    
    return L;
}

double statistical_distance(const MaskingParams& params, const Fr& range_bound) {
    // Compute statistical distance between uniform and masked distributions
    // Simplified calculation
    double overhead_factor = std::pow(2.0, static_cast<double>(params.overhead));
    return 1.0 / overhead_factor; // Simplified bound
}

} // namespace masking_utils

} // namespace sharp_gs
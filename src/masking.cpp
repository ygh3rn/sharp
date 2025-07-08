#include "masking.h"
#include <random>
#include <cmath>
#include <algorithm>
#include <cstring>

namespace sharp_gs {

MaskingScheme::Parameters::Parameters(size_t Lx, size_t Lr, size_t range_bound, 
                                     size_t challenge_size, size_t hiding_param)
    : L_x(Lx), L_r(Lr), B(range_bound), Gamma(challenge_size), S(hiding_param) {
    // Set field modulus (this should be set based on the curve being used)
    // For BN254, this is approximately 2^254
    field_modulus.setStr("21888242871839275222246405745257275088548364400416034343698204186575808495617");
}

bool MaskingScheme::Parameters::validate() const {
    // Basic parameter validation
    if (L_x == 0 || L_r == 0 || B == 0 || Gamma == 0 || S == 0) {
        return false;
    }
    
    // Check that masking overhead is reasonable
    if (L_x < 32 || L_r < 32) {
        return false;  // Too small for security
    }
    
    // Check that parameters don't cause overflow
    if (get_max_mask_value() == 0) {
        return false;  // Overflow occurred
    }
    
    return true;
}

size_t MaskingScheme::Parameters::get_max_mask_value() const {
    // Maximum masked value is (B*Γ + 1)*L_x
    // Check for overflow
    if (B > UINT64_MAX / Gamma) return 0;
    uint64_t temp = B * Gamma;
    if (temp > UINT64_MAX - 1) return 0;
    temp += 1;
    if (temp > UINT64_MAX / L_x) return 0;
    return temp * L_x;
}

double MaskingScheme::Parameters::get_abort_probability() const {
    // Abort probability is approximately 1/L for uniform rejection sampling
    return 1.0 / std::min(L_x, L_r);
}

std::optional<Fr> MaskingScheme::mask_value(const Fr& value, const Fr& mask_randomness) {
    size_t max_value = params_.get_max_mask_value();
    return uniform_rejection_sample(value, mask_randomness, max_value);
}

std::optional<Fr> MaskingScheme::mask_randomness(const Fr& randomness, const Fr& mask_randomness) {
    // For randomness masking, we can use the full field
    // Since randomness masking only needs to hide, not satisfy range checks
    Fr result;
    Fr::add(result, randomness, mask_randomness);
    return result;
}

Fr MaskingScheme::generate_value_mask() {
    // Generate random mask from [0, (B*Γ + 1)*L_x]
    std::random_device rd;
    std::mt19937_64 gen(rd());
    
    size_t max_value = params_.get_max_mask_value();
    std::uniform_int_distribution<uint64_t> dis(0, max_value);
    
    Fr mask;
    mask.setStr(std::to_string(dis(gen)), 10);  // Use setStr instead of setInt
    return mask;
}

Fr MaskingScheme::generate_randomness_mask() {
    // Generate random mask from [0, S*L_r]
    std::random_device rd;
    std::mt19937_64 gen(rd());
    
    // Avoid overflow by checking multiplication
    uint64_t max_value = params_.S;
    if (max_value <= UINT64_MAX / params_.L_r) {
        max_value *= params_.L_r;
    } else {
        max_value = UINT64_MAX;  // Use maximum representable value
    }
    
    std::uniform_int_distribution<uint64_t> dis(0, max_value);
    
    Fr mask;
    mask.setStr(std::to_string(dis(gen)), 10);  // Use setStr instead of setInt
    return mask;
}

bool MaskingScheme::is_in_range(const Fr& masked_value, bool is_value_mask) {
    if (is_value_mask) {
        // Check if masked value is in [0, (B*Γ + 1)*L_x]
        Fr max_value;
        max_value.setStr(std::to_string(params_.get_max_mask_value()), 10);  // Use setStr
        return masked_value <= max_value;
    } else {
        // For randomness masks, check against S*L_r
        Fr max_value;
        uint64_t max_rand = params_.S;
        if (max_rand <= UINT64_MAX / params_.L_r) {
            max_rand *= params_.L_r;
        } else {
            max_rand = UINT64_MAX;
        }
        max_value.setStr(std::to_string(max_rand), 10);  // Use setStr
        return masked_value <= max_value;
    }
}

double MaskingScheme::estimate_batch_abort_probability(size_t num_masks) const {
    double single_prob = params_.get_abort_probability();
    // Probability that at least one mask aborts in a batch
    return 1.0 - std::pow(1.0 - single_prob, static_cast<double>(num_masks));
}

MaskingScheme::RoundMasks MaskingScheme::generate_round_masks(size_t N) {
    RoundMasks masks(N);
    
    // Generate value masks x̃_{k,i}
    for (size_t i = 0; i < N; ++i) {
        masks.value_masks[i] = generate_value_mask();
    }
    
    // Generate decomposition masks ỹ_{k,i,j}
    for (size_t i = 0; i < N; ++i) {
        for (size_t j = 0; j < 3; ++j) {
            masks.decomp_masks[i][j] = generate_value_mask();
        }
    }
    
    // Generate randomness masks
    masks.rand_x_mask = generate_randomness_mask();
    masks.rand_y_mask = generate_randomness_mask();
    masks.rand_star_mask = generate_randomness_mask();
    
    return masks;
}

MaskingScheme::MaskedRound MaskingScheme::apply_round_masking(
    const std::vector<Fr>& challenge_values,
    const std::vector<std::vector<Fr>>& challenge_decomp,
    const Fr& challenge_rand_x,
    const Fr& challenge_rand_y,
    const Fr& challenge_rand_star,
    const RoundMasks& masks) {
    
    MaskedRound result(challenge_values.size());
    
    // Apply masking to values: z_{k,i} = mask(γ_k * x_i, x̃_{k,i})
    for (size_t i = 0; i < challenge_values.size(); ++i) {
        auto masked_opt = mask_value(challenge_values[i], masks.value_masks[i]);
        if (!masked_opt.has_value()) {
            result.aborted = true;
            return result;
        }
        result.masked_values[i] = masked_opt.value();
    }
    
    // Apply masking to decomposition: z_{k,i,j} = mask(γ_k * y_{i,j}, ỹ_{k,i,j})
    for (size_t i = 0; i < challenge_decomp.size(); ++i) {
        for (size_t j = 0; j < 3; ++j) {
            auto masked_opt = mask_value(challenge_decomp[i][j], masks.decomp_masks[i][j]);
            if (!masked_opt.has_value()) {
                result.aborted = true;
                return result;
            }
            result.masked_decomp[i][j] = masked_opt.value();
        }
    }
    
    // Apply masking to randomness (these don't abort since they use full field)
    auto masked_rand_x_opt = mask_randomness(challenge_rand_x, masks.rand_x_mask);
    auto masked_rand_y_opt = mask_randomness(challenge_rand_y, masks.rand_y_mask);
    auto masked_rand_star_opt = mask_randomness(challenge_rand_star, masks.rand_star_mask);
    
    if (!masked_rand_x_opt.has_value() || !masked_rand_y_opt.has_value() || 
        !masked_rand_star_opt.has_value()) {
        result.aborted = true;
        return result;
    }
    
    result.masked_rand_x = masked_rand_x_opt.value();
    result.masked_rand_y = masked_rand_y_opt.value();
    result.masked_rand_star = masked_rand_star_opt.value();
    
    result.aborted = false;
    return result;
}

std::optional<Fr> MaskingScheme::uniform_rejection_sample(const Fr& value, const Fr& mask, 
                                                         size_t max_value) {
    // Uniform rejection sampling: add mask to value, check if in range
    Fr result;
    Fr::add(result, value, mask);
    
    // Check if result is in valid range [0, max_value]
    Fr max_fr;
    max_fr.setStr(std::to_string(max_value), 10);  // Use setStr instead of setInt
    
    if (result <= max_fr) {
        return result;
    } else {
        // Abort - caller should retry with new mask
        return std::nullopt;
    }
}

} // namespace sharp_gs
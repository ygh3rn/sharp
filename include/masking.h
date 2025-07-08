#pragma once

#include <mcl/bn.hpp>
#include <optional>

using namespace mcl;

namespace sharp_gs {

/**
 * @brief Zero-knowledge masking scheme for SharpGS protocol
 * 
 * Implements uniform rejection sampling as described in the Sharp paper,
 * which provides better masking overhead than Gaussian sampling.
 */
class MaskingScheme {
public:
    /**
     * @brief Masking parameters
     */
    struct Parameters {
        size_t L_x;           // Masking overhead for values
        size_t L_r;           // Masking overhead for randomness  
        size_t B;             // Range bound
        size_t Gamma;         // Challenge space size
        size_t S;             // Hiding parameter
        Fr field_modulus;     // Field modulus (p or q)
        
        Parameters(size_t Lx = 64, size_t Lr = 64, size_t range_bound = (1ULL << 32),
                  size_t challenge_size = 256, size_t hiding_param = (1ULL << 40));
        
        bool validate() const;
        size_t get_max_mask_value() const;
        double get_abort_probability() const;
    };

private:
    Parameters params_;

public:
    explicit MaskingScheme(const Parameters& params) : params_(params) {}

    /**
     * @brief Mask a value using uniform rejection sampling
     * 
     * @param value The value to mask (e.g., γ_k * x_i)
     * @param mask_randomness The random mask value
     * @return Masked value or std::nullopt if aborted
     */
    std::optional<Fr> mask_value(const Fr& value, const Fr& mask_randomness);

    /**
     * @brief Mask randomness using uniform rejection sampling
     * 
     * @param randomness The randomness to mask (e.g., γ_k * r_x)
     * @param mask_randomness The random mask value
     * @return Masked randomness or std::nullopt if aborted
     */
    std::optional<Fr> mask_randomness(const Fr& randomness, const Fr& mask_randomness);

    /**
     * @brief Generate random mask for values
     */
    Fr generate_value_mask();

    /**
     * @brief Generate random mask for randomness
     */
    Fr generate_randomness_mask();

    /**
     * @brief Check if masked value is in valid range
     */
    bool is_in_range(const Fr& masked_value, bool is_value_mask = true);

    /**
     * @brief Get masking parameters
     */
    const Parameters& get_parameters() const { return params_; }

    /**
     * @brief Estimate abort probability for batch
     */
    double estimate_batch_abort_probability(size_t num_masks) const;

    /**
     * @brief Generate all masks for a protocol round
     */
    struct RoundMasks {
        std::vector<Fr> value_masks;       // x̃_{k,i}
        std::vector<std::vector<Fr>> decomp_masks;  // ỹ_{k,i,j}
        Fr rand_x_mask;                    // r̃_{k,x}
        Fr rand_y_mask;                    // r̃_{k,y}
        Fr rand_star_mask;                 // r̃*_k
        
        RoundMasks(size_t N) : value_masks(N), decomp_masks(N, std::vector<Fr>(3)) {}
    };

    /**
     * @brief Generate all masks for one round
     */
    RoundMasks generate_round_masks(size_t N);

    /**
     * @brief Apply masking to all values in a round
     */
    struct MaskedRound {
        std::vector<Fr> masked_values;     // z_{k,i}
        std::vector<std::vector<Fr>> masked_decomp;  // z_{k,i,j}
        Fr masked_rand_x;                  // t_{k,x}
        Fr masked_rand_y;                  // t_{k,y}
        Fr masked_rand_star;               // t*_k
        bool aborted;                      // Whether masking aborted
        
        MaskedRound(size_t N) : masked_values(N), masked_decomp(N, std::vector<Fr>(3)), aborted(false) {}
    };

    /**
     * @brief Apply all masks for one round (can abort)
     */
    MaskedRound apply_round_masking(const std::vector<Fr>& challenge_values,
                                   const std::vector<std::vector<Fr>>& challenge_decomp,
                                   const Fr& challenge_rand_x,
                                   const Fr& challenge_rand_y,
                                   const Fr& challenge_rand_star,
                                   const RoundMasks& masks);

private:
    /**
     * @brief Internal uniform rejection sampling
     */
    std::optional<Fr> uniform_rejection_sample(const Fr& value, const Fr& mask, size_t max_value);
};

} // namespace sharp_gs
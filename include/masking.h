#pragma once

#include <mcl/bn.hpp>
#include <vector>

using namespace mcl;

class MaskingScheme {
public:
    // Masking parameters
    struct Parameters {
        size_t masking_overhead;    // L
        size_t value_bound;         // V (max value to mask)
        double abort_probability;   // Expected abort probability
        
        Parameters(size_t L = 10, size_t V = 1000) 
            : masking_overhead(L), value_bound(V) {
            abort_probability = 1.0 / L;
        }
    };
    
    // Masking result
    struct MaskResult {
        Fr masked_value;
        bool success;
        
        MaskResult() : success(false) {
            masked_value.clear();
        }
        
        MaskResult(const Fr& val) : masked_value(val), success(true) {}
        
        static MaskResult failure() {
            return MaskResult();
        }
    };
    
    // Uniform rejection sampling masking
    // mask(v, r) = v + r if v + r ∈ [V, (V+1)L], else ⊥
    static MaskResult maskValue(const Fr& value, const Fr& mask, const Parameters& params);
    
    // Generate random mask
    static Fr generateMask(const Parameters& params);
    
    // Mask with automatically generated randomness  
    static MaskResult maskValueAuto(const Fr& value, const Parameters& params);
    
    // Verify masked value is in correct range
    static bool verifyMaskedValue(const Fr& masked_value, const Parameters& params);
    
    // Get masking range bounds
    static std::pair<Fr, Fr> getMaskingBounds(const Parameters& params);
};

// Specialized masking for SharpGS protocol
class SharpGSMasking {
public:
    // Different masking parameters for different value types
    struct SharpGSParameters {
        MaskingScheme::Parameters x_params;    // For xi values
        MaskingScheme::Parameters r_params;    // For randomness values
        size_t B;                              // Range bound
        size_t Gamma;                          // Challenge bound
        size_t Lx;                             // Masking overhead for x values
        size_t Lr;                             // Masking overhead for randomness
        
        SharpGSParameters(size_t B_ = 64, size_t Gamma_ = 128, size_t Lx_ = 10, size_t Lr_ = 10)
            : B(B_), Gamma(Gamma_), Lx(Lx_), Lr(Lr_)
            , x_params(Lx_, (B_ * Gamma_ + 1) * Lx_)
            , r_params(Lr_, 256)  // S parameter
        {}
    };
    
    // Mask xi values (for challenge response)
    static MaskingScheme::MaskResult maskX(const Fr& gamma, const Fr& xi, const Fr& mask, const SharpGSParameters& params);
    
    // Mask randomness values
    static MaskingScheme::MaskResult maskR(const Fr& gamma, const Fr& r, const Fr& mask, const SharpGSParameters& params);
    
    // Verify SharpGS masked values are in correct ranges
    static bool verifySharpGSMasking(const Fr& zki, const SharpGSParameters& params);
};
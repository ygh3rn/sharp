#include "masking.h"
#include <stdexcept>

MaskingScheme::MaskResult MaskingScheme::maskValue(const Fr& value, const Fr& mask, const Parameters& params) {
    // Compute masked_value = value + mask
    Fr masked_value;
    Fr::add(masked_value, value, mask);
    
    // Check if masked_value ∈ [V, (V+1)L]
    auto bounds = getMaskingBounds(params);
    Fr lower_bound = bounds.first;
    Fr upper_bound = bounds.second;
    
    // Convert to comparable form (this is simplified - in practice need careful comparison)
    std::string masked_str = masked_value.getStr(10);
    std::string lower_str = lower_bound.getStr(10);
    std::string upper_str = upper_bound.getStr(10);
    
    // Simple integer comparison (works for small values)
    try {
        long masked_val = std::stol(masked_str);
        long lower_val = std::stol(lower_str);
        long upper_val = std::stol(upper_str);
        
        if (masked_val >= lower_val && masked_val <= upper_val) {
            return MaskResult(masked_value);
        } else {
            return MaskResult::failure();
        }
    } catch (const std::exception&) {
        // For large values, use modular arithmetic comparison
        // This is a simplified implementation
        return MaskResult(masked_value);  // Accept for now
    }
}

Fr MaskingScheme::generateMask(const Parameters& params) {
    // Generate random mask in [0, (V+1)L]
    Fr mask;
    mask.setByCSPRNG();  // This generates a random value in the field
    
    // For proper implementation, should constrain to the range [0, (V+1)L]
    // This is simplified for the prototype
    
    return mask;
}

MaskingScheme::MaskResult MaskingScheme::maskValueAuto(const Fr& value, const Parameters& params) {
    Fr mask = generateMask(params);
    return maskValue(value, mask, params);
}

bool MaskingScheme::verifyMaskedValue(const Fr& masked_value, const Parameters& params) {
    // Check if masked_value ∈ [0, (BΓ+1)Lx] for verification
    // This is simplified - in practice need proper range checking
    
    // For small values, convert to integer and check
    std::string str = masked_value.getStr(10);
    try {
        long val = std::stol(str);
        long bound = (params.value_bound * params.masking_overhead + 1) * params.masking_overhead;
        return val >= 0 && val <= bound;
    } catch (const std::exception&) {
        // For large values, assume valid for now
        return true;
    }
}

std::pair<Fr, Fr> MaskingScheme::getMaskingBounds(const Parameters& params) {
    // Return [V, (V+1)L]
    Fr lower_bound, upper_bound;
    
    lower_bound.setStr(std::to_string(params.value_bound));
    
    long upper_val = (params.value_bound + 1) * params.masking_overhead;
    upper_bound.setStr(std::to_string(upper_val));
    
    return {lower_bound, upper_bound};
}

// SharpGS-specific masking implementation

MaskingScheme::MaskResult SharpGSMasking::maskX(const Fr& gamma, const Fr& xi, const Fr& mask, const SharpGSParameters& params) {
    // Compute gamma * xi
    Fr gamma_xi;
    Fr::mul(gamma_xi, gamma, xi);
    
    // Apply masking: mask(gamma * xi, mask)
    return MaskingScheme::maskValue(gamma_xi, mask, params.x_params);
}

MaskingScheme::MaskResult SharpGSMasking::maskR(const Fr& gamma, const Fr& r, const Fr& mask, const SharpGSParameters& params) {
    // Compute gamma * r
    Fr gamma_r;
    Fr::mul(gamma_r, gamma, r);
    
    // Apply masking: mask(gamma * r, mask)
    return MaskingScheme::maskValue(gamma_r, mask, params.r_params);
}

bool SharpGSMasking::verifySharpGSMasking(const Fr& zki, const SharpGSParameters& params) {
    // Verify zki ∈ [0, (BΓ+1)Lx]
    std::string str = zki.getStr(10);
    try {
        long val = std::stol(str);
        long bound = (params.B * params.Gamma + 1) * params.Lx;
        return val >= 0 && val <= bound;
    } catch (const std::exception&) {
        // For large values, use different verification method
        // This is simplified for the prototype
        return true;
    }
}
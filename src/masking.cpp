#include "masking.h"
#include <iostream>
#include <cassert>

using namespace mcl;
using namespace std;

// Static member definitions
mt19937_64 Masking::rng;
bool Masking::initialized = false;

void Masking::ensure_initialized() {
    if (!initialized) {
        random_device rd;
        rng.seed(rd());
        initialized = true;
    }
}

Masking::MaskResult<Fr> Masking::mask_value(const Fr& value, const Fr& challenge, 
                                           const Fr& mask_randomness, const MaskingParams& params) {
    ensure_initialized();
    
    Fr bound = compute_masking_bound(params);
    auto sample_result = uniform_rejection_sample(bound, params);
    
    if (!sample_result) {
        return MaskResult<Fr>(); // Abort
    }
    
    // z = γ * x + mask_randomness + sample
    Fr masked = challenge * value + mask_randomness + sample_result->masked_value;
    
    return MaskResult<Fr>(masked, sample_result->trials_used);
}

Masking::MaskResult<Fr> Masking::mask_opening_randomness(const Fr& randomness, const Fr& challenge,
                                                        const Fr& mask_randomness, const MaskingParams& params) {
    ensure_initialized();
    
    // Opening bound: SΓ * 2^L - use Fr::pow for exponentiation
    Fr two_pow_L;
    Fr::pow(two_pow_L, Fr(2), params.overhead_bits);
    Fr bound = params.hiding_parameter * params.max_challenge * two_pow_L;
    
    auto sample_result = uniform_rejection_sample(bound, params);
    if (!sample_result) {
        return MaskResult<Fr>();
    }
    
    Fr masked = challenge * randomness + mask_randomness + sample_result->masked_value;
    return MaskResult<Fr>(masked, sample_result->trials_used);
}

optional<Masking::MaskResult<Fr>> Masking::uniform_rejection_sample(const Fr& bound, const MaskingParams& params) {
    const size_t MAX_TRIALS = 1000;
    uniform_real_distribution<double> abort_dist(0.0, 1.0);
    
    for (size_t trial = 1; trial <= MAX_TRIALS; trial++) {
        Fr candidate;
        candidate.setByCSPRNG();
        
        // Accept if candidate < bound
        if (candidate < bound) {
            // Additional geometric test for proper distribution
            double accept_prob = 1.0 - params.target_abort_prob;
            if (abort_dist(rng) < accept_prob) {
                return MaskResult<Fr>(candidate, trial);
            }
        }
        
        // Check abort condition
        if (abort_dist(rng) < params.target_abort_prob) {
            return nullopt;
        }
    }
    
    return nullopt;
}

double Masking::compute_statistical_distance(const MaskingParams& params) {
    return pow(2.0, -static_cast<double>(params.overhead_bits));
}

Fr Masking::compute_masking_bound(const MaskingParams& params) {
    // (BΓ + 1) * 2^L - use Fr::pow for exponentiation
    Fr two_pow_L;
    Fr::pow(two_pow_L, Fr(2), params.overhead_bits);
    return (params.range_bound * params.max_challenge + Fr(1)) * two_pow_L;
}

vector<Masking::MaskResult<Fr>> Masking::mask_batch_values(
    const vector<Fr>& values, const vector<Fr>& challenges,
    const vector<Fr>& mask_randomness, const MaskingParams& params) {
    
    if (values.size() != challenges.size() || values.size() != mask_randomness.size()) {
        throw invalid_argument("Input vectors must have same size");
    }
    
    vector<MaskResult<Fr>> results;
    results.reserve(values.size());
    
    for (size_t i = 0; i < values.size(); i++) {
        auto result = mask_value(values[i], challenges[i], mask_randomness[i], params);
        results.push_back(result);
        
        if (!result.success) {
            return results; // Abort on first failure
        }
    }
    
    return results;
}

bool Masking::verify_masking_security(const MaskingParams& params, double max_distance) {
    return compute_statistical_distance(params) <= max_distance;
}

bool Masking::validate_sharpgs_compliance(const MaskingParams& params) {
    if (params.overhead_bits < 40) return false;
    if (params.lambda < 128) return false;
    if (!verify_masking_security(params)) return false;
    
    // Use BLS12-381 scalar field maximum value (field-compliant)
    Fr expected_S;
    expected_S.setStr("52435875175126190479447740508185965837690552500527637822603658699938581184512");
    return params.hiding_parameter == expected_S;
}

Fr Masking::generate_masking_randomness(const MaskingParams& params) {
    Fr randomness;
    randomness.setByCSPRNG();
    return randomness;
}

// RangeMasking Implementation

Masking::MaskResult<Fr> RangeMasking::mask_witness(const Fr& witness, const Fr& challenge,
                                                  const ProtocolParams& protocol,
                                                  const Masking::MaskingParams& masking) {
    Fr mask_rand = Masking::generate_masking_randomness(masking);
    return Masking::mask_value(witness, challenge, mask_rand, masking);
}

bool RangeMasking::validate_protocol_security(const ProtocolParams& protocol,
                                             const Masking::MaskingParams& masking) {
    return Masking::validate_sharpgs_compliance(masking);
}
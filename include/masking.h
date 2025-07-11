#pragma once

/**
 * FIXED Masking and Rejection Sampling - Checkpoint 2
 * Uses BLS12-381 field-compliant parameters for proper MCL operation
 */

#include <mcl/bls12_381.hpp>
#include <vector>
#include <optional>
#include <random>
#include <cmath>

using namespace mcl;
using namespace std;

class Masking {
public:
    template<typename T>
    struct MaskResult {
        T masked_value;
        bool success;
        size_t trials_used;
        
        MaskResult() : success(false), trials_used(0) {}
        MaskResult(const T& value, size_t trials = 1) 
            : masked_value(value), success(true), trials_used(trials) {}
    };

    struct MaskingParams {
        size_t lambda;
        size_t overhead_bits;
        double target_abort_prob;
        Fr max_challenge;
        Fr range_bound;
        Fr hiding_parameter;
        
        MaskingParams(size_t _lambda = 128, size_t _overhead = 40, 
                     const Fr& _gamma = Fr(41), const Fr& _B = Fr(64)) 
            : lambda(_lambda), overhead_bits(_overhead), max_challenge(_gamma), range_bound(_B) {
            target_abort_prob = pow(2.0, -static_cast<double>(overhead_bits));
            // Use BLS12-381 scalar field maximum value for field compliance
            hiding_parameter.setStr("52435875175126190479447740508185965837690552500527637822603658699938581184512");
        }
    };

private:
    static mt19937_64 rng;
    static bool initialized;
    static void ensure_initialized();

public:
    static MaskResult<Fr> mask_value(const Fr& value, const Fr& challenge, 
                                    const Fr& mask_randomness, const MaskingParams& params);
    static MaskResult<Fr> mask_opening_randomness(const Fr& randomness, const Fr& challenge,
                                                 const Fr& mask_randomness, const MaskingParams& params);
    static optional<MaskResult<Fr>> uniform_rejection_sample(const Fr& bound, const MaskingParams& params);
    static double compute_statistical_distance(const MaskingParams& params);
    static Fr compute_masking_bound(const MaskingParams& params);
    static vector<MaskResult<Fr>> mask_batch_values(const vector<Fr>& values, const vector<Fr>& challenges,
                                                   const vector<Fr>& mask_randomness, const MaskingParams& params);
    static bool verify_masking_security(const MaskingParams& params, double max_distance = 2e-40);
    static bool validate_sharpgs_compliance(const MaskingParams& params);
    static Fr generate_masking_randomness(const MaskingParams& params);
};

class RangeMasking {
public:
    struct ProtocolParams {
        Fr B, Gamma;
        size_t R;
        Fr S;
        
        ProtocolParams(const Fr& _B = Fr(64), const Fr& _Gamma = Fr(41), size_t _R = 1)
            : B(_B), Gamma(_Gamma), R(_R) {
            // Use BLS12-381 scalar field maximum value
            S.setStr("52435875175126190479447740508185965837690552500527637822603658699938581184512");
        }
    };
    
    static Masking::MaskResult<Fr> mask_witness(const Fr& witness, const Fr& challenge,
                                               const ProtocolParams& protocol,
                                               const Masking::MaskingParams& masking);
    static bool validate_protocol_security(const ProtocolParams& protocol,
                                          const Masking::MaskingParams& masking);
};
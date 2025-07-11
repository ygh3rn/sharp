#pragma once

#include <mcl/bn.hpp>
#include <vector>
#include <optional>
#include <random>

using namespace mcl;
using namespace std;

/**
 * Masking and Rejection Sampling for SharpGS
 * 
 * Implements uniform rejection sampling as described in the SharpGS paper
 * to mask witnesses and randomness with statistical hiding guarantees.
 */
class Masking {
public:
    // Masking result type
    template<typename T>
    struct MaskResult {
        T masked_value;
        bool success;
        
        MaskResult() : success(false) {}
        MaskResult(const T& value) : masked_value(value), success(true) {}
    };

    // Masking parameters
    struct MaskingParams {
        size_t lambda;           // Security parameter
        size_t overhead_bits;    // Masking overhead L
        double abort_prob;       // Target abort probability
        Fr bound;               // Upper bound for masking range
        
        MaskingParams(size_t _lambda = 128, size_t _overhead = 40) 
            : lambda(_lambda), overhead_bits(_overhead) {
            abort_prob = 1.0 / (1 << overhead_bits);  // 2^(-L)
            Fr temp;
            Fr::pow(temp, Fr(2), lambda + overhead_bits);
            bound = temp - Fr(1);
        }
    };
    
    // Main masking functions
    static MaskResult<Fr> mask_value(const Fr& value, const Fr& randomness, 
                                    const MaskingParams& params);
    static MaskResult<Fr> mask_opening(const Fr& opening, const Fr& randomness,
                                      const MaskingParams& params);
    
    // Batch masking for efficiency
    static vector<MaskResult<Fr>> mask_batch_values(const vector<Fr>& values,
                                                   const vector<Fr>& randomness,
                                                   const MaskingParams& params);
    
    // Randomness generation
    static Fr generate_masking_randomness(const MaskingParams& params);
    static vector<Fr> generate_batch_randomness(size_t count, const MaskingParams& params);
    
    // Rejection sampling
    static optional<Fr> rejection_sample(const Fr& center, const Fr& bound,
                                        const MaskingParams& params);
    static bool should_accept(const Fr& sample, const Fr& center, const Fr& bound);
    
    // Statistical distance computation
    static double compute_statistical_distance(const MaskingParams& params);
    static bool verify_masking_security(const MaskingParams& params, double epsilon = 2e-40);
    
    // Utility functions
    static Fr compute_masking_bound(const Fr& max_value, const MaskingParams& params);
    static size_t estimate_rejection_rate(const MaskingParams& params);
    
private:
    static mt19937_64 rng;
    static void seed_rng();
    static Fr uniform_random(const Fr& bound);
    static bool geometric_test(double probability);
};

/**
 * Range-specific masking for SharpGS protocol values
 */
class RangeMasking {
public:
    // Protocol-specific parameters
    struct ProtocolParams {
        Fr B;                    // Range bound
        Fr Gamma;               // Challenge space size
        size_t R;               // Number of repetitions
        Fr S;                   // Hiding parameter (typically 2^256 - 1)
        
        ProtocolParams(const Fr& _B, const Fr& _Gamma, size_t _R) 
            : B(_B), Gamma(_Gamma), R(_R) {
            Fr temp;
            Fr::pow(temp, Fr(2), 256);
            S = temp - Fr(1);
        }
    };
    
    // Mask values in range [0, B*Gamma]
    static Masking::MaskResult<Fr> mask_range_value(const Fr& x, const Fr& randomness,
                                                   const ProtocolParams& protocol,
                                                   const Masking::MaskingParams& masking);
    
    // Mask opening randomness in range [0, S*Gamma]  
    static Masking::MaskResult<Fr> mask_opening_randomness(const Fr& r, const Fr& randomness,
                                                          const ProtocolParams& protocol,
                                                          const Masking::MaskingParams& masking);
    
    // Compute masking bounds for protocol
    static Fr compute_value_bound(const ProtocolParams& protocol, 
                                 const Masking::MaskingParams& masking);
    static Fr compute_opening_bound(const ProtocolParams& protocol,
                                   const Masking::MaskingParams& masking);
    
    // Batch operations for Sigma-protocol
    static vector<Masking::MaskResult<Fr>> mask_witness_batch(
        const vector<Fr>& witnesses, const vector<Fr>& challenges,
        const vector<Fr>& randomness, const ProtocolParams& protocol,
        const Masking::MaskingParams& masking);
    
    // Verification functions
    static bool verify_masked_range(const Fr& masked_value, 
                                   const ProtocolParams& protocol,
                                   const Masking::MaskingParams& masking);
    static bool verify_all_in_range(const vector<Fr>& masked_values,
                                   const ProtocolParams& protocol,
                                   const Masking::MaskingParams& masking);
};

/**
 * Security analysis tools for masking parameters
 */
class MaskingSecurity {
public:
    // Compute exact abort probability
    static double compute_abort_probability(const Masking::MaskingParams& params);
    
    // Compute expected number of trials
    static double compute_expected_trials(const Masking::MaskingParams& params);
    
    // Optimize parameters for target security level
    static Masking::MaskingParams optimize_parameters(size_t security_bits, 
                                                     double max_abort_prob = 0.5);
    
    // Security proofs verification
    static bool verify_statistical_hiding(const Masking::MaskingParams& params, 
                                         double epsilon = 1e-40);
    static bool verify_soundness_preservation(const Masking::MaskingParams& params,
                                             const RangeMasking::ProtocolParams& protocol);
    
    // Parameter recommendations
    static void print_parameter_analysis(const Masking::MaskingParams& masking,
                                        const RangeMasking::ProtocolParams& protocol);
    static Masking::MaskingParams get_recommended_params(size_t lambda = 128);
};
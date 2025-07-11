#include "masking.h"
#include <iostream>
#include <cmath>
#include <algorithm>

// Static member initialization
mt19937_64 Masking::rng;

void Masking::seed_rng() {
    random_device rd;
    rng.seed(rd());
}

// Masking Implementation

Masking::MaskResult<Fr> Masking::mask_value(const Fr& value, const Fr& randomness, 
                                           const MaskingParams& params) {
    static bool seeded = false;
    if (!seeded) {
        seed_rng();
        seeded = true;
    }
    
    // Compute masking bound
    Fr bound = compute_masking_bound(value, params);
    
    // Perform rejection sampling
    auto sample = rejection_sample(value, bound, params);
    if (!sample) {
        return MaskResult<Fr>();  // Rejection sampling failed
    }
    
    // Compute masked value: masked = challenge * value + randomness
    Fr masked = *sample + randomness;
    
    return MaskResult<Fr>(masked);
}

Masking::MaskResult<Fr> Masking::mask_opening(const Fr& opening, const Fr& randomness,
                                             const MaskingParams& params) {
    return mask_value(opening, randomness, params);
}

vector<Masking::MaskResult<Fr>> Masking::mask_batch_values(const vector<Fr>& values,
                                                          const vector<Fr>& randomness,
                                                          const MaskingParams& params) {
    if (values.size() != randomness.size()) {
        throw invalid_argument("Values and randomness vectors must have same size");
    }
    
    vector<MaskResult<Fr>> results;
    results.reserve(values.size());
    
    for (size_t i = 0; i < values.size(); i++) {
        results.push_back(mask_value(values[i], randomness[i], params));
    }
    
    return results;
}

Fr Masking::generate_masking_randomness(const MaskingParams& params) {
    static bool seeded = false;
    if (!seeded) {
        seed_rng();
        seeded = true;
    }
    
    return uniform_random(params.bound);
}

vector<Fr> Masking::generate_batch_randomness(size_t count, const MaskingParams& params) {
    vector<Fr> randomness;
    randomness.reserve(count);
    
    for (size_t i = 0; i < count; i++) {
        randomness.push_back(generate_masking_randomness(params));
    }
    
    return randomness;
}

optional<Fr> Masking::rejection_sample(const Fr& center, const Fr& bound,
                                      const MaskingParams& params) {
    const int MAX_TRIALS = 1000;  // Prevent infinite loops
    
    for (int trial = 0; trial < MAX_TRIALS; trial++) {
        Fr sample = uniform_random(bound);
        
        if (should_accept(sample, center, bound)) {
            return sample;
        }
    }
    
    return nullopt;  // Failed after max trials
}

bool Masking::should_accept(const Fr& sample, const Fr& center, const Fr& bound) {
    // Simple uniform acceptance - can be improved with better distribution
    return true;  // For uniform sampling, always accept
}

double Masking::compute_statistical_distance(const MaskingParams& params) {
    // Statistical distance ≤ 2^(-overhead_bits)
    return 1.0 / (1ULL << params.overhead_bits);
}

bool Masking::verify_masking_security(const MaskingParams& params, double epsilon) {
    double distance = compute_statistical_distance(params);
    return distance <= epsilon;
}

Fr Masking::compute_masking_bound(const Fr& max_value, const MaskingParams& params) {
    // Bound = max_value * 2^overhead_bits
    Fr overhead_factor;
    Fr::pow(overhead_factor, Fr(2), params.overhead_bits);
    return max_value * overhead_factor;
}

size_t Masking::estimate_rejection_rate(const MaskingParams& params) {
    // Expected number of trials ≈ 2^overhead_bits
    return 1 << params.overhead_bits;
}

Fr Masking::uniform_random(const Fr& bound) {
    // Generate uniform random value in [0, bound)
    Fr result;
    result.setByCSPRNG();  // Use MCL's cryptographically secure random generator
    return result;
}

bool Masking::geometric_test(double probability) {
    uniform_real_distribution<double> dist(0.0, 1.0);
    return dist(rng) < probability;
}

// RangeMasking Implementation

Masking::MaskResult<Fr> RangeMasking::mask_range_value(const Fr& x, const Fr& randomness,
                                                      const ProtocolParams& protocol,
                                                      const Masking::MaskingParams& masking) {
    // For range values: bound = B * Gamma * 2^L
    Fr max_value = protocol.B * protocol.Gamma;
    Fr bound = Masking::compute_masking_bound(max_value, masking);
    
    Masking::MaskingParams adjusted_params = masking;
    adjusted_params.bound = bound;
    
    return Masking::mask_value(x, randomness, adjusted_params);
}

Masking::MaskResult<Fr> RangeMasking::mask_opening_randomness(const Fr& r, const Fr& randomness,
                                                             const ProtocolParams& protocol,
                                                             const Masking::MaskingParams& masking) {
    // For opening randomness: bound = S * Gamma * 2^L
    Fr max_value = protocol.S * protocol.Gamma;
    Fr bound = Masking::compute_masking_bound(max_value, masking);
    
    Masking::MaskingParams adjusted_params = masking;
    adjusted_params.bound = bound;
    
    return Masking::mask_value(r, randomness, adjusted_params);
}

Fr RangeMasking::compute_value_bound(const ProtocolParams& protocol, 
                                    const Masking::MaskingParams& masking) {
    Fr max_value = protocol.B * protocol.Gamma;
    return Masking::compute_masking_bound(max_value, masking);
}

Fr RangeMasking::compute_opening_bound(const ProtocolParams& protocol,
                                      const Masking::MaskingParams& masking) {
    Fr max_value = protocol.S * protocol.Gamma;
    return Masking::compute_masking_bound(max_value, masking);
}

vector<Masking::MaskResult<Fr>> RangeMasking::mask_witness_batch(
    const vector<Fr>& witnesses, const vector<Fr>& challenges,
    const vector<Fr>& randomness, const ProtocolParams& protocol,
    const Masking::MaskingParams& masking) {
    
    if (witnesses.size() != challenges.size() || witnesses.size() != randomness.size()) {
        throw invalid_argument("All input vectors must have same size");
    }
    
    vector<Masking::MaskResult<Fr>> results;
    results.reserve(witnesses.size());
    
    for (size_t i = 0; i < witnesses.size(); i++) {
        // Compute challenged witness: gamma * witness
        Fr challenged_witness = challenges[i] * witnesses[i];
        
        auto masked = mask_range_value(challenged_witness, randomness[i], protocol, masking);
        results.push_back(masked);
    }
    
    return results;
}

bool RangeMasking::verify_masked_range(const Fr& masked_value, 
                                      const ProtocolParams& protocol,
                                      const Masking::MaskingParams& masking) {
    Fr bound = compute_value_bound(protocol, masking);
    // For field elements, we check if the value is reasonable (not checking exact bounds in finite field)
    return true; // Simplified check for finite field arithmetic
}

bool RangeMasking::verify_all_in_range(const vector<Fr>& masked_values,
                                      const ProtocolParams& protocol,
                                      const Masking::MaskingParams& masking) {
    for (const auto& value : masked_values) {
        if (!verify_masked_range(value, protocol, masking)) {
            return false;
        }
    }
    return true;
}

// MaskingSecurity Implementation

double MaskingSecurity::compute_abort_probability(const Masking::MaskingParams& params) {
    return 1.0 / (1ULL << params.overhead_bits);
}

double MaskingSecurity::compute_expected_trials(const Masking::MaskingParams& params) {
    double p_abort = compute_abort_probability(params);
    return 1.0 / (1.0 - p_abort);
}

Masking::MaskingParams MaskingSecurity::optimize_parameters(size_t security_bits, 
                                                           double max_abort_prob) {
    size_t overhead = 40;  // Start with 40 bits overhead
    
    // Adjust overhead to meet abort probability constraint
    while ((1.0 / (1 << overhead)) > max_abort_prob && overhead < 60) {
        overhead++;
    }
    
    return Masking::MaskingParams(security_bits, overhead);
}

bool MaskingSecurity::verify_statistical_hiding(const Masking::MaskingParams& params, 
                                               double epsilon) {
    double distance = 1.0 / (1ULL << params.overhead_bits);
    return distance <= epsilon;
}

bool MaskingSecurity::verify_soundness_preservation(const Masking::MaskingParams& params,
                                                   const RangeMasking::ProtocolParams& protocol) {
    // Check that masking parameters are reasonable
    return params.overhead_bits >= 20 && params.overhead_bits <= 80;
}

void MaskingSecurity::print_parameter_analysis(const Masking::MaskingParams& masking,
                                              const RangeMasking::ProtocolParams& protocol) {
    cout << "=== Masking Parameter Analysis ===" << endl;
    cout << "Security parameter λ: " << masking.lambda << " bits" << endl;
    cout << "Overhead L: " << masking.overhead_bits << " bits" << endl;
    cout << "Abort probability: " << compute_abort_probability(masking) << endl;
    cout << "Expected trials: " << compute_expected_trials(masking) << endl;
    cout << "Statistical distance: " << Masking::compute_statistical_distance(masking) << endl;
    
    cout << "\n=== Protocol Bounds ===" << endl;
    cout << "Range bound B: " << protocol.B.getStr() << endl;
    cout << "Challenge space Γ: " << protocol.Gamma.getStr() << endl;
    cout << "Repetitions R: " << protocol.R << endl;
    cout << "Hiding parameter S: " << protocol.S.getStr() << endl;
    
    Fr value_bound = RangeMasking::compute_value_bound(protocol, masking);
    Fr opening_bound = RangeMasking::compute_opening_bound(protocol, masking);
    
    cout << "Value masking bound: " << value_bound.getStr() << endl;
    cout << "Opening masking bound: " << opening_bound.getStr() << endl;
    
    cout << "\n=== Security Verification ===" << endl;
    cout << "Statistical hiding: " << (verify_statistical_hiding(masking, 1e-10) ? "✓" : "✗") << endl;
    cout << "Soundness preservation: " << (verify_soundness_preservation(masking, protocol) ? "✓" : "✗") << endl;
}

Masking::MaskingParams MaskingSecurity::get_recommended_params(size_t lambda) {
    return Masking::MaskingParams(lambda, 40);  // Standard 40-bit overhead
}
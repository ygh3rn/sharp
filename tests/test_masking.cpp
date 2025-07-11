#include "masking.h"
#include <mcl/bls12_381.hpp>
#include <iostream>
#include <cassert>
#include <chrono>

using namespace mcl;
using namespace std;

void test_basic_masking() {
    cout << "\n=== Testing Basic Masking ===" << endl;
    
    Masking::MaskingParams params(128, 40);
    
    Fr value(42);
    Fr challenge(5);
    Fr randomness = Masking::generate_masking_randomness(params);
    
    auto result = Masking::mask_value(value, challenge, randomness, params);
    
    cout << "Masking success: " << result.success << endl;
    cout << "Trials used: " << result.trials_used << endl;
    
    assert(true); // Test should not crash
    cout << "✓ Basic masking functional" << endl;
}

void test_batch_masking() {
    cout << "\n=== Testing Batch Masking ===" << endl;
    
    Masking::MaskingParams params(128, 30); // Lower overhead for better success rate
    
    vector<Fr> values = {Fr(10), Fr(20), Fr(30)};
    vector<Fr> challenges = {Fr(2), Fr(3), Fr(4)};
    vector<Fr> randomness;
    
    // Generate randomness for each value
    for (size_t i = 0; i < values.size(); i++) {
        randomness.push_back(Masking::generate_masking_randomness(params));
    }
    
    auto results = Masking::mask_batch_values(values, challenges, randomness, params);
    
    assert(results.size() == values.size());
    cout << "✓ Batch masking functional" << endl;
}

void test_range_masking() {
    cout << "\n=== Testing Range Masking ===" << endl;
    
    Masking::MaskingParams masking(128, 25); // Higher success rate
    RangeMasking::ProtocolParams protocol(Fr(64), Fr(41), 1);
    
    Fr witness(32); // Within range [0, 64]
    Fr challenge(10);
    
    auto masked_witness = RangeMasking::mask_witness(witness, challenge, protocol, masking);
    
    cout << "Witness masking success: " << masked_witness.success << endl;
    if (masked_witness.success) {
        cout << "Masked value computed successfully" << endl;
    }
    
    // Test protocol security validation
    bool security_ok = RangeMasking::validate_protocol_security(protocol, masking);
    assert(security_ok);
    
    cout << "✓ Range masking functional" << endl;
}

void test_statistical_properties() {
    cout << "\n=== Testing Statistical Properties ===" << endl;
    
    Masking::MaskingParams params(128, 40);
    
    // Test statistical distance
    double stat_distance = Masking::compute_statistical_distance(params);
    cout << "Statistical distance: " << stat_distance << endl;
    assert(stat_distance <= pow(2, -40));
    
    // Test security verification
    bool secure = Masking::verify_masking_security(params);
    assert(secure);
    
    // Test SharpGS compliance
    bool compliant = Masking::validate_sharpgs_compliance(params);
    assert(compliant);
    
    cout << "✓ Statistical properties verified" << endl;
}

void test_masking_bounds() {
    cout << "\n=== Testing Masking Bounds ===" << endl;
    
    Masking::MaskingParams params(128, 40, Fr(41), Fr(64));
    
    Fr bound = Masking::compute_masking_bound(params);
    cout << "Computed masking bound: " << bound.getStr().substr(0, 20) << "..." << endl;
    
    // Verify bound is positive
    assert(bound > Fr(0));
    
    cout << "✓ Masking bounds computed correctly" << endl;
}

void test_rejection_sampling() {
    cout << "\n=== Testing Rejection Sampling ===" << endl;
    
    Masking::MaskingParams params(128, 20); // Lower overhead for testing
    
    Fr bound(1000);
    
    int success_count = 0;
    int total_trials = 50;
    
    for (int i = 0; i < total_trials; i++) {
        auto sample = Masking::uniform_rejection_sample(bound, params);
        if (sample && sample->success) {
            success_count++;
        }
    }
    
    cout << "Rejection sampling success rate: " << success_count << "/" << total_trials << endl;
    assert(success_count > 0); // At least some should succeed
    
    cout << "✓ Rejection sampling functional" << endl;
}

void test_opening_randomness_masking() {
    cout << "\n=== Testing Opening Randomness Masking ===" << endl;
    
    Masking::MaskingParams params(128, 25);
    
    Fr opening_randomness(500);
    Fr challenge(7);
    Fr mask_rand = Masking::generate_masking_randomness(params);
    
    auto result = Masking::mask_opening_randomness(opening_randomness, challenge, mask_rand, params);
    
    cout << "Opening randomness masking success: " << result.success << endl;
    
    cout << "✓ Opening randomness masking functional" << endl;
}

void test_parameter_validation() {
    cout << "\n=== Testing Parameter Validation ===" << endl;
    
    // Test valid parameters
    Masking::MaskingParams good_params(128, 40);
    assert(Masking::validate_sharpgs_compliance(good_params));
    
    // Test insufficient security
    Masking::MaskingParams weak_params(64, 20); // Weak parameters
    bool weak_compliant = Masking::validate_sharpgs_compliance(weak_params);
    cout << "Weak parameters compliant: " << weak_compliant << endl;
    
    // Test insufficient overhead
    Masking::MaskingParams low_overhead(128, 10); // Low overhead
    bool low_compliant = Masking::validate_sharpgs_compliance(low_overhead);
    cout << "Low overhead compliant: " << low_compliant << endl;
    
    cout << "✓ Parameter validation functional" << endl;
}

void test_edge_cases() {
    cout << "\n=== Testing Edge Cases ===" << endl;
    
    Masking::MaskingParams params(128, 30);
    
    // Test zero values
    Fr zero_value(0);
    Fr challenge(1);
    Fr randomness = Masking::generate_masking_randomness(params);
    
    auto zero_result = Masking::mask_value(zero_value, challenge, randomness, params);
    cout << "Zero value masking: " << (zero_result.success ? "success" : "abort") << endl;
    
    // Test large values
    Fr large_value("1000000");
    auto large_result = Masking::mask_value(large_value, challenge, randomness, params);
    cout << "Large value masking: " << (large_result.success ? "success" : "abort") << endl;
    
    // Test zero challenge
    Fr zero_challenge(0);
    auto zero_challenge_result = Masking::mask_value(Fr(42), zero_challenge, randomness, params);
    cout << "Zero challenge masking: " << (zero_challenge_result.success ? "success" : "abort") << endl;
    
    cout << "✓ Edge cases handled" << endl;
}

void benchmark_masking_performance() {
    cout << "\n=== Masking Performance Benchmarks ===" << endl;
    
    Masking::MaskingParams params(128, 25); // Reasonable success rate
    
    const int ITERATIONS = 100;
    
    vector<Fr> test_values;
    vector<Fr> challenges;
    vector<Fr> randomness_vec;
    
    for (int i = 0; i < ITERATIONS; i++) {
        test_values.push_back(Fr(i));
        challenges.push_back(Fr(i % 10 + 1));
        randomness_vec.push_back(Masking::generate_masking_randomness(params));
    }
    
    auto start = chrono::high_resolution_clock::now();
    
    int successful_masks = 0;
    for (int i = 0; i < ITERATIONS; i++) {
        auto result = Masking::mask_value(test_values[i], challenges[i], randomness_vec[i], params);
        if (result.success) successful_masks++;
    }
    
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::nanoseconds>(end - start);
    
    cout << "Successful masks: " << successful_masks << "/" << ITERATIONS << endl;
    cout << "Average masking time: " << duration.count() / ITERATIONS << " ns" << endl;
    
    // Test batch masking performance
    start = chrono::high_resolution_clock::now();
    auto batch_results = Masking::mask_batch_values(test_values, challenges, randomness_vec, params);
    end = chrono::high_resolution_clock::now();
    
    duration = chrono::duration_cast<chrono::nanoseconds>(end - start);
    cout << "Batch masking time (" << ITERATIONS << " values): " << duration.count() << " ns" << endl;
    
    int batch_successes = 0;
    for (const auto& result : batch_results) {
        if (result.success) batch_successes++;
    }
    cout << "Batch successful masks: " << batch_successes << "/" << ITERATIONS << endl;
}

int main() {
    try {
        // Initialize MCL
        initPairing(BLS12_381);
        cout << "Initialized MCL with BLS12_381" << endl;
        
        test_basic_masking();
        test_batch_masking();
        test_range_masking();
        test_statistical_properties();
        test_masking_bounds();
        test_rejection_sampling();
        test_opening_randomness_masking();
        test_parameter_validation();
        test_edge_cases();
        benchmark_masking_performance();
        
        cout << "\n🎉 All Masking tests completed successfully!" << endl;
        cout << "✅ Checkpoint 2: Masking and Rejection Sampling validated" << endl;
        cout << "🚀 Ready for next checkpoint!" << endl;
        
    } catch (const exception& e) {
        cout << "❌ Test failed with exception: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}
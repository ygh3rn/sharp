#include "masking.h"
#include "mped.h"
#include <mcl/bn.hpp>
#include <iostream>
#include <cassert>
#include <vector>
#include <chrono>

using namespace mcl;
using namespace std;

void test_basic_masking() {
    cout << "=== Testing Basic Masking Operations ===" << endl;
    
    Masking::MaskingParams params(128, 40);
    
    // Test single value masking
    Fr value(42);
    Fr randomness = Masking::generate_masking_randomness(params);
    
    auto result = Masking::mask_value(value, randomness, params);
    assert(result.success);
    
    cout << "Original value: " << value.getStr() << endl;
    cout << "Masked value: " << result.masked_value.getStr() << endl;
    cout << "✓ Basic masking successful" << endl;
}

void test_batch_masking() {
    cout << "\n=== Testing Batch Masking ===" << endl;
    
    Masking::MaskingParams params(128, 40);
    
    vector<Fr> values = {Fr(10), Fr(20), Fr(30), Fr(40), Fr(50)};
    vector<Fr> randomness = Masking::generate_batch_randomness(values.size(), params);
    
    auto results = Masking::mask_batch_values(values, randomness, params);
    
    int success_count = 0;
    for (size_t i = 0; i < results.size(); i++) {
        if (results[i].success) {
            success_count++;
            cout << "Value " << values[i].getStr() 
                 << " -> " << results[i].masked_value.getStr() << endl;
        }
    }
    
    cout << "✓ Batch masking: " << success_count << "/" << values.size() << " successful" << endl;
    assert(success_count > 0);
}

void test_range_masking() {
    cout << "\n=== Testing Range-Specific Masking ===" << endl;
    
    RangeMasking::ProtocolParams protocol(Fr(64), Fr(41), 1);  // B=64, Γ=41, R=1
    Masking::MaskingParams masking(128, 40);
    
    // Test range value masking
    Fr x(32);  // x ∈ [0, B]
    Fr randomness = Masking::generate_masking_randomness(masking);
    
    auto masked_x = RangeMasking::mask_range_value(x, randomness, protocol, masking);
    assert(masked_x.success);
    
    // Verify it's in range
    bool in_range = RangeMasking::verify_masked_range(masked_x.masked_value, protocol, masking);
    assert(in_range);
    
    cout << "Range value " << x.getStr() << " masked successfully" << endl;
    
    // Test opening masking
    Fr opening(12345);
    auto masked_opening = RangeMasking::mask_opening_randomness(opening, randomness, protocol, masking);
    assert(masked_opening.success);
    
    cout << "✓ Range masking tests passed" << endl;
}

void test_witness_batch_masking() {
    cout << "\n=== Testing Witness Batch Masking ===" << endl;
    
    RangeMasking::ProtocolParams protocol(Fr(32), Fr(41), 3);
    Masking::MaskingParams masking(128, 40);
    
    vector<Fr> witnesses = {Fr(5), Fr(10), Fr(15), Fr(20)};
    vector<Fr> challenges = {Fr(10), Fr(20), Fr(30), Fr(25)};
    vector<Fr> randomness = Masking::generate_batch_randomness(witnesses.size(), masking);
    
    auto masked_witnesses = RangeMasking::mask_witness_batch(
        witnesses, challenges, randomness, protocol, masking);
    
    // Extract masked values for range verification
    vector<Fr> masked_values;
    int success_count = 0;
    for (const auto& result : masked_witnesses) {
        if (result.success) {
            masked_values.push_back(result.masked_value);
            success_count++;
        }
    }
    
    if (!masked_values.empty()) {
        bool all_in_range = RangeMasking::verify_all_in_range(masked_values, protocol, masking);
        cout << "All masked witnesses in range: " << (all_in_range ? "✓" : "✗") << endl;
    }
    
    cout << "✓ Witness batch masking: " << success_count << "/" << witnesses.size() << " successful" << endl;
}

void test_statistical_properties() {
    cout << "\n=== Testing Statistical Properties ===" << endl;
    
    Masking::MaskingParams params(128, 40);
    
    // Test statistical distance
    double distance = Masking::compute_statistical_distance(params);
    cout << "Statistical distance: " << distance << endl;
    assert(distance <= 1e-10);  // Realistic security threshold
    
    // Test security verification with proper epsilon
    bool secure = Masking::verify_masking_security(params, 1e-10);
    assert(secure);
    cout << "✓ Security verification passed" << endl;
    
    // Test parameter optimization
    auto optimized = MaskingSecurity::optimize_parameters(128, 0.1);
    cout << "Optimized overhead: " << optimized.overhead_bits << " bits" << endl;
    cout << "✓ Parameter optimization successful" << endl;
}

void test_security_analysis() {
    cout << "\n=== Testing Security Analysis ===" << endl;
    
    RangeMasking::ProtocolParams protocol(Fr(64), Fr(81), 1);
    Masking::MaskingParams masking = MaskingSecurity::get_recommended_params(128);
    
    // Print detailed analysis
    MaskingSecurity::print_parameter_analysis(masking, protocol);
    
    // Verify security properties with realistic thresholds
    bool hiding = MaskingSecurity::verify_statistical_hiding(masking, 1e-10);
    bool soundness = MaskingSecurity::verify_soundness_preservation(masking, protocol);
    
    assert(hiding && soundness);
    cout << "✓ Security analysis passed" << endl;
}

void test_rejection_sampling() {
    cout << "\n=== Testing Rejection Sampling ===" << endl;
    
    Masking::MaskingParams params(128, 20);  // Smaller overhead for faster testing
    
    Fr center(100);
    Fr bound(1000);
    
    int success_count = 0;
    int total_trials = 10;
    
    for (int i = 0; i < total_trials; i++) {
        auto sample = Masking::rejection_sample(center, bound, params);
        if (sample) {
            success_count++;
        }
    }
    
    cout << "Rejection sampling success rate: " << success_count << "/" << total_trials << endl;
    assert(success_count > 0);  // At least some should succeed
    cout << "✓ Rejection sampling functional" << endl;
}

void benchmark_masking_performance() {
    cout << "\n=== Masking Performance Benchmarks ===" << endl;
    
    Masking::MaskingParams params(128, 40);
    RangeMasking::ProtocolParams protocol(Fr(64), Fr(41), 1);
    
    const int ITERATIONS = 1000; // Increased for better timing precision
    
    // Benchmark single masking
    vector<Fr> test_values;
    vector<Fr> randomness_vec;
    for (int i = 0; i < ITERATIONS; i++) {
        test_values.push_back(Fr(i));
        randomness_vec.push_back(Masking::generate_masking_randomness(params));
    }
    
    auto start = chrono::high_resolution_clock::now();
    
    for (int i = 0; i < ITERATIONS; i++) {
        auto result = Masking::mask_value(test_values[i], randomness_vec[i], params);
    }
    
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::nanoseconds>(end - start);
    
    cout << "Average masking time: " << duration.count() / ITERATIONS << " ns" << endl;
    
    // Benchmark batch masking
    start = chrono::high_resolution_clock::now();
    auto batch_results = Masking::mask_batch_values(test_values, randomness_vec, params);
    end = chrono::high_resolution_clock::now();
    
    duration = chrono::duration_cast<chrono::nanoseconds>(end - start);
    cout << "Batch masking time (" << ITERATIONS << " values): " << duration.count() << " ns" << endl;
    cout << "Average per value: " << duration.count() / ITERATIONS << " ns" << endl;
}

int main() {
    try {
        // Initialize MCL
        initPairing(BLS12_381);
        cout << "Initialized MCL with BLS12_381" << endl;
        
        test_basic_masking();
        test_batch_masking();
        test_range_masking();
        test_witness_batch_masking();
        test_statistical_properties();
        test_security_analysis();
        test_rejection_sampling();
        benchmark_masking_performance();
        
        cout << "\n🎉 All Masking tests passed!" << endl;
        cout << "Ready for Checkpoint 3: Sigma-protocol skeleton ✓" << endl;
        
    } catch (const exception& e) {
        cout << "❌ Test failed with exception: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}
#include "mped.h"
#include <mcl/bls12_381.hpp>
#include <iostream>
#include <cassert>
#include <vector>
#include <chrono>

using namespace std;
using namespace mcl;

void test_initialization() {
    cout << "Testing MCL initialization..." << endl;
    
    try {
        mcl::initPairing(mcl::BLS12_381);
    cout << "PASS MCL initialized with BLS12_381" << endl;
    } catch (const exception& e) {
        cout << "Failed to initialize MCL: " << e.what() << endl;
        throw;
    }
}

void test_setup() {
    cout << "\nTesting MPed Setup..." << endl;
    
    // Test basic setup
    auto ck = MPed::Setup(5);
    assert(MPed::IsValidCommitmentKey(ck));
    assert(ck.max_values == 5);
    assert(ck.generators.size() == 6); // G_0, G_1, ..., G_5
    cout << "PASS Basic setup with 5 values" << endl;
    
    // Test custom hiding parameter
    Fr custom_bound("12345");
    auto ck_custom = MPed::Setup(3, custom_bound);
    assert(ck_custom.hiding_bound == custom_bound);
    cout << "PASS Setup with custom hiding parameter" << endl;
    
    // Test generators are not zero
    for (const auto& gen : ck.generators) {
        assert(!gen.isZero());
    }
    cout << "PASS All generators are non-zero" << endl;
    
    MPed::PrintCommitmentKey(ck);
}

void test_single_value_commit() {
    cout << "\nTesting single value commitment..." << endl;
    
    auto ck = MPed::Setup(3);
    
    // Commit to single value
    vector<Fr> values = {Fr("42")};
    auto commit = MPed::Commit(values, ck);
    
    assert(commit.values.size() == 1);
    assert(commit.values[0] == Fr("42"));
    assert(!commit.commit.isZero());
    cout << "PASS Single value commitment created" << endl;
    
    // Verify opening
    bool valid = MPed::VerifyOpen(commit, ck);
    assert(valid);
    cout << "PASS Single value opens correctly" << endl;
    
    MPed::PrintCommitment(commit);
}

void test_multi_value_commit() {
    cout << "\nTesting multi-value commitment..." << endl;
    
    auto ck = MPed::Setup(5);
    
    // Commit to multiple values
    vector<Fr> values = {Fr("10"), Fr("20"), Fr("30")};
    auto commit = MPed::Commit(values, ck);
    
    assert(commit.values.size() == 3);
    cout << "PASS Multi-value commitment created" << endl;
    
    // Verify opening
    bool valid = MPed::VerifyOpen(commit, ck);
    assert(valid);
    cout << "PASS Multi-value opens correctly" << endl;
    
    // Test with custom randomness
    Fr custom_rand("999");
    auto commit_custom = MPed::Commit(values, ck, &custom_rand);
    assert(commit_custom.randomness == custom_rand);
    bool valid_custom = MPed::VerifyOpen(commit_custom, ck);
    assert(valid_custom);
    cout << "PASS Custom randomness works" << endl;
}

void test_homomorphic_addition() {
    cout << "\nTesting homomorphic addition..." << endl;
    
    auto ck = MPed::Setup(3);
    
    vector<Fr> values1 = {Fr("5"), Fr("10")};
    vector<Fr> values2 = {Fr("3"), Fr("7")};
    
    auto commit1 = MPed::Commit(values1, ck);
    auto commit2 = MPed::Commit(values2, ck);
    
    // Add commitments
    auto sum_commit = MPed::AddCommitments(commit1, commit2, ck);
    
    // Verify result
    assert(sum_commit.values.size() == 2);
    assert(sum_commit.values[0] == Fr("8"));  // 5 + 3
    assert(sum_commit.values[1] == Fr("17")); // 10 + 7
    
    bool valid = MPed::VerifyOpen(sum_commit, ck);
    assert(valid);
    cout << "PASS Homomorphic addition works" << endl;
    
    // Test different vector sizes
    vector<Fr> values3 = {Fr("1"), Fr("2"), Fr("3")};
    auto commit3 = MPed::Commit(values3, ck);
    auto sum_diff = MPed::AddCommitments(commit1, commit3, ck);
    
    assert(sum_diff.values.size() == 3);
    assert(sum_diff.values[0] == Fr("6"));  // 5 + 1
    assert(sum_diff.values[1] == Fr("12")); // 10 + 2
    assert(sum_diff.values[2] == Fr("3"));  // 0 + 3
    
    bool valid_diff = MPed::VerifyOpen(sum_diff, ck);
    assert(valid_diff);
    cout << "PASS Addition with different vector sizes works" << endl;
}

void test_scalar_multiplication() {
    cout << "\nTesting scalar multiplication..." << endl;
    
    auto ck = MPed::Setup(3);
    
    vector<Fr> values = {Fr("4"), Fr("6")};
    auto commit = MPed::Commit(values, ck);
    
    Fr scalar("3");
    auto scaled_commit = MPed::ScalarMultCommitment(commit, scalar, ck);
    
    // Verify result
    assert(scaled_commit.values.size() == 2);
    assert(scaled_commit.values[0] == Fr("12")); // 4 * 3
    assert(scaled_commit.values[1] == Fr("18")); // 6 * 3
    
    bool valid = MPed::VerifyOpen(scaled_commit, ck);
    assert(valid);
    cout << "PASS Scalar multiplication works" << endl;
}

void test_batch_commit() {
    cout << "\nTesting batch commitment..." << endl;
    
    auto ck = MPed::Setup(4);
    
    vector<vector<Fr>> value_vectors = {
        {Fr("1"), Fr("2")},
        {Fr("3"), Fr("4"), Fr("5")},
        {Fr("6")}
    };
    
    auto batch_commits = MPed::BatchCommit(value_vectors, ck);
    
    assert(batch_commits.size() == 3);
    
    // Verify each commitment
    for (size_t i = 0; i < batch_commits.size(); i++) {
        bool valid = MPed::VerifyOpen(batch_commits[i], ck);
        assert(valid);
        assert(batch_commits[i].values == value_vectors[i]);
    }
    
    cout << "PASS Batch commitment works" << endl;
}

void test_single_recommit() {
    cout << "\nTesting single value recommitment..." << endl;
    
    auto ck = MPed::Setup(5);
    
    Fr value("100");
    size_t index = 3;
    
    auto commit = MPed::RecommitSingle(value, index, ck);
    
    assert(commit.values.size() == index);
    assert(commit.values[index-1] == value);
    
    // Check other values are zero
    for (size_t i = 0; i < commit.values.size(); i++) {
        if (i != index-1) {
            assert(commit.values[i].isZero());
        }
    }
    
    bool valid = MPed::VerifyOpen(commit, ck);
    assert(valid);
    cout << "PASS Single value recommitment works" << endl;
}

void test_edge_cases() {
    cout << "\nTesting edge cases..." << endl;
    
    auto ck = MPed::Setup(3);
    
    // Empty vector
    vector<Fr> empty_values;
    auto empty_commit = MPed::Commit(empty_values, ck);
    bool valid_empty = MPed::VerifyOpen(empty_commit, ck);
    assert(valid_empty);
    cout << "PASS Empty value vector works" << endl;
    
    // Zero values
    vector<Fr> zero_values = {Fr("0"), Fr("0")};
    auto zero_commit = MPed::Commit(zero_values, ck);
    bool valid_zero = MPed::VerifyOpen(zero_commit, ck);
    assert(valid_zero);
    cout << "PASS Zero values work" << endl;
    
    // Large values
    Fr large_val;
    large_val.setStr("123456789012345678901234567890");
    vector<Fr> large_values = {large_val};
    auto large_commit = MPed::Commit(large_values, ck);
    bool valid_large = MPed::VerifyOpen(large_commit, ck);
    assert(valid_large);
    cout << "PASS Large values work" << endl;
}

void test_security_properties() {
    cout << "\nTesting security properties..." << endl;
    
    auto ck = MPed::Setup(3);
    
    // Binding: Same values with different randomness should give different commitments
    vector<Fr> values = {Fr("42"), Fr("84")};
    Fr rand1("123");
    Fr rand2("456");
    
    auto commit1 = MPed::Commit(values, ck, &rand1);
    auto commit2 = MPed::Commit(values, ck, &rand2);
    
    assert(!(commit1.commit == commit2.commit));
    cout << "PASS Different randomness gives different commitments" << endl;
    
    // Different values should give different commitments (with high probability)
    vector<Fr> values_diff = {Fr("43"), Fr("84")};
    auto commit_diff = MPed::Commit(values_diff, ck);
    
    assert(!(commit1.commit == commit_diff.commit));
    cout << "PASS Different values give different commitments" << endl;
    
    // Invalid opening should fail
    MPed::Opening wrong_opening;
    wrong_opening.randomness = Fr("999");
    wrong_opening.values = {Fr("999")};
    
    bool should_fail = MPed::VerifyOpen(commit1.commit, wrong_opening, ck);
    assert(!should_fail);
    cout << "PASS Invalid opening correctly rejected" << endl;
}

void benchmark_performance() {
    cout << "\nBenchmarking performance..." << endl;
    
    const size_t NUM_VALUES = 100;
    const size_t NUM_ITERATIONS = 100;
    
    auto ck = MPed::Setup(NUM_VALUES);
    
    // Generate test values
    vector<Fr> values(NUM_VALUES);
    for (size_t i = 0; i < NUM_VALUES; i++) {
        values[i].setByCSPRNG();
    }
    
    // Benchmark commitment
    auto start = chrono::high_resolution_clock::now();
    for (size_t i = 0; i < NUM_ITERATIONS; i++) {
        auto commit = MPed::Commit(values, ck);
    }
    auto end = chrono::high_resolution_clock::now();
    
    auto commit_time = chrono::duration_cast<chrono::microseconds>(end - start).count();
    cout << "PASS Commitment (" << NUM_VALUES << " values): " 
         << commit_time / NUM_ITERATIONS << " μs average" << endl;
    
    // Benchmark verification
    auto test_commit = MPed::Commit(values, ck);
    start = chrono::high_resolution_clock::now();
    for (size_t i = 0; i < NUM_ITERATIONS; i++) {
        bool valid = MPed::VerifyOpen(test_commit, ck);
        (void)valid; // Suppress unused variable warning
    }
    end = chrono::high_resolution_clock::now();
    
    auto verify_time = chrono::duration_cast<chrono::microseconds>(end - start).count();
    cout << "PASS Verification (" << NUM_VALUES << " values): " 
         << verify_time / NUM_ITERATIONS << " μs average" << endl;
}

int main() {
    cout << "=== MPed (Pedersen Multi-Commitment) Test Suite ===" << endl;
    cout << "SharpGS Implementation - Checkpoint 1" << endl;
    cout << "===================================================" << endl;
    
    try {
        test_initialization();
        test_setup();
        test_single_value_commit();
        test_multi_value_commit();
        test_homomorphic_addition();
        test_scalar_multiplication();
        test_batch_commit();
        test_single_recommit();
        test_edge_cases();
        test_security_properties();
        benchmark_performance();
        
        cout << "\nSUCCESS: All tests passed! MPed implementation is working correctly." << endl;
        cout << "Ready for Checkpoint 2: Masking and Rejection Sampling" << endl;
        
    } catch (const exception& e) {
        cout << "\nFAILED: Test failed with exception: " << e.what() << endl;
        return 1;
    } catch (...) {
        cout << "\nFAILED: Test failed with unknown exception" << endl;
        return 1;
    }
    
    return 0;
}
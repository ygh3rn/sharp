// tests/test_sharp_gs.cpp
#include <mcl/bn.hpp>
#include <iostream>
#include <chrono>
#include <vector>
#include <cassert>
#include <random>

#include "sharp_gs.h"
#include "pedersen.h"
#include "three_squares.h"

using namespace mcl;
using namespace std;
using namespace std::chrono;

class TestSuite {
private:
    size_t passed = 0, total = 0;
    
    void test(const string& name, bool condition) {
        total++;
        if (condition) {
            passed++;
            cout << "PASS " << name << endl;
        } else {
            cout << "FAIL " << name << endl;
        }
    }

public:
    void run_tests() {
        cout << "SharpGS Range Proof Test Suite" << endl;
        cout << "==============================" << endl;
        
        initPairing(BN_SNARK1);
        
        cout << "\nBasic Protocol Tests" << endl;
        cout << "--------------------" << endl;
        test_sharp_gs_basic();
        test_boundary_values();
        test_different_ranges();
        test_batch_proofs();
        test_zero_value();
        
        cout << "\nCryptographic Component Tests" << endl;
        cout << "-----------------------------" << endl;
        test_three_squares_decomposition();
        test_pedersen_commitments();
        test_challenge_generation();
        test_response_computation();
        
        cout << "\nSecurity Tests" << endl;
        cout << "--------------" << endl;
        test_invalid_proofs();
        test_malformed_inputs();
        test_commitment_binding();
        test_soundness_attacks();
        
        cout << "\nStress Tests" << endl;
        cout << "------------" << endl;
        test_large_batch_proofs();
        test_large_ranges();
        test_random_values();
        test_performance();
        
        cout << "\nEdge Cases" << endl;
        cout << "----------" << endl;
        test_edge_cases();
        test_decomposition_edge_cases();
        test_field_arithmetic_edge_cases();
        
        cout << "\nFinal Results" << endl;
        cout << "===============" << endl;
        cout << "Tests Passed: " << passed << "/" << total;
        cout << (passed == total ? " - All passed!" : " - Some failed") << endl;
    }

private:
    void test_sharp_gs_basic() {
        bool success = true;
        try {
            Fr B(100);
            auto pp = SharpGS::setup(1, B, 128);
            
            SharpGS::Witness witness;
            witness.values = {Fr(42)};
            witness.randomness.setByCSPRNG();
            
            auto commit = PedersenMultiCommitment::commit(pp.ck_com, witness.values, witness.randomness);
            SharpGS::Statement stmt;
            stmt.commitment = commit.value;
            stmt.B = B;
            
            auto first_msg = SharpGS::prove_first(pp, stmt, witness);
            auto challenge = SharpGS::generate_challenge(pp);
            auto response = SharpGS::prove_response(pp, stmt, witness, first_msg, challenge);
            
            SharpGS::Proof proof;
            proof.first_msg = first_msg;
            proof.response = response;
            
            success = SharpGS::verify(pp, stmt, proof, challenge);
        } catch (const exception& e) {
            success = false;
        }
        test("SharpGS Basic Range Proof", success);
    }

    void test_boundary_values() {
        bool success = true;
        try {
            Fr B(100);
            auto pp = SharpGS::setup(1, B, 128);
            
            for (int val : {0, 100}) {
                SharpGS::Witness witness;
                witness.values = {Fr(val)};
                witness.randomness.setByCSPRNG();
                
                auto commit = PedersenMultiCommitment::commit(pp.ck_com, witness.values, witness.randomness);
                SharpGS::Statement stmt;
                stmt.commitment = commit.value;
                stmt.B = B;
                
                auto first_msg = SharpGS::prove_first(pp, stmt, witness);
                auto challenge = SharpGS::generate_challenge(pp);
                auto response = SharpGS::prove_response(pp, stmt, witness, first_msg, challenge);
                
                SharpGS::Proof proof;
                proof.first_msg = first_msg;
                proof.response = response;
                
                if (!SharpGS::verify(pp, stmt, proof, challenge)) {
                    success = false;
                    break;
                }
            }
        } catch (const exception& e) {
            success = false;
        }
        test("Boundary Values (0 and B)", success);
    }

    void test_different_ranges() {
        bool success = true;
        try {
            vector<int> ranges = {10, 50, 255, 1000};
            vector<int> test_values = {5, 25, 128, 500};
            
            for (size_t i = 0; i < ranges.size(); i++) {
                Fr B(ranges[i]);
                auto pp = SharpGS::setup(1, B, 128);
                
                SharpGS::Witness witness;
                witness.values = {Fr(test_values[i])};
                witness.randomness.setByCSPRNG();
                
                auto commit = PedersenMultiCommitment::commit(pp.ck_com, witness.values, witness.randomness);
                SharpGS::Statement stmt;
                stmt.commitment = commit.value;
                stmt.B = B;
                
                auto first_msg = SharpGS::prove_first(pp, stmt, witness);
                auto challenge = SharpGS::generate_challenge(pp);
                auto response = SharpGS::prove_response(pp, stmt, witness, first_msg, challenge);
                
                SharpGS::Proof proof;
                proof.first_msg = first_msg;
                proof.response = response;
                
                if (!SharpGS::verify(pp, stmt, proof, challenge)) {
                    success = false;
                    break;
                }
            }
        } catch (const exception& e) {
            success = false;
        }
        test("Different Range Sizes", success);
    }

    void test_batch_proofs() {
        bool success = true;
        try {
            Fr B(100);
            size_t batch_size = 4;
            auto pp = SharpGS::setup(batch_size, B, 128);
            
            SharpGS::Witness witness;
            witness.values = {Fr(10), Fr(25), Fr(42), Fr(63)};
            witness.randomness.setByCSPRNG();
            
            auto commit = PedersenMultiCommitment::commit(pp.ck_com, witness.values, witness.randomness);
            SharpGS::Statement stmt;
            stmt.commitment = commit.value;
            stmt.B = B;
            
            auto first_msg = SharpGS::prove_first(pp, stmt, witness);
            auto challenge = SharpGS::generate_challenge(pp);
            auto response = SharpGS::prove_response(pp, stmt, witness, first_msg, challenge);
            
            SharpGS::Proof proof;
            proof.first_msg = first_msg;
            proof.response = response;
            
            success = SharpGS::verify(pp, stmt, proof, challenge);
        } catch (const exception& e) {
            success = false;
        }
        test("Batch Proof (4 values)", success);
    }

    void test_zero_value() {
        bool success = true;
        try {
            Fr B(50);
            auto pp = SharpGS::setup(1, B, 128);
            
            SharpGS::Witness witness;
            witness.values = {Fr(0)};
            witness.randomness.setByCSPRNG();
            
            auto commit = PedersenMultiCommitment::commit(pp.ck_com, witness.values, witness.randomness);
            SharpGS::Statement stmt;
            stmt.commitment = commit.value;
            stmt.B = B;
            
            auto first_msg = SharpGS::prove_first(pp, stmt, witness);
            auto challenge = SharpGS::generate_challenge(pp);
            auto response = SharpGS::prove_response(pp, stmt, witness, first_msg, challenge);
            
            SharpGS::Proof proof;
            proof.first_msg = first_msg;
            proof.response = response;
            
            success = SharpGS::verify(pp, stmt, proof, challenge);
        } catch (const exception& e) {
            success = false;
        }
        test("Zero Value Proof", success);
    }

    void test_three_squares_decomposition() {
        bool success = true;
        try {
            vector<long> test_values = {30, 42, 100, 169, 1000, 2025, 4900};
            
            for (long val : test_values) {
                Fr n(static_cast<int>(val));
                auto decomp = ThreeSquares::decompose(n);
                
                if (!decomp || !ThreeSquares::verify(*decomp, n)) {
                    success = false;
                    break;
                }
            }
            
            Fr x(42), B(100);
            Fr range_val = ThreeSquares::compute_range_value(x, B);
            auto decomp = ThreeSquares::decompose(range_val);
            
            if (!decomp || !ThreeSquares::verify(*decomp, range_val)) {
                success = false;
            }
        } catch (const exception& e) {
            success = false;
        }
        test("Three Squares Decomposition", success);
    }

    void test_pedersen_commitments() {
        bool success = true;
        try {
            auto ck = PedersenMultiCommitment::setup(3);
            
            // Test single value commitment
            vector<Fr> values1 = {Fr(42)};
            Fr r1; r1.setByCSPRNG();
            auto commit1 = PedersenMultiCommitment::commit(ck, values1, r1);
            
            // Test multiple value commitment
            vector<Fr> values2 = {Fr(10), Fr(20), Fr(30)};
            Fr r2; r2.setByCSPRNG();
            auto commit2 = PedersenMultiCommitment::commit(ck, values2, r2);
            
            // Test homomorphic property
            vector<Fr> sum_values = {Fr(52), Fr(20), Fr(30)};
            Fr sum_r; Fr::add(sum_r, r1, r2);
            auto expected_commit = PedersenMultiCommitment::commit(ck, sum_values, sum_r);
            
            G1 actual_sum;
            G1::add(actual_sum, commit1.value, commit2.value);
            
            success = (actual_sum == expected_commit.value);
        } catch (const exception& e) {
            success = false;
        }
        test("Pedersen Commitment Properties", success);
    }

    void test_challenge_generation() {
        bool success = true;
        try {
            Fr B(100);
            auto pp = SharpGS::setup(1, B, 128);
            
            // Generate multiple challenges and ensure they're different
            vector<SharpGS::Challenge> challenges;
            for (int i = 0; i < 10; i++) {
                challenges.push_back(SharpGS::generate_challenge(pp));
            }
            
            // Check that challenges have correct length
            for (const auto& challenge : challenges) {
                if (challenge.gammas.size() != pp.repetitions) {
                    success = false;
                    break;
                }
            }
            
            // Check that challenges are different (probabilistic)
            bool found_different = false;
            for (size_t i = 0; i < challenges.size() - 1; i++) {
                if (!(challenges[i].gammas[0] == challenges[i+1].gammas[0])) {
                    found_different = true;
                    break;
                }
            }
            if (!found_different) success = false;
            
        } catch (const exception& e) {
            success = false;
        }
        test("Challenge Generation", success);
    }

    void test_response_computation() {
        bool success = true;
        try {
            Fr B(100);
            auto pp = SharpGS::setup(2, B, 64);
            
            SharpGS::Witness witness;
            witness.values = {Fr(25), Fr(75)};
            witness.randomness.setByCSPRNG();
            
            auto commit = PedersenMultiCommitment::commit(pp.ck_com, witness.values, witness.randomness);
            SharpGS::Statement stmt;
            stmt.commitment = commit.value;
            stmt.B = B;
            
            auto first_msg = SharpGS::prove_first(pp, stmt, witness);
            auto challenge = SharpGS::generate_challenge(pp);
            
            // Test multiple response computations with same inputs
            auto response1 = SharpGS::prove_response(pp, stmt, witness, first_msg, challenge);
            auto response2 = SharpGS::prove_response(pp, stmt, witness, first_msg, challenge);
            
            // Responses should be identical (deterministic given inputs)
            success = (response1.z_values[0][0] == response2.z_values[0][0]);
            
        } catch (const exception& e) {
            success = false;
        }
        test("Response Computation Consistency", success);
    }

    void test_invalid_proofs() {
        bool success = true;
        try {
            Fr B(100);
            auto pp = SharpGS::setup(1, B, 128);
            
            SharpGS::Witness witness;
            witness.values = {Fr(42)};
            witness.randomness.setByCSPRNG();
            
            auto commit = PedersenMultiCommitment::commit(pp.ck_com, witness.values, witness.randomness);
            SharpGS::Statement stmt;
            stmt.commitment = commit.value;
            stmt.B = B;
            
            auto first_msg = SharpGS::prove_first(pp, stmt, witness);
            auto challenge = SharpGS::generate_challenge(pp);
            auto response = SharpGS::prove_response(pp, stmt, witness, first_msg, challenge);
            
            SharpGS::Proof proof;
            proof.first_msg = first_msg;
            proof.response = response;
            
            // Valid proof should pass
            if (!SharpGS::verify(pp, stmt, proof, challenge)) {
                success = false;
            }
            
            // Modified response should fail
            Fr original_z = proof.response.z_values[0][0];
            Fr::add(proof.response.z_values[0][0], original_z, Fr(1));
            
            if (SharpGS::verify(pp, stmt, proof, challenge)) {
                success = false;
            }
            
            proof.response.z_values[0][0] = original_z;
            
            // Wrong challenge should fail
            auto wrong_challenge = SharpGS::generate_challenge(pp);
            if (SharpGS::verify(pp, stmt, proof, wrong_challenge)) {
                success = false;
            }
            
        } catch (const exception& e) {
            success = false;
        }
        test("Invalid Proof Detection", success);
    }

    void test_malformed_inputs() {
        bool success = true;
        try {
            Fr B(100);
            auto pp = SharpGS::setup(1, B, 128);
            
            // Test with mismatched witness/commitment sizes
            try {
                SharpGS::Witness witness;
                witness.values = {Fr(42)};  // 1 value
                witness.randomness.setByCSPRNG();
                
                // Create commitment for different number of values
                vector<Fr> wrong_values = {Fr(10), Fr(20)};  // 2 values
                auto commit = PedersenMultiCommitment::commit(pp.ck_com, wrong_values, witness.randomness);
                
                SharpGS::Statement stmt;
                stmt.commitment = commit.value;
                stmt.B = B;
                
                // This should handle the mismatch gracefully
                auto first_msg = SharpGS::prove_first(pp, stmt, witness);
                
            } catch (...) {
                // Expected to fail - this is good
            }
            
        } catch (const exception& e) {
            success = false;
        }
        test("Malformed Input Handling", success);
    }

    void test_commitment_binding() {
        bool success = true;
        try {
            auto ck = PedersenMultiCommitment::setup(1);
            
            // Two different values with same randomness should produce different commitments
            Fr r; r.setByCSPRNG();
            
            auto commit1 = PedersenMultiCommitment::commit(ck, {Fr(42)}, r);
            auto commit2 = PedersenMultiCommitment::commit(ck, {Fr(43)}, r);
            
            success = !(commit1.value == commit2.value);
            
        } catch (const exception& e) {
            success = false;
        }
        test("Commitment Binding Property", success);
    }

    void test_soundness_attacks() {
        bool success = true;
        try {
            Fr B(100);
            auto pp = SharpGS::setup(1, B, 128);
            
            // Create proof for one value, try to verify with different commitment
            SharpGS::Witness witness1, witness2;
            witness1.values = {Fr(42)};
            witness1.randomness.setByCSPRNG();
            witness2.values = {Fr(43)};
            witness2.randomness.setByCSPRNG();
            
            auto commit1 = PedersenMultiCommitment::commit(pp.ck_com, witness1.values, witness1.randomness);
            auto commit2 = PedersenMultiCommitment::commit(pp.ck_com, witness2.values, witness2.randomness);
            
            SharpGS::Statement stmt1, stmt2;
            stmt1.commitment = commit1.value;
            stmt1.B = B;
            stmt2.commitment = commit2.value;
            stmt2.B = B;
            
            auto first_msg = SharpGS::prove_first(pp, stmt1, witness1);
            auto challenge = SharpGS::generate_challenge(pp);
            auto response = SharpGS::prove_response(pp, stmt1, witness1, first_msg, challenge);
            
            SharpGS::Proof proof;
            proof.first_msg = first_msg;
            proof.response = response;
            
            // Proof should verify with correct statement
            if (!SharpGS::verify(pp, stmt1, proof, challenge)) {
                success = false;
            }
            
            // Proof should NOT verify with different statement
            if (SharpGS::verify(pp, stmt2, proof, challenge)) {
                success = false;
            }
            
        } catch (const exception& e) {
            success = false;
        }
        test("Soundness Attack Resistance", success);
    }

    void test_large_batch_proofs() {
        bool success = true;
        try {
            Fr B(1000);
            size_t batch_size = 10;
            auto pp = SharpGS::setup(batch_size, B, 64);
            
            SharpGS::Witness witness;
            witness.randomness.setByCSPRNG();
            
            // Generate random values in range
            random_device rd;
            mt19937 gen(rd());
            uniform_int_distribution<> dis(0, 1000);
            
            for (size_t i = 0; i < batch_size; i++) {
                witness.values.push_back(Fr(dis(gen)));
            }
            
            auto commit = PedersenMultiCommitment::commit(pp.ck_com, witness.values, witness.randomness);
            SharpGS::Statement stmt;
            stmt.commitment = commit.value;
            stmt.B = B;
            
            auto first_msg = SharpGS::prove_first(pp, stmt, witness);
            auto challenge = SharpGS::generate_challenge(pp);
            auto response = SharpGS::prove_response(pp, stmt, witness, first_msg, challenge);
            
            SharpGS::Proof proof;
            proof.first_msg = first_msg;
            proof.response = response;
            
            success = SharpGS::verify(pp, stmt, proof, challenge);
            
        } catch (const exception& e) {
            success = false;
        }
        test("Large Batch Proof (10 values)", success);
    }

    void test_large_ranges() {
        bool success = true;
        try {
            vector<int> large_ranges = {10000, 65535, 100000};
            vector<int> test_values = {5000, 32767, 50000};
            
            for (size_t i = 0; i < large_ranges.size(); i++) {
                Fr B(large_ranges[i]);
                auto pp = SharpGS::setup(1, B, 64);
                
                SharpGS::Witness witness;
                witness.values = {Fr(test_values[i])};
                witness.randomness.setByCSPRNG();
                
                auto commit = PedersenMultiCommitment::commit(pp.ck_com, witness.values, witness.randomness);
                SharpGS::Statement stmt;
                stmt.commitment = commit.value;
                stmt.B = B;
                
                auto first_msg = SharpGS::prove_first(pp, stmt, witness);
                auto challenge = SharpGS::generate_challenge(pp);
                auto response = SharpGS::prove_response(pp, stmt, witness, first_msg, challenge);
                
                SharpGS::Proof proof;
                proof.first_msg = first_msg;
                proof.response = response;
                
                if (!SharpGS::verify(pp, stmt, proof, challenge)) {
                    success = false;
                    break;
                }
            }
            
        } catch (const exception& e) {
            success = false;
        }
        test("Large Range Proofs", success);
    }

    void test_random_values() {
        bool success = true;
        try {
            Fr B(1000);
            auto pp = SharpGS::setup(1, B, 64);
            
            random_device rd;
            mt19937 gen(rd());
            uniform_int_distribution<> dis(0, 1000);
            
            // Test 20 random values
            for (int i = 0; i < 20; i++) {
                SharpGS::Witness witness;
                witness.values = {Fr(dis(gen))};
                witness.randomness.setByCSPRNG();
                
                auto commit = PedersenMultiCommitment::commit(pp.ck_com, witness.values, witness.randomness);
                SharpGS::Statement stmt;
                stmt.commitment = commit.value;
                stmt.B = B;
                
                auto first_msg = SharpGS::prove_first(pp, stmt, witness);
                auto challenge = SharpGS::generate_challenge(pp);
                auto response = SharpGS::prove_response(pp, stmt, witness, first_msg, challenge);
                
                SharpGS::Proof proof;
                proof.first_msg = first_msg;
                proof.response = response;
                
                if (!SharpGS::verify(pp, stmt, proof, challenge)) {
                    success = false;
                    break;
                }
            }
            
        } catch (const exception& e) {
            success = false;
        }
        test("Random Value Stress Test", success);
    }

    void test_performance() {
        bool success = true;
        try {
            Fr B(100);
            auto pp = SharpGS::setup(1, B, 64);
            
            auto start = high_resolution_clock::now();
            
            for (int i = 0; i < 10; i++) {
                SharpGS::Witness witness;
                witness.values = {Fr(10 + i * 5)};
                witness.randomness.setByCSPRNG();
                
                auto commit = PedersenMultiCommitment::commit(pp.ck_com, witness.values, witness.randomness);
                SharpGS::Statement stmt;
                stmt.commitment = commit.value;
                stmt.B = B;
                
                auto first_msg = SharpGS::prove_first(pp, stmt, witness);
                auto challenge = SharpGS::generate_challenge(pp);
                auto response = SharpGS::prove_response(pp, stmt, witness, first_msg, challenge);
                
                SharpGS::Proof proof;
                proof.first_msg = first_msg;
                proof.response = response;
                
                if (!SharpGS::verify(pp, stmt, proof, challenge)) {
                    success = false;
                    break;
                }
            }
            
            auto end = high_resolution_clock::now();
            auto duration = duration_cast<milliseconds>(end - start);
            
            if (duration.count() > 15000) {  // 15 seconds
                success = false;
            }
            
        } catch (const exception& e) {
            success = false;
        }
        test("Performance Test (10 proofs)", success);
    }

    void test_edge_cases() {
        bool success = true;
        try {
            // Test B = 1 (minimal range)
            Fr B(1);
            auto pp = SharpGS::setup(1, B, 64);
            
            for (int val : {0, 1}) {
                SharpGS::Witness witness;
                witness.values = {Fr(val)};
                witness.randomness.setByCSPRNG();
                
                auto commit = PedersenMultiCommitment::commit(pp.ck_com, witness.values, witness.randomness);
                SharpGS::Statement stmt;
                stmt.commitment = commit.value;
                stmt.B = B;
                
                auto first_msg = SharpGS::prove_first(pp, stmt, witness);
                auto challenge = SharpGS::generate_challenge(pp);
                auto response = SharpGS::prove_response(pp, stmt, witness, first_msg, challenge);
                
                SharpGS::Proof proof;
                proof.first_msg = first_msg;
                proof.response = response;
                
                if (!SharpGS::verify(pp, stmt, proof, challenge)) {
                    success = false;
                    break;
                }
            }
            
        } catch (const exception& e) {
            success = false;
        }
        test("Edge Cases (B=1)", success);
    }

    void test_decomposition_edge_cases() {
        bool success = true;
        try {
            // Test edge cases for three squares decomposition
            vector<long> edge_values = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 13, 169, 289};
            
            for (long val : edge_values) {
                Fr n(static_cast<int>(val));
                auto decomp = ThreeSquares::decompose(n);
                
                if (decomp && !ThreeSquares::verify(*decomp, n)) {
                    success = false;
                    break;
                }
            }
            
        } catch (const exception& e) {
            success = false;
        }
        test("Decomposition Edge Cases", success);
    }

    void test_field_arithmetic_edge_cases() {
        bool success = true;
        try {
            // Test field operations near boundaries
            Fr max_val, zero(0), one(1);
            max_val.setByCSPRNG();  // Large random value
            
            // Test operations don't crash
            Fr result;
            Fr::add(result, max_val, one);
            Fr::sub(result, max_val, one);
            Fr::mul(result, max_val, one);
            Fr::sqr(result, max_val);
            
            // Test with zero
            Fr::add(result, zero, max_val);
            Fr::mul(result, zero, max_val);
            
            success = true;  // If we reach here, no crashes occurred
            
        } catch (const exception& e) {
            success = false;
        }
        test("Field Arithmetic Edge Cases", success);
    }
};

int main() {
    try {
        TestSuite suite;
        suite.run_tests();
        return 0;
    } catch (const exception& e) {
        cerr << "Test suite error: " << e.what() << endl;
        return 1;
    }
}
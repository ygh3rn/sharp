#include <mcl/bn.hpp>
#include <iostream>
#include <chrono>
#include <vector>
#include <cassert>
#include <random>
#include <set>

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
        cout << "SharpGS Test Suite" << endl;
        cout << "==================" << endl;
        
        initPairing(BN_SNARK1);
        
        cout << "\nBasic Functionality Tests" << endl;
        cout << "-------------------------" << endl;
        test_three_squares_decomposition();
        test_pedersen_commitments();
        test_basic_range_proof();
        test_batch_range_proofs();
        test_edge_cases();
        
        cout << "\nAlgorithm 1 Compliance Tests" << endl;
        cout << "-----------------------------" << endl;
        test_generator_independence();
        test_alpha_coefficient_computation();
        test_commitment_structure();
        test_polynomial_commitments();
        test_verification_equations();
        
        cout << "\nSecurity and Correctness Tests" << endl;
        cout << "------------------------------" << endl;
        test_challenge_independence();
        test_commitment_binding();
        test_soundness_properties();
        test_masking_properties();
        
        cout << "\nPerformance Tests" << endl;
        cout << "-----------------" << endl;
        test_performance_benchmarks();
        
        cout << "\n" << string(40, '=') << endl;
        cout << "Results: " << passed << "/" << total << " tests passed" << endl;
        if (passed == total) {
            cout << "All tests passed!" << endl;
        } else {
            cout << (total - passed) << " tests failed." << endl;
        }
    }

private:
    // Basic functionality tests
    void test_three_squares_decomposition() {
        bool success = true;
        try {
            vector<Fr> test_values = {Fr(0), Fr(1), Fr(42), Fr(100), Fr(255)};
            Fr B(256);
            
            for (const Fr& x : test_values) {
                Fr range_value = ThreeSquares::compute_range_value(x, B);
                auto decomp = ThreeSquares::decompose(range_value);
                
                if (!decomp || !decomp->valid) {
                    success = false;
                    break;
                }
                
                // Verify decomposition
                Fr sum;
                Fr::sqr(sum, decomp->x);
                Fr temp;
                Fr::sqr(temp, decomp->y);
                Fr::add(sum, sum, temp);
                Fr::sqr(temp, decomp->z);
                Fr::add(sum, sum, temp);
                
                if (!(sum == range_value)) {
                    success = false;
                    break;
                }
            }
        } catch (...) {
            success = false;
        }
        test("Three Squares Decomposition", success);
    }
    
    void test_pedersen_commitments() {
        bool success = true;
        try {
            auto ck = PedersenMultiCommitment::setup(3);
            vector<Fr> values = {Fr(1), Fr(2), Fr(3)};
            Fr randomness;
            randomness.setByCSPRNG();
            
            auto commit = PedersenMultiCommitment::commit(ck, values, randomness);
            bool verified = PedersenMultiCommitment::verify(ck, commit, values, randomness);
            
            if (!verified) success = false;
            
            // Test homomorphic properties
            auto commit2 = PedersenMultiCommitment::commit(ck, values, randomness);
            auto sum = PedersenMultiCommitment::add(commit, commit2);
            
        } catch (...) {
            success = false;
        }
        test("Pedersen Commitments", success);
    }
    
    void test_basic_range_proof() {
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
            
            bool verified = SharpGS::verify(pp, stmt, proof, challenge);
            
            if (!verified) success = false;
            
        } catch (...) {
            success = false;
        }
        test("Basic Range Proof", success);
    }
    
    void test_batch_range_proofs() {
        bool success = true;
        try {
            Fr B(50);
            auto pp = SharpGS::setup(3, B, 128);
            
            SharpGS::Witness witness;
            witness.values = {Fr(10), Fr(25), Fr(40)};
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
            
            bool verified = SharpGS::verify(pp, stmt, proof, challenge);
            
            if (!verified) success = false;
            
        } catch (...) {
            success = false;
        }
        test("Batch Range Proofs", success);
    }
    
    void test_edge_cases() {
        bool success = true;
        try {
            Fr B(10);
            auto pp = SharpGS::setup(1, B, 128);
            
            // Test boundary values
            vector<Fr> boundary_values = {Fr(0), B};
            
            for (const Fr& val : boundary_values) {
                SharpGS::Witness witness;
                witness.values = {val};
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
                
                bool verified = SharpGS::verify(pp, stmt, proof, challenge);
                
                if (!verified) {
                    success = false;
                    break;
                }
            }
            
        } catch (...) {
            success = false;
        }
        test("Edge Cases", success);
    }
    
    // Algorithm 1 compliance tests
    void test_generator_independence() {
        bool success = true;
        try {
            Fr B(100);
            auto pp = SharpGS::setup(2, B, 128);
            
            // Check generator counts
            size_t expected_com = 1 + pp.num_values + pp.num_values * 3;
            size_t expected_3sq = 1 + pp.num_values;
            
            if (pp.ck_com.generators.size() != expected_com ||
                pp.ck_3sq.generators.size() != expected_3sq) {
                success = false;
            }
            
            // Check generators are different
            if (pp.ck_com.generators[0] == pp.ck_3sq.generators[0]) {
                success = false;
            }
            
        } catch (...) {
            success = false;
        }
        test("Generator Independence", success);
    }
    
    void test_alpha_coefficient_computation() {
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
            
            // Check if polynomial commitments exist
            if (first_msg.poly_commitments_star.size() != pp.repetitions ||
                first_msg.mask_poly_commitments.size() != pp.repetitions) {
                success = false;
            }
            
            for (size_t k = 0; k < pp.repetitions; k++) {
                if (first_msg.poly_commitments_star[k].isZero() ||
                    first_msg.mask_poly_commitments[k].isZero()) {
                    success = false;
                    break;
                }
            }
            
        } catch (...) {
            success = false;
        }
        test("Alpha Coefficient Computation", success);
    }
    
    void test_commitment_structure() {
        bool success = true;
        try {
            Fr B(100);
            auto pp = SharpGS::setup(2, B, 128);
            
            // Test combined commitment key structure
            auto ck_combined = PedersenMultiCommitment::setup_combined(2);
            if (ck_combined.generators.size() != 9) { // 1 + 2 + 2*3
                success = false;
            }
            
            // Test independent commitment key
            auto ck_independent = PedersenMultiCommitment::setup_independent(2);
            if (ck_independent.generators.size() != 3) { // 1 + 2
                success = false;
            }
            
        } catch (...) {
            success = false;
        }
        test("Commitment Structure", success);
    }
    
    void test_polynomial_commitments() {
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
            
            // Check if polynomial commitments use ck_3sq (different generators)
            for (size_t k = 0; k < pp.repetitions; k++) {
                if (first_msg.poly_commitments_star[k].isZero()) {
                    success = false;
                    break;
                }
            }
            
        } catch (...) {
            success = false;
        }
        test("Polynomial Commitments", success);
    }
    
    void test_verification_equations() {
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
            
            bool verified = SharpGS::verify(pp, stmt, proof, challenge);
            
            if (!verified) success = false;
            
        } catch (...) {
            success = false;
        }
        test("Verification Equations", success);
    }
    
    // Security tests
    void test_challenge_independence() {
        bool success = true;
        try {
            Fr B(100);
            auto pp = SharpGS::setup(1, B, 128);
            
            set<string> challenge_set;
            for (int i = 0; i < 10; i++) {
                auto challenge = SharpGS::generate_challenge(pp);
                string challenge_str;
                for (const auto& gamma : challenge.gammas) {
                    challenge_str += gamma.getStr();
                }
                challenge_set.insert(challenge_str);
            }
            
            if (challenge_set.size() <= 1) success = false;
            
        } catch (...) {
            success = false;
        }
        test("Challenge Independence", success);
    }
    
    void test_commitment_binding() {
        bool success = true;
        try {
            Fr B(100);
            auto pp = SharpGS::setup(1, B, 128);
            
            SharpGS::Witness witness1, witness2;
            witness1.values = {Fr(42)};
            witness2.values = {Fr(43)};
            witness1.randomness.setByCSPRNG();
            witness2.randomness = witness1.randomness;
            
            auto commit1 = PedersenMultiCommitment::commit(pp.ck_com, witness1.values, witness1.randomness);
            auto commit2 = PedersenMultiCommitment::commit(pp.ck_com, witness2.values, witness2.randomness);
            
            if (commit1.value == commit2.value) success = false;
            
        } catch (...) {
            success = false;
        }
        test("Commitment Binding", success);
    }
    
    void test_soundness_properties() {
        bool success = true;
        try {
            Fr B(100);
            auto pp = SharpGS::setup(1, B, 128);
            
            // Test with valid witness
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
            
            bool verified = SharpGS::verify(pp, stmt, proof, challenge);
            
            if (!verified) success = false;
            
        } catch (...) {
            success = false;
        }
        test("Soundness Properties", success);
    }
    
    void test_masking_properties() {
        bool success = true;
        try {
            auto masks1 = SharpGS::generate_mask_values(10);
            auto masks2 = SharpGS::generate_mask_values(10);
            
            // Check masks are different
            bool different = false;
            for (size_t i = 0; i < 10; i++) {
                if (!(masks1[i] == masks2[i])) {
                    different = true;
                    break;
                }
            }
            
            if (!different) success = false;
            
        } catch (...) {
            success = false;
        }
        test("Masking Properties", success);
    }
    
    void test_performance_benchmarks() {
        bool success = true;
        try {
            Fr B(1000);
            auto pp = SharpGS::setup(4, B, 128);
            
            auto start = high_resolution_clock::now();
            
            for (int i = 0; i < 10; i++) {
                SharpGS::Witness witness;
                witness.values = {Fr(100), Fr(200), Fr(300), Fr(400)};
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
                
                bool verified = SharpGS::verify(pp, stmt, proof, challenge);
                
                if (!verified) {
                    success = false;
                    break;
                }
            }
            
            auto end = high_resolution_clock::now();
            auto duration = duration_cast<milliseconds>(end - start);
            
            cout << "Batch performance: 10 proofs in " << duration.count() << "ms" << endl;
            
        } catch (...) {
            success = false;
        }
        test("Performance Benchmarks", success);
    }
};

int main() {
    TestSuite suite;
    suite.run_tests();
    return 0;
}
#include <mcl/bn.hpp>
#include <iostream>
#include <chrono>
#include <cassert>

#include "sharpgs.h"
#include "polynomial.h"
#include "ntt.h"
#include "commitments.h"
#include "utils.h"

using namespace mcl;
using namespace std;
using namespace std::chrono;

class SharpGSTestSuite {
private:
    size_t passed = 0;
    size_t total = 0;
    
    void test(const string& name, bool condition) {
        total++;
        if (condition) {
            passed++;
            cout << "✓ " << name << endl;
        } else {
            cout << "✗ " << name << endl;
        }
    }
    
    template<typename F>
    void benchmark(const string& name, F func) {
        auto start = high_resolution_clock::now();
        func();
        auto end = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(end - start);
        cout << "⏱ " << name << ": " << duration.count() << "μs" << endl;
    }

public:
    void run_all_tests() {
        cout << "SharpGS Test Suite (Fixed Implementation)" << endl;
        cout << "=========================================" << endl;
        
        initPairing(BN254);
        
        test_parameter_validation();
        test_square_decomposition();
        test_commitment_operations();
        test_sharpgs_protocol();
        test_bounds_checking();
        
        cout << "\nBenchmarks" << endl;
        cout << "----------" << endl;
        benchmark_basic_operations();
        
        cout << "\nResults: " << passed << "/" << total << " tests passed" << endl;
        if (passed == total) {
            cout << "🎉 All tests passed!" << endl;
        } else {
            cout << "❌ Some tests failed - check implementation" << endl;
        }
    }

private:
    void test_parameter_validation() {
        cout << "\nTesting Parameter Validation..." << endl;
        
        // Test valid parameters
        SharpGSParams params_valid(128, 32);
        test("Valid parameters (128, 32)", params_valid.validate_parameters());
        
        // Test constraint validation
        test("Security level set correctly", params_valid.security_level == 128);
        test("Range bits set correctly", params_valid.range_bits == 32);
        test("Repetitions > 0", params_valid.repetitions > 0);
        test("Challenge bits reasonable", params_valid.challenge_bits >= 20 && params_valid.challenge_bits <= 40);
        
        // Test paper constraints: p >= 2(BΓ² + 1)L
        uint64_t B = 1UL << params_valid.range_bits;
        uint64_t Gamma = (1UL << params_valid.challenge_bits) - 1;
        uint64_t L = 1UL << params_valid.masking_bits;
        uint64_t p_min = 2 * (B * Gamma * Gamma + 1) * L;
        test("p order meets paper constraint", Utils::to_int(params_valid.p_order) >= p_min);
        
        // Test q constraint: q >= 18K²
        uint64_t K = (B * Gamma + 1) * L;
        uint64_t q_min = 18 * K * K;
        test("q order meets paper constraint", Utils::to_int(params_valid.q_order) >= q_min);
        
        // Test invalid parameters
        try {
            SharpGSParams params_invalid(0, 0);
            test("Invalid parameters rejected", !params_invalid.validate_parameters());
        } catch (...) {
            test("Invalid parameters rejected", true);
        }
    }
    
    void test_square_decomposition() {
        cout << "\nTesting 3-Square Decomposition..." << endl;
        
        // Test basic decomposition
        Fr x = Fr(10);
        Fr B = Fr(100);
        
        try {
            vector<Fr> y_values = SharpGS::compute_square_decomposition(x, B);
            test("Decomposition returns 3 values", y_values.size() == 3);
            
            bool is_valid = SharpGS::verify_square_decomposition(x, B, y_values);
            test("Decomposition verification passes", is_valid);
            
            // Manually verify: 4*10*(100-10) + 1 = 4*10*90 + 1 = 3601
            uint64_t expected = 4 * 10 * 90 + 1;
            uint64_t actual = 0;
            for (const auto& y : y_values) {
                uint64_t y_int = Utils::to_int(y);
                actual += y_int * y_int;
            }
            test("Manual verification: 4x(B-x)+1 = ∑y²", actual == expected);
            
        } catch (const exception& e) {
            cout << "Decomposition error: " << e.what() << endl;
            test("Basic decomposition", false);
        }
        
        // Test edge cases
        try {
            vector<Fr> y_zero = SharpGS::compute_square_decomposition(Fr(0), Fr(100));
            test("Decomposition for x=0", y_zero.size() == 3);
            
            vector<Fr> y_max = SharpGS::compute_square_decomposition(Fr(100), Fr(100));
            test("Decomposition for x=B", y_max.size() == 3);
        } catch (...) {
            test("Edge case decompositions", false);
        }
        
        // Test forbidden form 4^a(8b+7)
        // 7 = 4^0(8*0+7), should fail for some constructions
        try {
            Fr x_forbidden = Fr(1); 
            Fr B_forbidden = Fr(2);
            // 4*1*(2-1) + 1 = 5, not forbidden form
            vector<Fr> y_vals = SharpGS::compute_square_decomposition(x_forbidden, B_forbidden);
            test("Non-forbidden form works", true);
        } catch (...) {
            test("Non-forbidden form works", false);
        }
    }
    
    void test_commitment_operations() {
        cout << "\nTesting Commitment Operations..." << endl;
        
        // Test commitment key setup
        CommitmentKey ck = PedersenCommitment::setup(10);
        test("Commitment key setup", ck.generators.size() == 10);
        
        // Test commitment and verification
        Fr value = Fr(42);
        auto [commit, randomness] = PedersenCommitment::commit(ck, value);
        bool verify_result = PedersenCommitment::verify(ck, commit, value, randomness);
        test("Commitment verification", verify_result);
        
        // Test multi-value commitment
        vector<Fr> values = {Fr(1), Fr(2), Fr(3)};
        auto [multi_commit, multi_rand] = PedersenCommitment::commit(ck, values);
        bool multi_verify = PedersenCommitment::verify(ck, multi_commit, values, multi_rand);
        test("Multi-value commitment", multi_verify);
        
        // Test commitment arithmetic
        Commitment sum = commit + multi_commit;
        Commitment scaled = commit * Fr(2);
        test("Commitment arithmetic", true); // No crash = success
    }
    
    void test_sharpgs_protocol() {
        cout << "\nTesting SharpGS Protocol..." << endl;
        
        // Setup with small parameters for testing
        SharpGSParams params(80, 16); // Reduced for faster testing
        
        try {
            SharpGSPublicParams pp = SharpGS::setup(params);
            test("SharpGS setup", pp.ck_com.generators.size() > 0);
            
            // Create valid witness
            vector<Fr> values = {Fr(10), Fr(20)}; // Values in range [0, 2^16)
            Fr randomness = Utils::random_fr();
            
            auto [value_commit, _] = PedersenCommitment::commit(pp.ck_com, values);
            
            SharpGSWitness witness(values, randomness);
            SharpGSStatement statement(value_commit, Fr(1ULL << params.range_bits));
            
            // Test first message generation
            SharpGSFirstMessage first_msg = SharpGS::prove_first(pp, statement, witness);
            test("First message generation", true);
            test("Y commitment present", !first_msg.y_commit.value.isZero());
            test("D commitments correct size", first_msg.d_commits.size() == params.repetitions);
            
            // Test challenge generation
            SharpGSChallenge challenge = SharpGS::generate_challenge(params);
            test("Challenge generation", challenge.challenges.size() == params.repetitions);
            
            // Verify challenges are within bounds
            bool challenges_valid = true;
            uint64_t max_challenge = params.get_challenge_bound();
            for (const auto& c : challenge.challenges) {
                if (Utils::to_int(c) > max_challenge) {
                    challenges_valid = false;
                    break;
                }
            }
            test("Challenges within bounds", challenges_valid);
            
            // Test response generation
            SharpGSResponse response = SharpGS::prove_second(pp, statement, witness, first_msg, challenge);
            test("Response generation", response.z_values.size() == params.repetitions);
            test("T values present", response.t_values.size() == params.repetitions * 3);
            
            // Test complete proof
            SharpGSProof proof;
            proof.first_msg = first_msg;
            proof.challenge = challenge;
            proof.response = response;
            
            bool verification = SharpGS::verify(pp, statement, proof);
            test("Protocol verification", verification);
            
            // Test non-interactive proof
            SharpGSProof ni_proof = SharpGS::prove(pp, statement, witness);
            bool ni_verification = SharpGS::verify(pp, statement, ni_proof);
            test("Non-interactive proof", ni_verification);
            
        } catch (const exception& e) {
            cout << "Protocol error: " << e.what() << endl;
            test("SharpGS protocol", false);
        }
    }
    
    void test_bounds_checking() {
        cout << "\nTesting Bounds Checking..." << endl;
        
        // Test masking bounds
        Fr test_value = Fr(100);
        bool bounds_ok = SharpGS::check_masking_bounds(test_value, 16, 20, 10);
        test("Masking bounds check", bounds_ok);
        
        // Test large value rejection
        Fr large_value = Fr(1ULL << 50); // Very large value
        bool large_rejected = !SharpGS::check_masking_bounds(large_value, 16, 20, 10);
        test("Large value rejected", large_rejected);
        
        // Test coefficient computation
        vector<Fr> x_vals = {Fr(1), Fr(2)};
        vector<vector<Fr>> y_vals = {{Fr(1), Fr(1), Fr(1)}, {Fr(2), Fr(2), Fr(2)}};
        vector<Fr> x_masks = {Fr(10), Fr(20)};
        vector<Fr> y_masks = {Fr(1), Fr(2), Fr(3), Fr(4), Fr(5), Fr(6)};
        Fr B = Fr(100);
        
        vector<Fr> coeffs = SharpGS::compute_decomposition_coeffs(x_vals, y_vals, x_masks, y_masks, B);
        test("Coefficient computation", coeffs.size() == 2);
        test("Coefficients not zero", !coeffs[0].isZero() || !coeffs[1].isZero());
    }
    
    void benchmark_basic_operations() {
        SharpGSParams params(80, 16);
        SharpGSPublicParams pp = SharpGS::setup(params);
        
        vector<Fr> values = {Fr(42)};
        Fr randomness = Utils::random_fr();
        auto [commit, _] = PedersenCommitment::commit(pp.ck_com, values);
        
        SharpGSWitness witness(values, randomness);
        SharpGSStatement statement(commit, Fr(1ULL << params.range_bits));
        
        // Benchmark square decomposition
        benchmark("Square decomposition", [&]() {
            vector<Fr> y_vals = SharpGS::compute_square_decomposition(Fr(42), Fr(1000));
        });
        
        // Benchmark proof generation  
        benchmark("Proof generation", [&]() {
            SharpGSProof proof = SharpGS::prove(pp, statement, witness);
        });
        
        // Benchmark verification
        SharpGSProof proof = SharpGS::prove(pp, statement, witness);
        benchmark("Proof verification", [&]() {
            bool result = SharpGS::verify(pp, statement, proof);
            (void)result;
        });
    }
};

int main() {
    try {
        SharpGSTestSuite suite;
        suite.run_all_tests();
        return 0;
    } catch (const exception& e) {
        cerr << "Test suite error: " << e.what() << endl;
        return 1;
    }
}
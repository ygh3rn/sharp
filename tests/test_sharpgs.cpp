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

class TestSuite {
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
        cout << "Running SharpGS Test Suite" << endl;
        cout << "==========================" << endl;
        
        initPairing(BN254);
        
        test_polynomial_operations();
        test_ntt_operations();
        test_commitment_scheme();
        test_sharpgs_protocol();
        test_edge_cases();
        
        cout << "\nBenchmarks" << endl;
        cout << "----------" << endl;
        benchmark_sharpgs();
        
        cout << "\nResults: " << passed << "/" << total << " tests passed" << endl;
        if (passed == total) {
            cout << "🎉 All tests passed!" << endl;
        }
    }

private:
    void test_polynomial_operations() {
        cout << "\nTesting Polynomial Operations..." << endl;
        
        // Test evaluation
        vector<Fr> poly = {Fr(1), Fr(2), Fr(3)}; // 1 + 2x + 3x²
        Fr x = Fr(2);
        Fr result = Polynomial::evaluate(poly, x);
        Fr expected = Fr(1 + 2*2 + 3*4); // 1 + 4 + 12 = 17
        test("Polynomial evaluation", result == expected);
        
        // Test addition
        vector<Fr> a = {Fr(1), Fr(2)};
        vector<Fr> b = {Fr(3), Fr(4), Fr(5)};
        vector<Fr> sum = Polynomial::add(a, b);
        test("Polynomial addition size", sum.size() == 3);
        test("Polynomial addition values", sum[0] == Fr(4) && sum[1] == Fr(6) && sum[2] == Fr(5));
        
        // Test multiplication (small example)
        vector<Fr> p1 = {Fr(1), Fr(2)};
        vector<Fr> p2 = {Fr(3), Fr(4)};
        vector<Fr> product = Polynomial::multiply(p1, p2);
        test("Polynomial multiplication", product.size() == 3);
        
        // Test vanishing polynomial
        vector<Fr> vanish = Polynomial::vanishing(4);
        test("Vanishing polynomial", vanish.size() == 5 && vanish[0] == Fr(-1) && vanish[4] == Fr(1));
    }
    
    void test_ntt_operations() {
        cout << "\nTesting NTT Operations..." << endl;
        
        // Test power of 2 check
        test("Power of 2 check true", NTT::is_power_of_2(8));
        test("Power of 2 check false", !NTT::is_power_of_2(6));
        
        // Test primitive root finding
        try {
            Fr root = NTT::find_primitive_root(8);
            test("Primitive root generation", true);
            
            // Test NTT transform and inverse
            vector<Fr> input = {Fr(1), Fr(2), Fr(3), Fr(4), Fr(0), Fr(0), Fr(0), Fr(0)};
            vector<Fr> transformed = NTT::transform(input, root, 8);
            vector<Fr> reconstructed = NTT::inverse_transform(transformed, root, 8);
            
            bool ntt_correct = true;
            for (size_t i = 0; i < input.size(); i++) {
                if (!(input[i] == reconstructed[i])) {
                    ntt_correct = false;
                    break;
                }
            }
            test("NTT roundtrip", ntt_correct);
        } catch (...) {
            test("NTT operations", false);
        }
    }
    
    void test_commitment_scheme() {
        cout << "\nTesting Commitment Scheme..." << endl;
        
        // Test setup
        CommitmentKey ck = PedersenCommitment::setup(10);
        test("Commitment key setup", ck.generators.size() == 10);
        
        // Test single value commitment
        Fr value = Fr(42);
        auto [commit, randomness] = PedersenCommitment::commit(ck, value);
        bool verify_result = PedersenCommitment::verify(ck, commit, value, randomness);
        test("Single value commitment", verify_result);
        
        // Test multi-value commitment
        vector<Fr> values = {Fr(1), Fr(2), Fr(3)};
        auto [multi_commit, multi_rand] = PedersenCommitment::commit(ck, values);
        bool multi_verify = PedersenCommitment::verify(ck, multi_commit, values, multi_rand);
        test("Multi-value commitment", multi_verify);
        
        // Test commitment arithmetic
        Fr scalar = Fr(5);
        Commitment scaled = commit * scalar;
        test("Commitment scaling", true); // Just test it doesn't crash
        
        Commitment sum = commit + multi_commit;
        test("Commitment addition", true); // Just test it doesn't crash
    }
    
    void test_sharpgs_protocol() {
        cout << "\nTesting SharpGS Protocol..." << endl;
        
        // Setup parameters
        SharpGSParams params(128, 32); // 128-bit security, 32-bit range
        SharpGSPublicParams pp = SharpGS::setup(params);
        test("SharpGS setup", pp.ck_com.generators.size() > 0);
        
        // Create witness and statement
        vector<Fr> values = {Fr(100), Fr(200)}; // Values in range [0, 2^32)
        Fr randomness = Utils::random_fr();
        
        auto [value_commit, _] = PedersenCommitment::commit(pp.ck_com, values);
        
        SharpGSWitness witness(values, randomness);
        SharpGSStatement statement(value_commit, Fr(1ULL << 32));
        
        // Test first message generation
        try {
            SharpGSFirstMessage first_msg = SharpGS::prove_first(pp, statement, witness);
            test("First message generation", true);
            
            // Test challenge generation
            SharpGSChallenge challenge = SharpGS::generate_challenge(params);
            test("Challenge generation", challenge.challenges.size() == params.repetitions);
            
            // Test response generation
            SharpGSResponse response = SharpGS::prove_second(pp, statement, witness, first_msg, challenge);
            test("Response generation", response.z_values.size() == params.repetitions);
            
            // Test complete proof
            SharpGSProof proof;
            proof.first_msg = first_msg;
            proof.challenge = challenge;
            proof.response = response;
            
            bool verification = SharpGS::verify(pp, statement, proof);
            test("Protocol verification", verification);
            
        } catch (const exception& e) {
            cout << "Error in SharpGS protocol: " << e.what() << endl;
            test("SharpGS protocol", false);
        }
        
        // Test non-interactive proof
        try {
            SharpGSProof ni_proof = SharpGS::prove(pp, statement, witness);
            bool ni_verification = SharpGS::verify(pp, statement, ni_proof);
            test("Non-interactive proof", ni_verification);
        } catch (...) {
            test("Non-interactive proof", false);
        }
    }
    
    void test_edge_cases() {
        cout << "\nTesting Edge Cases..." << endl;
        
        // Test empty polynomial operations
        vector<Fr> empty_poly;
        Fr eval_result = Polynomial::evaluate(empty_poly, Fr(1));
        test("Empty polynomial evaluation", eval_result == Fr(0));
        
        // Test single element polynomial
        vector<Fr> single = {Fr(42)};
        Fr single_eval = Polynomial::evaluate(single, Fr(10));
        test("Single element polynomial", single_eval == Fr(42));
        
        // Test utils functions
        Fr random_val = Utils::random_fr();
        test("Random Fr generation", true); // Just test it doesn't crash
        
        vector<Fr> random_vec = Utils::random_fr_vector(5);
        test("Random Fr vector", random_vec.size() == 5);
        
        G1 random_g1 = Utils::random_g1();
        test("Random G1 generation", true);
        
        // Test serialization
        vector<uint8_t> fr_data = Utils::serialize_fr(Fr(123));
        Fr restored_fr = Utils::deserialize_fr(fr_data);
        test("Fr serialization roundtrip", restored_fr == Fr(123));
    }
    
    void benchmark_sharpgs() {
        // Setup for benchmarking
        SharpGSParams params_small(80, 16);   // Smaller for faster benchmarking
        SharpGSParams params_large(128, 64);  // Full-size parameters
        
        cout << "\nSmall parameters (80-bit security, 16-bit range):" << endl;
        benchmark_single_proof(params_small);
        
        cout << "\nLarge parameters (128-bit security, 64-bit range):" << endl;
        benchmark_single_proof(params_large);
    }
    
    void benchmark_single_proof(const SharpGSParams& params) {
        SharpGSPublicParams pp = SharpGS::setup(params);
        
        vector<Fr> values = {Fr(42)};
        Fr randomness = Utils::random_fr();
        auto [commit, _] = PedersenCommitment::commit(pp.ck_com, values);
        
        SharpGSWitness witness(values, randomness);
        SharpGSStatement statement(commit, Fr(1ULL << params.range_bits));
        
        // Benchmark proof generation
        benchmark("Proof generation", [&]() {
            SharpGSProof proof = SharpGS::prove(pp, statement, witness);
        });
        
        // Generate proof for verification benchmark
        SharpGSProof proof = SharpGS::prove(pp, statement, witness);
        
        // Benchmark verification
        benchmark("Proof verification", [&]() {
            bool result = SharpGS::verify(pp, statement, proof);
            (void)result; // Suppress unused variable warning
        });
    }
};

int main() {
    try {
        TestSuite suite;
        suite.run_all_tests();
        return 0;
    } catch (const exception& e) {
        cerr << "Test suite error: " << e.what() << endl;
        return 1;
    }
}
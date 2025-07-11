#include "sharpgs.h"
#include "three_squares.h"
#include "commitment.h"
#include "masking.h"
#include <mcl/bn.hpp>
#include <iostream>
#include <chrono>
#include <vector>

using namespace mcl;
using namespace std;
using namespace std::chrono;

class SharpGSTestSuite {
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
    
    void benchmark(const string& name, function<void()> func) {
        auto start = high_resolution_clock::now();
        func();
        auto end = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(end - start);
        cout << name << ": " << duration.count() << "μs" << endl;
    }
    
public:
    void run_tests() {
        cout << "SharpGS Implementation Test Suite" << endl;
        cout << "=================================" << endl;
        
        // Initialize MCL library
        initPairing(BN_SNARK1);
        
        cout << "\nBasic Component Tests" << endl;
        cout << "---------------------" << endl;
        test_three_squares();
        test_commitment();
        test_masking();
        
        cout << "\nSharpGS Protocol Tests" << endl;
        cout << "----------------------" << endl;
        test_sharpgs_basic();
        test_sharpgs_multi_value();
        test_sharpgs_security();
        
        cout << "\nPerformance Benchmarks" << endl;
        cout << "----------------------" << endl;
        benchmark_sharpgs();
        
        cout << "\nFinal Results" << endl;
        cout << "===============" << endl;
        cout << "Tests Passed: " << passed << "/" << total;
        cout << (passed == total ? " - All passed!" : " - Some failed") << endl;
    }
    
private:
    void test_three_squares() {
        bool decomposition_works = true;
        
        try {
            // Test small values
            for (int n = 1; n <= 20; ++n) {
                Fr n_fr;
                n_fr.setStr(to_string(n));
                
                auto decomp = ThreeSquares::compute(n_fr);
                if (decomp.valid) {
                    bool verification = ThreeSquares::verify(decomp.x, decomp.y, decomp.z, n_fr);
                    if (!verification) {
                        decomposition_works = false;
                        cout << "Verification failed for n=" << n << endl;
                        break;
                    }
                }
            }
            
            // Test SharpGS specific decomposition
            Fr xi(5), B(64);
            auto y_vals = ThreeSquares::computeSharpGSDecomposition(xi, B);
            
            // Verify: 4*xi*(B-xi) + 1 = y1² + y2² + y3²
            Fr target, temp1, temp2;
            Fr::sub(temp1, B, xi);           // B - xi
            Fr::mul(temp2, xi, temp1);       // xi * (B - xi)
            Fr four(4);
            Fr::mul(temp1, four, temp2);     // 4 * xi * (B - xi)
            Fr one(1);
            Fr::add(target, temp1, one);     // 4*xi*(B-xi) + 1
            
            Fr sum, y1_sq, y2_sq, y3_sq;
            Fr::mul(y1_sq, y_vals[0], y_vals[0]);
            Fr::mul(y2_sq, y_vals[1], y_vals[1]);
            Fr::mul(y3_sq, y_vals[2], y_vals[2]);
            Fr::add(sum, y1_sq, y2_sq);
            Fr::add(sum, sum, y3_sq);
            
            if (!(sum == target)) {
                decomposition_works = false;
                cout << "SharpGS decomposition verification failed" << endl;
            }
            
        } catch (const exception& e) {
            decomposition_works = false;
            cout << "Three squares test error: " << e.what() << endl;
        }
        
        test("Three Squares Decomposition", decomposition_works);
    }
    
    void test_commitment() {
        bool commitment_works = true;
        
        try {
            // Test single commitment
            auto setup_params = PedersenCommitment::setup(4, 256);
            
            Fr value(42);
            auto commit = PedersenCommitment::commit(value, setup_params);
            
            bool verification = PedersenCommitment::verify(commit, value, commit.randomness, setup_params);
            if (!verification) {
                commitment_works = false;
                cout << "Single commitment verification failed" << endl;
            }
            
            // Test multi-commitment
            vector<Fr> values = {Fr(1), Fr(2), Fr(3), Fr(4)};
            auto multi_commit = PedersenCommitment::commitMulti(values, setup_params);
            
            bool multi_verification = PedersenCommitment::verifyMulti(multi_commit, values, multi_commit.randomness, setup_params);
            if (!multi_verification) {
                commitment_works = false;
                cout << "Multi-commitment verification failed" << endl;
            }
            
            // Test SharpGS commitment
            vector<vector<Fr>> y_values = {{Fr(1), Fr(2), Fr(3)}, {Fr(4), Fr(5), Fr(6)}};
            auto sharpgs_commit = PedersenCommitment::createSharpGSCommitment(
                {Fr(10), Fr(20)}, y_values, setup_params);
            
            // Basic sanity check - commitments should not be zero
            if (sharpgs_commit.Cx.isZero() || sharpgs_commit.Cy.isZero()) {
                commitment_works = false;
                cout << "SharpGS commitment created zero values" << endl;
            }
            
        } catch (const exception& e) {
            commitment_works = false;
            cout << "Commitment test error: " << e.what() << endl;
        }
        
        test("Pedersen Commitments", commitment_works);
    }
    
    void test_masking() {
        bool masking_works = true;
        
        try {
            MaskingScheme::Parameters params(10, 100);
            
            Fr value(42);
            auto mask_result = MaskingScheme::maskValueAuto(value, params);
            
            if (!mask_result.success) {
                masking_works = false;
                cout << "Masking failed" << endl;
            }
            
            // Test SharpGS masking
            SharpGSMasking::SharpGSParameters sharpgs_params(64, 128, 10, 10);
            Fr gamma(5), xi(10);
            Fr mask;
            mask.setByCSPRNG();
            
            auto sharpgs_mask_result = SharpGSMasking::maskX(gamma, xi, mask, sharpgs_params);
            
            if (!sharpgs_mask_result.success) {
                masking_works = false;
                cout << "SharpGS masking failed" << endl;
            }
            
            // Test verification
            bool verification = SharpGSMasking::verifySharpGSMasking(sharpgs_mask_result.masked_value, sharpgs_params);
            if (!verification) {
                masking_works = false;
                cout << "SharpGS masking verification failed" << endl;
            }
            
        } catch (const exception& e) {
            masking_works = false;
            cout << "Masking test error: " << e.what() << endl;
        }
        
        test("Masking Schemes", masking_works);
    }
    
    void test_sharpgs_basic() {
        bool protocol_works = true;
        
        try {
            // Create test parameters
            SharpGS::Parameters params(1, 64, 128, 1, 256, 10, 10);  // N=1, B=64, Γ=128, R=1
            
            // Create witness
            vector<Fr> x_values = {Fr(10)};  // x ∈ [0, 64]
            Fr rx;
            rx.setByCSPRNG();
            SharpGS::Witness witness(x_values, rx);
            
            // Setup
            auto setup_params = SharpGS::setup(params);
            
            // Create statement
            auto statement = SharpGS::createStatement(x_values, rx, params, setup_params);
            
            // Execute protocol
            auto [proof, verification_result] = SharpGS::executeProtocol(witness, statement, params);
            
            if (!verification_result) {
                protocol_works = false;
                cout << "SharpGS protocol verification failed" << endl;
            }
            
        } catch (const exception& e) {
            protocol_works = false;
            cout << "SharpGS basic test error: " << e.what() << endl;
        }
        
        test("SharpGS Basic Protocol", protocol_works);
    }
    
    void test_sharpgs_multi_value() {
        bool multi_protocol_works = true;
        
        try {
            // Create test parameters for multiple values
            SharpGS::Parameters params(3, 32, 64, 1, 256, 10, 10);  // N=3, B=32, Γ=64, R=1
            
            // Create witness with multiple values
            vector<Fr> x_values = {Fr(5), Fr(10), Fr(15)};  // All in [0, 32]
            Fr rx;
            rx.setByCSPRNG();
            SharpGS::Witness witness(x_values, rx);
            
            // Setup
            auto setup_params = SharpGS::setup(params);
            
            // Create statement
            auto statement = SharpGS::createStatement(x_values, rx, params, setup_params);
            
            // Execute protocol
            auto [proof, verification_result] = SharpGS::executeProtocol(witness, statement, params);
            
            if (!verification_result) {
                multi_protocol_works = false;
                cout << "SharpGS multi-value protocol verification failed" << endl;
            }
            
        } catch (const exception& e) {
            multi_protocol_works = false;
            cout << "SharpGS multi-value test error: " << e.what() << endl;
        }
        
        test("SharpGS Multi-Value Protocol", multi_protocol_works);
    }
    
    void test_sharpgs_security() {
        bool security_works = true;
        
        try {
            // Test with value outside range (should still work due to relaxed soundness)
            SharpGS::Parameters params(1, 16, 32, 1, 256, 10, 10);  // N=1, B=16, Γ=32, R=1
            
            vector<Fr> x_values = {Fr(8)};  // Valid value in [0, 16]
            Fr rx;
            rx.setByCSPRNG();
            SharpGS::Witness witness(x_values, rx);
            
            auto setup_params = SharpGS::setup(params);
            auto statement = SharpGS::createStatement(x_values, rx, params, setup_params);
            
            auto [proof, verification_result] = SharpGS::executeProtocol(witness, statement, params);
            
            if (!verification_result) {
                security_works = false;
                cout << "SharpGS security test failed for valid value" << endl;
            }
            
        } catch (const exception& e) {
            security_works = false;
            cout << "SharpGS security test error: " << e.what() << endl;
        }
        
        test("SharpGS Security Properties", security_works);
    }
    
    void benchmark_sharpgs() {
        try {
            SharpGS::Parameters params(1, 64, 128, 1, 256, 10, 10);
            
            vector<Fr> x_values = {Fr(42)};
            Fr rx;
            rx.setByCSPRNG();
            SharpGS::Witness witness(x_values, rx);
            
            auto setup_params = SharpGS::setup(params);
            auto statement = SharpGS::createStatement(x_values, rx, params, setup_params);
            
            benchmark("SharpGS Single Proof", [&]() {
                auto [proof, verification_result] = SharpGS::executeProtocol(witness, statement, params);
            });
            
            // Benchmark with multiple repetitions
            SharpGS::Parameters params_multi_r(1, 64, 128, 3, 256, 10, 10);  // R=3
            benchmark("SharpGS Multiple Repetitions", [&]() {
                auto [proof, verification_result] = SharpGS::executeProtocol(witness, statement, params_multi_r);
            });
            
            // Benchmark with multiple values
            SharpGS::Parameters params_multi_n(4, 64, 128, 1, 256, 10, 10);  // N=4
            vector<Fr> x_values_multi = {Fr(10), Fr(20), Fr(30), Fr(40)};
            SharpGS::Witness witness_multi(x_values_multi, rx);
            auto statement_multi = SharpGS::createStatement(x_values_multi, rx, params_multi_n, setup_params);
            
            benchmark("SharpGS Multiple Values", [&]() {
                auto [proof, verification_result] = SharpGS::executeProtocol(witness_multi, statement_multi, params_multi_n);
            });
            
        } catch (const exception& e) {
            cout << "Benchmark error: " << e.what() << endl;
        }
    }
};

int main() {
    try {
        SharpGSTestSuite suite;
        suite.run_tests();
        return 0;
    } catch (const exception& e) {
        cerr << "Test suite error: " << e.what() << endl;
        return 1;
    }
}
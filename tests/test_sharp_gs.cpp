// tests/test_sharp_gs.cpp - Enhanced with debugging
#include <mcl/bn.hpp>
#include <iostream>
#include <chrono>
#include <vector>
#include <cassert>

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
    
    void benchmark(const string& name, function<void()> func) {
        auto start = high_resolution_clock::now();
        func();
        auto end = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(end - start);
        cout << name << ": " << duration.count() << "μs" << endl;
    }

public:
    void run_tests() {
        cout << "SharpGS Range Proof Test Suite" << endl;
        cout << "==============================" << endl;
        
        // Initialize pairing
        initPairing(BN_SNARK1);
        
        cout << "\nSharpGS Protocol Tests" << endl;
        cout << "----------------------" << endl;
        test_sharp_gs_basic();
        
        cout << "\nFinal Results" << endl;
        cout << "===============" << endl;
        cout << "Tests Passed: " << passed << "/" << total;
        cout << (passed == total ? " - All passed!" : " - Some failed") << endl;
    }

private:
    void test_sharp_gs_basic() {
        bool success = true;
        
        try {
            cout << "  Testing basic SharpGS protocol..." << endl;
            
            // Setup parameters
            Fr B(100);
            cout << "  - Setting up parameters for range [0, 100]..." << endl;
            auto pp = SharpGS::setup(1, B, 128);
            cout << "    Repetitions: " << pp.repetitions << ", Gamma max: " << pp.gamma_max << endl;
            
            // Create witness
            SharpGS::Witness witness;
            witness.values = {Fr(42)};
            witness.randomness.setByCSPRNG();
            cout << "  - Created witness with value 42" << endl;
            
            // Create statement
            cout << "  - Computing commitment..." << endl;
            auto commit = PedersenMultiCommitment::commit(pp.ck_com, witness.values, witness.randomness);
            SharpGS::Statement stmt;
            stmt.commitment = commit.value;
            stmt.B = B;
            cout << "  - Statement created" << endl;
            
            // Generate proof
            cout << "  - Generating first message..." << endl;
            auto first_msg = SharpGS::prove_first(pp, stmt, witness);
            cout << "    First message generated with " << first_msg.mask_commitments_x.size() << " repetitions" << endl;
            
            cout << "  - Generating challenge..." << endl;
            auto challenge = SharpGS::generate_challenge(pp);
            cout << "    Challenge generated with " << challenge.gammas.size() << " gamma values" << endl;
            
            cout << "  - Computing response..." << endl;
            cout << "    BEFORE prove_response call" << endl;
            auto response = SharpGS::prove_response(pp, stmt, witness, first_msg, challenge);
            cout << "    AFTER prove_response call" << endl;
            cout << "    Response computed with " << response.z_values.size() << " repetitions" << endl;
            
            // MANUAL RESPONSE CREATION FOR DEBUGGING
            cout << "    Creating manual response..." << endl;
            SharpGS::Response manual_response;
            manual_response.z_values.resize(pp.repetitions);
            manual_response.z_squares.resize(pp.repetitions);
            manual_response.t_x.resize(pp.repetitions);
            manual_response.t_y.resize(pp.repetitions);
            manual_response.t_star.resize(pp.repetitions);
            
            auto square_decomp_values = SharpGS::compute_square_decomposition_values(witness.values, pp.B);
            
            for (size_t k = 0; k < pp.repetitions; k++) {
                Fr gamma = challenge.gammas[k];
                manual_response.z_values[k].resize(pp.num_values);
                manual_response.z_squares[k].resize(pp.num_values);
                
                for (size_t i = 0; i < pp.num_values; i++) {
                    // Manual z computation
                    Fr gamma_xi;
                    Fr::mul(gamma_xi, gamma, witness.values[i]);
                    Fr::add(manual_response.z_values[k][i], gamma_xi, first_msg.x_tildes[k][i]);
                    
                    // Manual squares computation
                    manual_response.z_squares[k][i].resize(3);
                    for (size_t j = 0; j < 3; j++) {
                        Fr gamma_yij;
                        Fr::mul(gamma_yij, gamma, square_decomp_values[i][j]);
                        Fr::add(manual_response.z_squares[k][i][j], gamma_yij, first_msg.y_tildes[k][3*i + j]);
                    }
                }
                
                // Manual randomness computation
                Fr gamma_rx;
                Fr::mul(gamma_rx, gamma, witness.randomness);
                Fr::add(manual_response.t_x[k], gamma_rx, first_msg.re_k_x[k]);
                
                Fr gamma_ry;
                Fr::mul(gamma_ry, gamma, first_msg.ry);
                Fr::add(manual_response.t_y[k], gamma_ry, first_msg.re_k_y[k]);
                
                Fr gamma_r_star;
                Fr::mul(gamma_r_star, gamma, first_msg.r_star_values[k]);
                Fr::add(manual_response.t_star[k], gamma_r_star, first_msg.re_star_k[k]);
            }
            
            cout << "    Manual response created" << endl;
            
            SharpGS::Proof proof;
            proof.first_msg = first_msg;
            proof.response = response;
            
            // Manual step-by-step verification
            cout << "  - Manual step-by-step verification..." << endl;
            
            // Test mask storage first
            cout << "    Testing mask storage..." << endl;
            cout << "    first_msg.x_tildes size: " << first_msg.x_tildes.size() << endl;
            if (first_msg.x_tildes.size() > 0) {
                cout << "    first_msg.x_tildes[0] size: " << first_msg.x_tildes[0].size() << endl;
            }
            
            Fr gamma = challenge.gammas[0];
            char gamma_str[256], witness_str[256], mask_str[256];
            gamma.getStr(gamma_str, sizeof(gamma_str), 10);
            witness.values[0].getStr(witness_str, sizeof(witness_str), 10);
            first_msg.x_tildes[0][0].getStr(mask_str, sizeof(mask_str), 10);
            
            cout << "    gamma = " << gamma_str << endl;
            cout << "    witness = " << witness_str << endl;
            cout << "    stored mask = " << mask_str << endl;
            
            // Manual z computation
            Fr manual_z, gamma_times_witness;
            Fr::mul(gamma_times_witness, gamma, witness.values[0]);
            Fr::add(manual_z, gamma_times_witness, first_msg.x_tildes[0][0]);
            
            char manual_str[256], response_str[256];
            manual_z.getStr(manual_str, sizeof(manual_str), 10);
            response.z_values[0][0].getStr(response_str, sizeof(response_str), 10);
            
            cout << "    manual z = " << manual_str << endl;
            cout << "    response z = " << response_str << endl;
            
            // Test if this is a simple recomputation issue
            cout << "    Testing direct recomputation..." << endl;
            Fr test_z;
            Fr::mul(test_z, gamma, witness.values[0]);
            Fr::add(test_z, test_z, first_msg.x_tildes[0][0]);
            
            char test_str[256];
            test_z.getStr(test_str, sizeof(test_str), 10);
            cout << "    test z = " << test_str << endl;
            
            bool z_correct = (manual_z == response.z_values[0][0]);
            cout << "    z computation correct: " << (z_correct ? "YES" : "NO") << endl;
            
            if (!z_correct) {
                cout << "    ERROR: Response computation is wrong!" << endl;
                
                // Test if the issue is in the response array itself
                cout << "    Testing response array modification..." << endl;
                Fr original_response = response.z_values[0][0];
                response.z_values[0][0] = manual_z;
                
                bool now_correct = (manual_z == response.z_values[0][0]);
                cout << "    After manual assignment: " << (now_correct ? "CORRECT" : "STILL_WRONG") << endl;
                
                // Restore and check
                response.z_values[0][0] = original_response;
                
                success = false;
            } else {
                // Only test verification if response is correct
                bool verified = SharpGS::verify(pp, stmt, proof, challenge);
                cout << "    Verification result: " << (verified ? "PASS" : "FAIL") << endl;
                success = verified;
            }
            
        } catch (const exception& e) {
            cout << "  - ERROR: Exception in basic SharpGS test: " << e.what() << endl;
            success = false;
        }
        
        test("SharpGS Basic Range Proof", success);
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
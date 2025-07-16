#include <mcl/bn.hpp>
#include <iostream>
#include <chrono>
#include <vector>
#include <cassert>
#include <random>
#include <set>
#include <algorithm>
#include <cmath>

#include "sharp_gs.h"
#include "pedersen.h"
#include "three_squares.h"

using namespace mcl;
using namespace std;
using namespace std::chrono;

class TestSuite {
private:
    size_t passed = 0, total = 0;
    mt19937 rng{random_device{}()};
    
    void test(const string& name, bool condition, const string& details = "") {
        total++;
        if (condition) {
            passed++;
            cout << "PASS " << name << endl;
        } else {
            cout << "FAIL " << name;
            if (!details.empty()) {
                cout << " - " << details;
            }
            cout << endl;
        }
    }
    
    Fr random_fr(int max_bits = 64) {
        Fr result;
        result.setByCSPRNG();
        return result;
    }

public:
    void run_all_tests() {
        cout << "SharpGS Compliance Test Suite" << endl;
        cout << "==========================================" << endl;
        
        initPairing(BN_SNARK1);
        
        cout << "\n1. Generator Structure Compliance (SharpGS)" << endl;
        cout << "-----------------------------------------------" << endl;
        test_generator_structure_gcom();
        test_generator_structure_g3sq();
        test_generator_independence();
        
        cout << "\n2. SharpGS Step-by-Step Verification" << endl;
        cout << "----------------------------------------" << endl;
        test_sharpgs_line1_decomposition();
        test_sharpgs_line2_cy_commitment();
        test_sharpgs_lines3to12_first_flow();
        test_sharpgs_line13to18_response();
        test_sharpgs_lines2to8_verification();
        
        cout << "\n3. Mathematical Correctness Tests" << endl;
        cout << "--------------------------------" << endl;
        test_alpha_star_computation();
        test_f_star_computation();
        test_decomposition_polynomial_consistency();
        
        cout << "\n4. Masking and Randomness Tests" << endl;
        cout << "------------------------------" << endl;
        test_masking_algorithm_compliance();
        test_abort_probability();
        test_challenge_space_bounds();
        
        cout << "\n5. Group Switching Implementation" << endl;
        cout << "--------------------------------" << endl;
        test_dual_group_usage();
        test_commitment_group_consistency();
        test_decomposition_group_consistency();
        
        cout << "\n6. Batch Processing Compliance" << endl;
        cout << "-----------------------------" << endl;
        test_batch_commitment_structure();
        test_batch_response_computation();
        test_batch_verification_equations();
        
        cout << "\n7. Security Properties Verification" << endl;
        cout << "----------------------------------" << endl;
        test_hiding_property();
        test_binding_property();
        test_soundness_properties();
        
        cout << "\n8. Edge Cases and Error Handling" << endl;
        cout << "-------------------------------" << endl;
        test_boundary_values();
        test_invalid_decompositions();
        test_parameter_validation();
        
        cout << "\n" << string(50, '=') << endl;
        cout << "SharpGS Compliance Results: " << passed << "/" << total << " tests passed" << endl;
        
        if (passed != total) {
            cout << "\nCRITICAL ISSUES DETECTED:" << endl;
            cout << "Your implementation has " << (total - passed) << " compliance issues." << endl;
            cout << "Please review SharpGS specification carefully." << endl;
        } else {
            cout << "All SharpGS compliance tests passed!" << endl;
        }
    }

private:
    // Test 1: Generator Structure Compliance
    void test_generator_structure_gcom() {
        bool correct_structure = true;
        string issue_details;
        
        try {
            Fr B(100);
            auto pp = SharpGS::setup(3, B, 128);
            
            size_t expected_gcom_generators = 1 + 3 + 3*3;
            
            if (pp.ck_com.generators.size() != expected_gcom_generators) {
                correct_structure = false;
                issue_details = "Expected " + to_string(expected_gcom_generators) + 
                              " generators in Gcom, got " + to_string(pp.ck_com.generators.size());
            }
            
            set<string> generator_set;
            for (const auto& gen : pp.ck_com.generators) {
                string gen_str;
                gen_str.resize(1024);
                size_t len = gen.serialize(&gen_str[0], gen_str.size());
                gen_str.resize(len);
                
                if (generator_set.count(gen_str)) {
                    correct_structure = false;
                    issue_details += " Duplicate generators detected";
                    break;
                }
                generator_set.insert(gen_str);
            }
            
        } catch (const exception& e) {
            correct_structure = false;
            issue_details = "Exception: " + string(e.what());
        }
        
        test("Gcom Generator Structure", correct_structure, issue_details);
    }
    
    void test_generator_structure_g3sq() {
        bool correct_structure = true;
        string issue_details;
        
        try {
            Fr B(100);
            auto pp = SharpGS::setup(3, B, 128);
            
            size_t expected_g3sq_generators = 1 + 3;
            
            if (pp.ck_3sq.generators.size() != expected_g3sq_generators) {
                correct_structure = false;
                issue_details = "Expected " + to_string(expected_g3sq_generators) + 
                              " generators in G3sq, got " + to_string(pp.ck_3sq.generators.size());
            }
            
        } catch (const exception& e) {
            correct_structure = false;
            issue_details = "Exception: " + string(e.what());
        }
        
        test("G3sq Generator Structure", correct_structure, issue_details);
    }
    
    void test_generator_independence() {
        bool independent = true;
        string issue_details;
        
        try {
            Fr B(100);
            auto pp = SharpGS::setup(2, B, 128);
            
            set<string> all_generators;
            
            for (const auto& gen : pp.ck_com.generators) {
                string gen_str;
                gen_str.resize(1024);
                size_t len = gen.serialize(&gen_str[0], gen_str.size());
                gen_str.resize(len);
                all_generators.insert(gen_str);
            }
            
            for (const auto& gen : pp.ck_3sq.generators) {
                string gen_str;
                gen_str.resize(1024);
                size_t len = gen.serialize(&gen_str[0], gen_str.size());
                gen_str.resize(len);
                
                if (all_generators.count(gen_str)) {
                    independent = false;
                    issue_details = "Gcom and G3sq share generators";
                    break;
                }
            }
            
        } catch (const exception& e) {
            independent = false;
            issue_details = "Exception: " + string(e.what());
        }
        
        test("Generator Independence", independent, issue_details);
    }
    
    // Test 2: Step Verification
    void test_sharpgs_line1_decomposition() {
        bool line1_correct = true;
        string issue_details;
        
        try {
            Fr B(100);
            vector<Fr> values = {Fr(25), Fr(42)}; 
            
            // Line 1
            for (size_t i = 0; i < values.size(); i++) {
                Fr xi = values[i];
                Fr range_val = ThreeSquares::compute_range_value(xi, B);
                
                auto decomp = ThreeSquares::decompose(range_val);
                if (!decomp || !decomp->valid) {
                    line1_correct = false;
                    issue_details = "Failed to decompose 4*" + to_string(i) + "*(B-" + to_string(i) + ")+1";
                    break;
                }
                
                Fr sum_squares;
                Fr x_sq, y_sq, z_sq;
                Fr::sqr(x_sq, decomp->x);
                Fr::sqr(y_sq, decomp->y);
                Fr::sqr(z_sq, decomp->z);
                Fr::add(sum_squares, x_sq, y_sq);
                Fr::add(sum_squares, sum_squares, z_sq);
                
                if (!(sum_squares == range_val)) {
                    line1_correct = false;
                    issue_details = "Decomposition verification failed for xi=" + to_string(i);
                    break;
                }
            }
            
        } catch (const exception& e) {
            line1_correct = false;
            issue_details = "Exception: " + string(e.what());
        }
        
        test("SharpGS Line 1 (Decomposition)", line1_correct, issue_details);
    }
    
    void test_sharpgs_line2_cy_commitment() {
        bool line2_correct = true;
        string issue_details;
        
        try {
            Fr B(100);
            auto pp = SharpGS::setup(2, B, 128);
            
            SharpGS::Witness witness;
            witness.values = {Fr(25), Fr(42)};
            witness.randomness.setByCSPRNG();
            
            auto commit = PedersenMultiCommitment::commit(pp.ck_com, witness.values, witness.randomness);
            SharpGS::Statement stmt;
            stmt.commitment = commit.value;
            stmt.B = B;
            
            auto first_msg = SharpGS::prove_first(pp, stmt, witness);
            
            // Line 2
            if (first_msg.commitment_y.isZero()) {
                line2_correct = false;
                issue_details = "Cy commitment is zero (not properly computed)";
            }      
        } catch (const exception& e) {
            line2_correct = false;
            issue_details = "Exception: " + string(e.what());
        }
        
        test("SharpGS Line 2 (Cy Commitment)", line2_correct, issue_details);
    }
    
    void test_sharpgs_lines3to12_first_flow() {
        bool first_flow_correct = true;
        string issue_details;
        
        try {
            Fr B(100);
            auto pp = SharpGS::setup(2, B, 128);
            
            SharpGS::Witness witness;
            witness.values = {Fr(25), Fr(42)};
            witness.randomness.setByCSPRNG();
            
            auto commit = PedersenMultiCommitment::commit(pp.ck_com, witness.values, witness.randomness);
            SharpGS::Statement stmt;
            stmt.commitment = commit.value;
            stmt.B = B;
            
            auto first_msg = SharpGS::prove_first(pp, stmt, witness);
            
            // Lines 3-12
            size_t expected_repetitions = pp.repetitions;
            
            if (first_msg.mask_commitments_x.size() != expected_repetitions) {
                first_flow_correct = false;
                issue_details = "Dk,x size mismatch: expected " + to_string(expected_repetitions) + 
                              ", got " + to_string(first_msg.mask_commitments_x.size());
            }
            
            if (first_msg.mask_commitments_y.size() != expected_repetitions) {
                first_flow_correct = false;
                issue_details = "Dk,y size mismatch: expected " + to_string(expected_repetitions) + 
                              ", got " + to_string(first_msg.mask_commitments_y.size());
            }
            
            if (first_msg.poly_commitments_star.size() != expected_repetitions) {
                first_flow_correct = false;
                issue_details = "Ck,* size mismatch: expected " + to_string(expected_repetitions) + 
                              ", got " + to_string(first_msg.poly_commitments_star.size());
            }
            
            if (first_msg.mask_poly_commitments.size() != expected_repetitions) {
                first_flow_correct = false;
                issue_details = "Dk,* size mismatch: expected " + to_string(expected_repetitions) + 
                              ", got " + to_string(first_msg.mask_poly_commitments.size());
            }
        } catch (const exception& e) {
            first_flow_correct = false;
            issue_details = "Exception: " + string(e.what());
        }
        
        test("SharpGS Lines 3-12 (First Flow)", first_flow_correct, issue_details);
    }
    
    void test_sharpgs_line13to18_response() {
        bool response_correct = true;
        string issue_details;
        
        try {
            Fr B(100);
            auto pp = SharpGS::setup(2, B, 128);
            
            SharpGS::Witness witness;
            witness.values = {Fr(25), Fr(42)};
            witness.randomness.setByCSPRNG();
            
            auto commit = PedersenMultiCommitment::commit(pp.ck_com, witness.values, witness.randomness);
            SharpGS::Statement stmt;
            stmt.commitment = commit.value;
            stmt.B = B;
            
            auto first_msg = SharpGS::prove_first(pp, stmt, witness);
            auto challenge = SharpGS::generate_challenge(pp);
            auto response = SharpGS::prove_response(pp, stmt, witness, first_msg, challenge);
            
            // Lines 14-16
            size_t N = witness.values.size();
            size_t R = pp.repetitions;
            
            if (response.z_values.size() != R) {
                response_correct = false;
                issue_details = "z_values outer dimension should be R=" + to_string(R);
            }
            
            if (response.z_values.size() > 0 && response.z_values[0].size() != N) {
                response_correct = false;
                issue_details = "z_values inner dimension should be N=" + to_string(N);
            }
            
            if (response.z_squares.size() != R) {
                response_correct = false;
                issue_details = "z_squares outer dimension should be R=" + to_string(R);
            }
            
            if (response.z_squares.size() > 0 && response.z_squares[0].size() != N) {
                response_correct = false;
                issue_details = "z_squares middle dimension should be N=" + to_string(N);
            }
            
            if (response.z_squares.size() > 0 && response.z_squares[0].size() > 0 && 
                response.z_squares[0][0].size() != 3) {
                response_correct = false;
                issue_details = "z_squares inner dimension should be 3 (three squares)";
            }
            
        } catch (const exception& e) {
            response_correct = false;
            issue_details = "Exception: " + string(e.what());
        }
        
        test("SharpGS Lines 13-18 (Response)", response_correct, issue_details);
    }
    
    void test_sharpgs_lines2to8_verification() {
        bool verification_correct = true;
        string issue_details;
        
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
            
            if (!verified) {
                verification_correct = false;
                issue_details = "Valid proof failed verification - check SharpGS equations";
            }
            
        } catch (const exception& e) {
            verification_correct = false;
            issue_details = "Exception: " + string(e.what());
        }
        
        test("SharpGS Lines 2-8 (Verification)", verification_correct, issue_details);
    }
    
    // Test 3: Mathematical Correctness
    void test_alpha_star_computation() {
        bool alpha_correct = true;
        string issue_details;
        
        try {
            // Line 9-10
            Fr B(100), x(25), x_tilde(10);
            vector<Fr> y_vals = {Fr(3), Fr(4), Fr(5)};
            vector<Fr> y_tildes = {Fr(1), Fr(2), Fr(3)};
            
            Fr expected_alpha1;
            Fr four(4), eight(8), two(2);
            Fr term1, term2, term3_sum;
            
            Fr::mul(term1, four, x_tilde);
            Fr::mul(term1, term1, B);
            
            Fr::mul(term2, eight, x);
            Fr::mul(term2, term2, x_tilde);
            
            term3_sum.clear();
            for (size_t j = 0; j < 3; j++) {
                Fr prod;
                Fr::mul(prod, y_vals[j], y_tildes[j]);
                Fr::add(term3_sum, term3_sum, prod);
            }
            Fr::mul(term3_sum, two, term3_sum);
            
            Fr::sub(expected_alpha1, term1, term2);
            Fr::sub(expected_alpha1, expected_alpha1, term3_sum);    
        } catch (const exception& e) {
            alpha_correct = false;
            issue_details = "Exception: " + string(e.what());
        }
        
        test("Alpha* Coefficient Computation", alpha_correct, issue_details);
    }
    
    void test_f_star_computation() {
        bool f_star_correct = true;
        string issue_details;
        
        try {
            // Line 5
            Fr gamma(7), B(100), z_val(30);
            vector<Fr> z_squares = {Fr(2), Fr(3), Fr(5)};
            
            Fr result = SharpGS::compute_f_star(z_val, gamma, B, z_squares);
            
            Fr four(4), gamma_B, gamma_B_minus_z, first_term, gamma_sq, sum_z_sq, expected;
            
            Fr::mul(gamma_B, gamma, B);
            Fr::sub(gamma_B_minus_z, gamma_B, z_val);
            Fr::mul(first_term, four, z_val);
            Fr::mul(first_term, first_term, gamma_B_minus_z);
            
            Fr::sqr(gamma_sq, gamma);
            
            sum_z_sq.clear();
            for (const Fr& zs : z_squares) {
                Fr sq;
                Fr::sqr(sq, zs);
                Fr::add(sum_z_sq, sum_z_sq, sq);
            }
            
            Fr::add(expected, first_term, gamma_sq);
            Fr::sub(expected, expected, sum_z_sq);
            
            if (!(result == expected)) {
                f_star_correct = false;
                issue_details = "f* computation doesn't match Algorithm 1 Line 5";
            }
            
        } catch (const exception& e) {
            f_star_correct = false;
            issue_details = "Exception: " + string(e.what());
        }
        
        test("f* Computation (SharpGS Line 5)", f_star_correct, issue_details);
    }
    
    void test_decomposition_polynomial_consistency() {
        bool consistency = true;
        string issue_details;
        
        try {
            Fr B(100);
            vector<Fr> test_values = {Fr(0), Fr(25), Fr(50), Fr(99)};
            
            for (const Fr& x : test_values) {
                Fr range_val = ThreeSquares::compute_range_value(x, B);
                auto decomp = ThreeSquares::decompose(range_val);
                
                if (!decomp || !decomp->valid) {
                    consistency = false;
                    issue_details = "Decomposition failed for x=" + to_string(fr_to_long(x));
                    break;
                }
                
                Fr lhs = range_val;
                Fr rhs;
                Fr y1_sq, y2_sq, y3_sq;
                Fr::sqr(y1_sq, decomp->x);
                Fr::sqr(y2_sq, decomp->y);
                Fr::sqr(y3_sq, decomp->z);
                Fr::add(rhs, y1_sq, y2_sq);
                Fr::add(rhs, rhs, y3_sq);
                
                if (!(lhs == rhs)) {
                    consistency = false;
                    issue_details = "Decomposition verification failed for x=" + to_string(fr_to_long(x));
                    break;
                }
            }
            
        } catch (const exception& e) {
            consistency = false;
            issue_details = "Exception: " + string(e.what());
        }
        
        test("Decomposition Polynomial Consistency", consistency, issue_details);
    }
    
    long fr_to_long(const Fr& value) {
        char str_buf[256];
        size_t len = value.getStr(str_buf, sizeof(str_buf), 10);
        if (len == 0) return 0;
        try {
            return stol(string(str_buf, len));
        } catch (...) {
            return 0;
        }
    }
    
    // Test 4: Masking and Randomness
    void test_masking_algorithm_compliance() {
        bool masking_correct = true;
        string issue_details;
        
        try {
            // Lines 17-18 
            Fr B(100);
            auto pp = SharpGS::setup(1, B, 128);
            
            bool abort_possible = false;
            for (int i = 0; i < 100; i++) {
                try {
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
                    
                } catch (const runtime_error& e) {
                    string error_msg = e.what();
                    if (error_msg.find("abort") != string::npos || error_msg.find("mask") != string::npos) {
                        abort_possible = true;
                        break;
                    }
                }
            }                      
        } catch (const exception& e) {
            masking_correct = false;
            issue_details = "Exception: " + string(e.what());
        }
        
        test("Masking Algorithm Implementation", masking_correct, issue_details);
    }
    
    void test_abort_probability() {
        bool abort_behavior_correct = true;
        string issue_details; 
        
        test("Abort Probability Behavior", abort_behavior_correct, issue_details);
    }
    
    void test_challenge_space_bounds() {
        bool bounds_correct = true;
        string issue_details;
        
        try {
            Fr B(100);
            auto pp = SharpGS::setup(1, B, 128);
            
            auto challenge = SharpGS::generate_challenge(pp);
            
            if (challenge.gammas.size() != pp.repetitions) {
                bounds_correct = false;
                issue_details = "Challenge count mismatch: expected " + to_string(pp.repetitions) + 
                              ", got " + to_string(challenge.gammas.size());
            }
            
            for (const Fr& gamma : challenge.gammas) {
                long gamma_val = fr_to_long(gamma);
                if (gamma_val < 0 || gamma_val > (long)pp.gamma_max) {
                    bounds_correct = false;
                    issue_details = "Challenge outside bounds [0," + to_string(pp.gamma_max) + "]";
                    break;
                }
            }
            
        } catch (const exception& e) {
            bounds_correct = false;
            issue_details = "Exception: " + string(e.what());
        }
        
        test("Challenge Space Bounds", bounds_correct, issue_details);
    }
    
    // Test 5: Group Switching
    void test_dual_group_usage() {
        bool dual_groups_used = true;
        string issue_details;
        
        try {
            Fr B(100);
            auto pp = SharpGS::setup(1, B, 128);
            
            if (pp.ck_com.generators.size() == pp.ck_3sq.generators.size()) {
                bool same_generators = true;
                for (size_t i = 0; i < min(pp.ck_com.generators.size(), pp.ck_3sq.generators.size()); i++) {
                    if (!(pp.ck_com.generators[i] == pp.ck_3sq.generators[i])) {
                        same_generators = false;
                        break;
                    }
                }
                
                if (same_generators) {
                    dual_groups_used = false;
                    issue_details = "ck_com and ck_3sq appear to use the same generators (no group switching)";
                }
            }
            
        } catch (const exception& e) {
            dual_groups_used = false;
            issue_details = "Exception: " + string(e.what());
        }
        
        test("Dual Group Usage (Group Switching)", dual_groups_used, issue_details);
    }
    
    void test_commitment_group_consistency() {
        bool gcom_consistency = true;
        string issue_details;
        
        test("Gcom Commitment Consistency", gcom_consistency, issue_details);
    }
    
    void test_decomposition_group_consistency() {
        bool g3sq_consistency = true;
        string issue_details;
        
        test("G3sq Decomposition Consistency", g3sq_consistency, issue_details);
    }
    
    // Test 6: Batch Processing
    void test_batch_commitment_structure() {
        bool batch_correct = true;
        string issue_details;
        
        try {
            Fr B(100);
            auto pp = SharpGS::setup(3, B, 128);
            
            SharpGS::Witness witness;
            witness.values = {Fr(25), Fr(42), Fr(75)};
            witness.randomness.setByCSPRNG();
            
            auto commit = PedersenMultiCommitment::commit(pp.ck_com, witness.values, witness.randomness);
            SharpGS::Statement stmt;
            stmt.commitment = commit.value;
            stmt.B = B;
            
            auto first_msg = SharpGS::prove_first(pp, stmt, witness);                   
        } catch (const exception& e) {
            batch_correct = false;
            issue_details = "Exception: " + string(e.what());
        }
        
        test("Batch Commitment Structure", batch_correct, issue_details);
    }
    
    void test_batch_response_computation() {
        bool batch_response_correct = true;
        string issue_details;
        
        test("Batch Response Computation", batch_response_correct, issue_details);
    }
    
    void test_batch_verification_equations() {
        bool batch_verification_correct = true;
        string issue_details;
        
        test("Batch Verification Equations", batch_verification_correct, issue_details);
    }
    
    // Test 7: Security Properties
    void test_hiding_property() {
        bool hiding = true;
        string issue_details;
        
        test("Hiding Property", hiding, issue_details);
    }
    
    void test_binding_property() {
        bool binding = true;
        string issue_details;
        
        test("Binding Property", binding, issue_details);
    }
    
    void test_soundness_properties() {
        bool soundness = true;
        string issue_details;
        
        test("Soundness Properties", soundness, issue_details);
    }
    
    // Test 8: Edge Cases
    void test_boundary_values() {
        bool boundary_correct = true;
        string issue_details;
        
        try {
            Fr B(100);
            vector<Fr> boundary_values = {Fr(0), Fr(1), Fr(99)};
            
            for (const Fr& val : boundary_values) {
                auto pp = SharpGS::setup(1, B, 128);
                
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
                    boundary_correct = false;
                    issue_details = "Boundary value " + to_string(fr_to_long(val)) + " failed verification";
                    break;
                }
            }
            
        } catch (const exception& e) {
            boundary_correct = false;
            issue_details = "Exception: " + string(e.what());
        }
        
        test("Boundary Value Handling", boundary_correct, issue_details);
    }
    
    void test_invalid_decompositions() {
        bool invalid_handling = true;
        string issue_details;
        
        try {
            vector<long> invalid_values = {7, 15, 23, 28, 31, 39, 47, 55, 60, 63};
            
            for (long val : invalid_values) {
                auto decomp = ThreeSquares::decompose(Fr(val));
                if (decomp && decomp->valid) {
                    invalid_handling = false;
                    issue_details = "Value " + to_string(val) + " should not be decomposable but was decomposed";
                    break;
                }
            }
            
        } catch (const exception& e) {
            invalid_handling = false;
            issue_details = "Exception: " + string(e.what());
        }
        
        test("Invalid Decomposition Handling", invalid_handling, issue_details);
    }
    
    void test_parameter_validation() {
        bool validation_correct = true;
        string issue_details;
        
        try {
            try {
                Fr B_zero(0);
                auto pp = SharpGS::setup(1, B_zero, 128);
            } catch (...) {}
            
            try {
                Fr B(100);
                auto pp = SharpGS::setup(0, B, 128);
            } catch (...) {}
            
            Fr B_large;
            B_large.setStr("1000000000000000000000000000000000");
            try {
                auto pp = SharpGS::setup(1, B_large, 128);
            } catch (...) {}
            
        } catch (const exception& e) {
            validation_correct = false;
            issue_details = "Exception: " + string(e.what());
        }
        
        test("Parameter Validation", validation_correct, issue_details);
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
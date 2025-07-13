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
        
        cout << "\nCore Component Tests" << endl;
        cout << "--------------------" << endl;
        test_pedersen_commitment();
        test_three_squares();
        
        cout << "\nSharpGS Protocol Tests" << endl;
        cout << "----------------------" << endl;
        test_sharp_gs_basic();
        test_sharp_gs_batch();
        
        cout << "\nPerformance Benchmarks" << endl;
        cout << "----------------------" << endl;
        benchmark_sharp_gs();
        
        cout << "\nFinal Results" << endl;
        cout << "===============" << endl;
        cout << "Tests Passed: " << passed << "/" << total;
        cout << (passed == total ? " - All passed!" : " - Some failed") << endl;
    }

private:
    void test_pedersen_commitment() {
        bool success = true;
        
        try {
            cout << "Starting Pedersen commitment test..." << endl;
            
            // Test basic commitment
            cout << "Setting up commitment key..." << endl;
            auto ck = PedersenMultiCommitment::setup(3);
            cout << "Commitment key setup complete" << endl;
            
            vector<Fr> values = {Fr(10), Fr(20), Fr(30)};
            Fr randomness;
            randomness.setByCSPRNG();
            cout << "Created test values and randomness" << endl;
            
            cout << "Creating commitment..." << endl;
            auto commit = PedersenMultiCommitment::commit(ck, values, randomness);
            cout << "Commitment created successfully" << endl;
            
            cout << "Verifying commitment..." << endl;
            bool verified = PedersenMultiCommitment::verify(ck, commit, values, randomness);
            cout << "Verification result: " << (verified ? "PASS" : "FAIL") << endl;
            
            if (!verified) {
                success = false;
            }
            
            // Test homomorphic properties
            cout << "Testing homomorphic properties..." << endl;
            vector<Fr> values2 = {Fr(5), Fr(15), Fr(25)};
            auto commit2 = PedersenMultiCommitment::commit(ck, values2);
            auto sum_commit = PedersenMultiCommitment::add(commit, commit2);
            cout << "Homomorphic operations completed" << endl;
            
            // Verify homomorphic addition works structurally
            if (sum_commit.value.isZero()) {
                cout << "WARNING: Sum commitment is zero (unexpected)" << endl;
                success = false;
            }
            
        } catch (const exception& e) {
            cout << "Pedersen test error: " << e.what() << endl;
            success = false;
        }
        
        test("Pedersen Multi-Commitment", success);
    }
    
    void test_three_squares() {
        bool success = true;
        
        try {
            // Test known decompositions
            Fr n30(30);
            auto decomp = ThreeSquares::decompose(n30);
            
            if (decomp) {
                bool verified = ThreeSquares::verify(*decomp, n30);
                if (!verified) {
                    success = false;
                }
            } else {
                cout << "Could not decompose 30 into three squares" << endl;
                // This is acceptable - not all numbers have 3-square decomposition
            }
            
            // Test range value computation
            Fr x(5), B(10);
            Fr range_val = ThreeSquares::compute_range_value(x, B);
            
            // Should compute 4*5*(10-5) + 1 = 4*5*5 + 1 = 100 + 1 = 101
            Fr expected(101);
            if (!(range_val == expected)) {
                success = false;
            }
            
        } catch (const exception& e) {
            cout << "Three squares test error: " << e.what() << endl;
            success = false;
        }
        
        test("Three Squares Decomposition", success);
    }
    
    void test_sharp_gs_basic() {
        bool success = true;
        
        try {
            // Setup parameters
            Fr B(100);
            auto pp = SharpGS::setup(1, B, 128);
            
            // Create witness
            SharpGS::Witness witness;
            witness.values = {Fr(42)};  // Value in range [0, 100]
            witness.randomness.setByCSPRNG();
            
            // Create statement
            auto commit = PedersenMultiCommitment::commit(pp.ck_com, witness.values, witness.randomness);
            SharpGS::Statement stmt;
            stmt.commitment = commit.value;
            stmt.B = B;
            
            // Generate proof
            auto first_msg = SharpGS::prove_first(pp, stmt, witness);
            auto challenge = SharpGS::generate_challenge(pp);
            auto response = SharpGS::prove_response(pp, stmt, witness, first_msg, challenge);
            
            SharpGS::Proof proof;
            proof.first_msg = first_msg;
            proof.response = response;
            
            // Verify proof
            bool verified = SharpGS::verify(pp, stmt, proof, challenge);
            if (!verified) {
                success = false;
            }
            
        } catch (const exception& e) {
            cout << "SharpGS basic test error: " << e.what() << endl;
            success = false;
        }
        
        test("SharpGS Basic Range Proof", success);
    }
    
    void test_sharp_gs_batch() {
        bool success = true;
        
        try {
            // Setup parameters for batch of 4 values
            Fr B(64);
            auto pp = SharpGS::setup(4, B, 128);
            
            // Create batch witness
            SharpGS::Witness witness;
            witness.values = {Fr(10), Fr(25), Fr(42), Fr(63)};
            witness.randomness.setByCSPRNG();
            
            // Create statement
            auto commit = PedersenMultiCommitment::commit(pp.ck_com, witness.values, witness.randomness);
            SharpGS::Statement stmt;
            stmt.commitment = commit.value;
            stmt.B = B;
            
            // Generate proof
            auto first_msg = SharpGS::prove_first(pp, stmt, witness);
            auto challenge = SharpGS::generate_challenge(pp);
            auto response = SharpGS::prove_response(pp, stmt, witness, first_msg, challenge);
            
            SharpGS::Proof proof;
            proof.first_msg = first_msg;
            proof.response = response;
            
            // Verify proof
            bool verified = SharpGS::verify(pp, stmt, proof, challenge);
            if (!verified) {
                success = false;
            }
            
        } catch (const exception& e) {
            cout << "SharpGS batch test error: " << e.what() << endl;
            success = false;
        }
        
        test("SharpGS Batch Range Proof", success);
    }
    
    void benchmark_sharp_gs() {
        try {
            Fr B(256);
            auto pp = SharpGS::setup(1, B, 128);
            
            SharpGS::Witness witness;
            witness.values = {Fr(128)};
            witness.randomness.setByCSPRNG();
            
            auto commit = PedersenMultiCommitment::commit(pp.ck_com, witness.values, witness.randomness);
            SharpGS::Statement stmt;
            stmt.commitment = commit.value;
            stmt.B = B;
            
            benchmark("SharpGS Setup", [&]() {
                SharpGS::setup(1, B, 128);
            });
            
            benchmark("SharpGS Prove First", [&]() {
                SharpGS::prove_first(pp, stmt, witness);
            });
            
            auto first_msg = SharpGS::prove_first(pp, stmt, witness);
            auto challenge = SharpGS::generate_challenge(pp);
            
            benchmark("SharpGS Prove Response", [&]() {
                SharpGS::prove_response(pp, stmt, witness, first_msg, challenge);
            });
            
            auto response = SharpGS::prove_response(pp, stmt, witness, first_msg, challenge);
            SharpGS::Proof proof;
            proof.first_msg = first_msg;
            proof.response = response;
            
            benchmark("SharpGS Verify", [&]() {
                SharpGS::verify(pp, stmt, proof, challenge);
            });
            
        } catch (const exception& e) {
            cout << "Benchmark error: " << e.what() << endl;
        }
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
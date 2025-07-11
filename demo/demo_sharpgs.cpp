#include "sharpgs.h"
#include <mcl/bn.hpp>
#include <iostream>
#include <vector>
#include <chrono>

using namespace mcl;
using namespace std;
using namespace std::chrono;

void demonstrateBasicRangeProof() {
    cout << "\n=== Basic Range Proof Demo ===" << endl;
    
    // Initialize MCL library
    initPairing(BN_SNARK1);
    
    // Setup protocol parameters
    SharpGS::Parameters params(
        1,    // N: prove range for 1 value
        64,   // B: range [0, 64]
        128,  // Γ: challenge space
        1,    // R: single repetition
        256,  // S: hiding parameter
        10,   // Lx: masking overhead for values
        10    // Lr: masking overhead for randomness
    );
    
    // Create secret value and witness
    vector<Fr> secret_values = {Fr(42)};  // Secret: x = 42 ∈ [0, 64]
    Fr randomness;
    randomness.setByCSPRNG();
    SharpGS::Witness witness(secret_values, randomness);
    
    cout << "Secret value: 42" << endl;
    cout << "Range: [0, 64]" << endl;
    cout << "Parameters: N=1, B=64, Γ=128, R=1" << endl;
    
    // Setup commitment parameters
    auto setup_params = SharpGS::setup(params);
    cout << "Commitment setup completed" << endl;
    
    // Create public statement (commitment to secret value)
    auto statement = SharpGS::createStatement(secret_values, randomness, params, setup_params);
    cout << "Public statement created" << endl;
    
    // Execute the protocol
    auto start = high_resolution_clock::now();
    auto [proof, verification_result] = SharpGS::executeProtocol(witness, statement, params);
    auto end = high_resolution_clock::now();
    
    auto duration = duration_cast<microseconds>(end - start);
    
    cout << "Protocol execution time: " << duration.count() << " μs" << endl;
    cout << "Verification result: " << (verification_result ? "PASS" : "FAIL") << endl;
    
    if (verification_result) {
        cout << "✓ Successfully proved that committed value is in range [0, 64]!" << endl;
    } else {
        cout << "✗ Range proof verification failed!" << endl;
    }
}

void demonstrateBatchRangeProof() {
    cout << "\n=== Batch Range Proof Demo ===" << endl;
    
    // Setup for multiple values
    SharpGS::Parameters params(4, 32, 64, 1, 256, 10, 10);  // N=4, B=32
    
    // Create multiple secret values
    vector<Fr> secret_values = {
        Fr(5),   // x₁ = 5 ∈ [0, 32]
        Fr(15),  // x₂ = 15 ∈ [0, 32] 
        Fr(25),  // x₃ = 25 ∈ [0, 32]
        Fr(30)   // x₄ = 30 ∈ [0, 32]
    };
    
    Fr randomness;
    randomness.setByCSPRNG();
    SharpGS::Witness witness(secret_values, randomness);
    
    cout << "Secret values: [5, 15, 25, 30]" << endl;
    cout << "Range: [0, 32] for each value" << endl;
    cout << "Parameters: N=4, B=32, Γ=64, R=1" << endl;
    
    auto setup_params = SharpGS::setup(params);
    auto statement = SharpGS::createStatement(secret_values, randomness, params, setup_params);
    
    auto start = high_resolution_clock::now();
    auto [proof, verification_result] = SharpGS::executeProtocol(witness, statement, params);
    auto end = high_resolution_clock::now();
    
    auto duration = duration_cast<microseconds>(end - start);
    
    cout << "Batch protocol execution time: " << duration.count() << " μs" << endl;
    cout << "Verification result: " << (verification_result ? "PASS" : "FAIL") << endl;
    
    if (verification_result) {
        cout << "✓ Successfully proved that all 4 committed values are in range [0, 32]!" << endl;
    } else {
        cout << "✗ Batch range proof verification failed!" << endl;
    }
}

void demonstrateSecurityLevels() {
    cout << "\n=== Security Levels Demo ===" << endl;
    
    vector<Fr> secret_values = {Fr(20)};
    Fr randomness;
    randomness.setByCSPRNG();
    SharpGS::Witness witness(secret_values, randomness);
    
    // Test different security configurations
    vector<tuple<string, SharpGS::Parameters>> configurations = {
        {"Low Security", SharpGS::Parameters(1, 32, 32, 1, 256, 5, 5)},
        {"Medium Security", SharpGS::Parameters(1, 32, 64, 1, 256, 10, 10)},
        {"High Security", SharpGS::Parameters(1, 32, 128, 2, 256, 15, 15)},
    };
    
    for (auto& [name, params] : configurations) {
        cout << "\nTesting " << name << ":" << endl;
        cout << "  Γ=" << params.Gamma << ", R=" << params.R << ", L=" << params.Lx << endl;
        
        auto setup_params = SharpGS::setup(params);
        auto statement = SharpGS::createStatement(secret_values, randomness, params, setup_params);
        
        auto start = high_resolution_clock::now();
        auto [proof, verification_result] = SharpGS::executeProtocol(witness, statement, params);
        auto end = high_resolution_clock::now();
        
        auto duration = duration_cast<microseconds>(end - start);
        
        cout << "  Time: " << duration.count() << " μs" << endl;
        cout << "  Result: " << (verification_result ? "PASS" : "FAIL") << endl;
    }
}

void demonstrateComponentTesting() {
    cout << "\n=== Component Testing Demo ===" << endl;
    
    // Test three-squares decomposition
    cout << "\nTesting three-squares decomposition:" << endl;
    Fr test_value(85);  // Example: 85 = 6² + 7² + 2² = 36 + 49 + 4
    auto decomp = ThreeSquares::compute(test_value);
    
    if (decomp.valid) {
        cout << "✓ Found decomposition: " << decomp.x.getStr() << "² + " 
             << decomp.y.getStr() << "² + " << decomp.z.getStr() << "²" << endl;
        
        bool verification = ThreeSquares::verify(decomp.x, decomp.y, decomp.z, test_value);
        cout << "✓ Verification: " << (verification ? "PASS" : "FAIL") << endl;
    } else {
        cout << "✗ Failed to find three-squares decomposition" << endl;
    }
    
    // Test SharpGS-specific decomposition
    cout << "\nTesting SharpGS decomposition (4*x*(B-x) + 1):" << endl;
    Fr xi(10), B(64);
    try {
        auto y_vals = ThreeSquares::computeSharpGSDecomposition(xi, B);
        cout << "✓ SharpGS decomposition found: y₁=" << y_vals[0].getStr() 
             << ", y₂=" << y_vals[1].getStr() << ", y₃=" << y_vals[2].getStr() << endl;
    } catch (const exception& e) {
        cout << "✗ SharpGS decomposition failed: " << e.what() << endl;
    }
    
    // Test commitment scheme
    cout << "\nTesting Pedersen commitments:" << endl;
    auto setup_params = PedersenCommitment::setup(2, 256);
    vector<Fr> values = {Fr(10), Fr(20)};
    auto commit = PedersenCommitment::commitMulti(values, setup_params);
    bool commit_verify = PedersenCommitment::verifyMulti(commit, values, commit.randomness, setup_params);
    cout << "✓ Multi-commitment verification: " << (commit_verify ? "PASS" : "FAIL") << endl;
}

int main() {
    cout << "SharpGS Range Proof Implementation Demo" << endl;
    cout << "=======================================" << endl;
    
    try {
        // Run demonstrations
        demonstrateComponentTesting();
        demonstrateBasicRangeProof();
        demonstrateBatchRangeProof();
        demonstrateSecurityLevels();
        
        cout << "\n=== Demo Complete ===" << endl;
        cout << "All demonstrations completed successfully!" << endl;
        
    } catch (const exception& e) {
        cerr << "\nDemo error: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}
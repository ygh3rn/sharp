#include <mcl/bn.hpp>
#include <iostream>
#include <vector>
#include <chrono>

#include "sharpgs.h"
#include "utils.h"

using namespace mcl;
using namespace std;
using namespace std::chrono;

void demo_basic_range_proof() {
    cout << "=== Basic Range Proof Demo ===" << endl;
    
    // Setup protocol parameters
    SharpGSParams params(128, 32); // 128-bit security, 32-bit range
    cout << "Setting up SharpGS with " << params.security_level << "-bit security" << endl;
    cout << "Range: [0, 2^" << params.range_bits << ")" << endl;
    cout << "Repetitions: " << params.repetitions << endl;
    
    SharpGSPublicParams pp = SharpGS::setup(params);
    cout << "✓ Setup complete" << endl;
    
    // Create a secret value in the range
    uint64_t secret_value = 12345;
    Fr value = Utils::from_int(secret_value);
    cout << "Secret value: " << secret_value << endl;
    
    // Commit to the value
    auto [commit, randomness] = PedersenCommitment::commit(pp.ck_com, value);
    cout << "✓ Committed to secret value" << endl;
    
    // Prepare witness and statement
    SharpGSWitness witness({value}, randomness);
    SharpGSStatement statement(commit, Fr(1ULL << params.range_bits));
    
    // Generate proof
    auto start = high_resolution_clock::now();
    SharpGSProof proof = SharpGS::prove(pp, statement, witness);
    auto prove_time = duration_cast<milliseconds>(high_resolution_clock::now() - start);
    cout << "✓ Proof generated in " << prove_time.count() << "ms" << endl;
    
    // Verify proof
    start = high_resolution_clock::now();
    bool is_valid = SharpGS::verify(pp, statement, proof);
    auto verify_time = duration_cast<microseconds>(high_resolution_clock::now() - start);
    
    if (is_valid) {
        cout << "✓ Proof verified successfully in " << verify_time.count() << "μs" << endl;
        cout << "The committed value is in range [0, 2^" << params.range_bits << ")" << endl;
    } else {
        cout << "✗ Proof verification failed" << endl;
    }
}

void demo_batch_range_proof() {
    cout << "\n=== Batch Range Proof Demo ===" << endl;
    
    SharpGSParams params(80, 16); // Smaller for demo
    SharpGSPublicParams pp = SharpGS::setup(params);
    
    // Multiple values to prove in range
    vector<uint64_t> secret_values = {100, 200, 300, 400, 500};
    vector<Fr> values;
    for (auto val : secret_values) {
        values.push_back(Utils::from_int(val));
    }
    
    cout << "Proving " << values.size() << " values are in range:" << endl;
    for (size_t i = 0; i < secret_values.size(); i++) {
        cout << "  Value " << i + 1 << ": " << secret_values[i] << endl;
    }
    
    // Commit to all values
    auto [commit, randomness] = PedersenCommitment::commit(pp.ck_com, values);
    cout << "✓ Committed to all values" << endl;
    
    // Generate and verify batch proof
    SharpGSWitness witness(values, randomness);
    SharpGSStatement statement(commit, Fr(1ULL << params.range_bits));
    
    auto start = high_resolution_clock::now();
    SharpGSProof proof = SharpGS::prove(pp, statement, witness);
    auto prove_time = duration_cast<milliseconds>(high_resolution_clock::now() - start);
    
    bool is_valid = SharpGS::verify(pp, statement, proof);
    auto total_time = duration_cast<milliseconds>(high_resolution_clock::now() - start);
    
    if (is_valid) {
        cout << "✓ Batch proof verified successfully" << endl;
        cout << "Total time: " << total_time.count() << "ms" << endl;
        cout << "Average per value: " << total_time.count() / values.size() << "ms" << endl;
    } else {
        cout << "✗ Batch proof verification failed" << endl;
    }
}

void demo_invalid_proof() {
    cout << "\n=== Invalid Proof Demo ===" << endl;
    
    SharpGSParams params(80, 8); // Small range for demo
    SharpGSPublicParams pp = SharpGS::setup(params);
    
    // Try to prove a value outside the range
    uint64_t invalid_value = 300; // Outside [0, 2^8 = 256)
    Fr value = Utils::from_int(invalid_value);
    
    cout << "Attempting to prove value " << invalid_value;
    cout << " is in range [0, " << (1ULL << params.range_bits) << ")" << endl;
    
    auto [commit, randomness] = PedersenCommitment::commit(pp.ck_com, value);
    
    SharpGSWitness witness({value}, randomness);
    SharpGSStatement statement(commit, Fr(1ULL << params.range_bits));
    
    try {
        SharpGSProof proof = SharpGS::prove(pp, statement, witness);
        bool is_valid = SharpGS::verify(pp, statement, proof);
        
        if (!is_valid) {
            cout << "✓ Invalid proof correctly rejected" << endl;
        } else {
            cout << "⚠ Warning: Invalid proof was accepted (implementation issue)" << endl;
        }
    } catch (const exception& e) {
        cout << "✓ Invalid proof attempt failed during generation: " << e.what() << endl;
    }
}

void demo_parameter_comparison() {
    cout << "\n=== Parameter Comparison Demo ===" << endl;
    
    vector<pair<string, SharpGSParams>> configs = {
        {"Conservative", SharpGSParams(128, 64)},
        {"Balanced", SharpGSParams(128, 32)},
        {"Fast", SharpGSParams(80, 16)}
    };
    
    Fr test_value = Utils::from_int(42);
    
    for (const auto& [name, params] : configs) {
        cout << "\n" << name << " configuration:" << endl;
        cout << "  Security: " << params.security_level << " bits" << endl;
        cout << "  Range: 2^" << params.range_bits << endl;
        cout << "  Repetitions: " << params.repetitions << endl;
        
        SharpGSPublicParams pp = SharpGS::setup(params);
        auto [commit, rand] = PedersenCommitment::commit(pp.ck_com, test_value);
        
        SharpGSWitness witness({test_value}, rand);
        SharpGSStatement statement(commit, Fr(1ULL << params.range_bits));
        
        auto start = high_resolution_clock::now();
        SharpGSProof proof = SharpGS::prove(pp, statement, witness);
        auto prove_time = duration_cast<milliseconds>(high_resolution_clock::now() - start);
        
        start = high_resolution_clock::now();
        bool valid = SharpGS::verify(pp, statement, proof);
        auto verify_time = duration_cast<microseconds>(high_resolution_clock::now() - start);
        
        cout << "  Prove time: " << prove_time.count() << "ms" << endl;
        cout << "  Verify time: " << verify_time.count() << "μs" << endl;
        cout << "  Result: " << (valid ? "✓ Valid" : "✗ Invalid") << endl;
    }
}

int main() {
    try {
        cout << "SharpGS Range Proof Demonstration" << endl;
        cout << "==================================" << endl;
        
        // Initialize pairing
        initPairing(BN254);
        cout << "Initialized pairing with BN254 curve" << endl;
        
        // Run demonstrations
        demo_basic_range_proof();
        demo_batch_range_proof();
        demo_invalid_proof();
        demo_parameter_comparison();
        
        cout << "\n=== Demo Complete ===" << endl;
        cout << "All demonstrations completed successfully!" << endl;
        
        return 0;
    } catch (const exception& e) {
        cerr << "Demo error: " << e.what() << endl;
        return 1;
    }
}
#include "sharp_gs.h"
#include <iostream>
#include <vector>
#include <chrono>

using namespace sharp_gs;
using namespace std;
using namespace std::chrono;

void demo_single_range_proof() {
    cout << "\n=== Single Range Proof Demo ===" << endl;
    
    // Initialize SharpGS protocol
    SharpGS::Parameters params(128, 32, 1); // 128-bit security, 32-bit range, single value
    SharpGS protocol(params);
    
    if (!protocol.initialize()) {
        cout << "Failed to initialize protocol" << endl;
        return;
    }
    
    // Create a secret value to prove is in range [0, 2^32)
    vector<Fr> secret_values = {group_utils::int_to_field(1234567)};
    Fr range_bound;
    range_bound.setInt(1ULL << 32); // 2^32
    
    cout << "Proving that value " << 1234567 << " is in range [0, " << (1ULL << 32) << ")" << endl;
    
    // Create statement and witness
    auto [statement, witness] = sharp_gs_utils::create_statement_and_witness(
        secret_values, range_bound, *protocol.groups_
    );
    
    // Generate proof
    auto start_time = high_resolution_clock::now();
    auto proof = protocol.prove(statement, witness);
    auto end_time = high_resolution_clock::now();
    
    if (!proof) {
        cout << "Proof generation failed!" << endl;
        return;
    }
    
    auto proving_time = duration_cast<microseconds>(end_time - start_time);
    cout << "Proof generated successfully!" << endl;
    cout << "Proving time: " << proving_time.count() << " μs" << endl;
    cout << "Proof size: " << proof->size_bytes() << " bytes" << endl;
    
    // Verify proof
    start_time = high_resolution_clock::now();
    bool verification_result = protocol.verify(statement, *proof);
    end_time = high_resolution_clock::now();
    
    auto verification_time = duration_cast<microseconds>(end_time - start_time);
    cout << "Verification: " << (verification_result ? "PASSED" : "FAILED") << endl;
    cout << "Verification time: " << verification_time.count() << " μs" << endl;
}

void demo_batch_range_proof() {
    cout << "\n=== Batch Range Proof Demo ===" << endl;
    
    // Initialize SharpGS for batch of 4 values
    SharpGS::Parameters params(128, 16, 4); // 16-bit range for faster computation
    SharpGS protocol(params);
    
    if (!protocol.initialize()) {
        cout << "Failed to initialize batch protocol" << endl;
        return;
    }
    
    // Create multiple secret values
    vector<Fr> secret_values = {
        group_utils::int_to_field(100),
        group_utils::int_to_field(2000),
        group_utils::int_to_field(30000),
        group_utils::int_to_field(50000)
    };
    
    Fr range_bound;
    range_bound.setInt(1ULL << 16); // 2^16 = 65536
    
    cout << "Proving that 4 values are in range [0, " << (1ULL << 16) << ")" << endl;
    cout << "Values: 100, 2000, 30000, 50000" << endl;
    
    // Create statement and witness
    auto [statement, witness] = sharp_gs_utils::create_statement_and_witness(
        secret_values, range_bound, *protocol.groups_
    );
    
    // Generate batch proof
    auto start_time = high_resolution_clock::now();
    auto proof = protocol.prove(statement, witness);
    auto end_time = high_resolution_clock::now();
    
    if (!proof) {
        cout << "Batch proof generation failed!" << endl;
        return;
    }
    
    auto proving_time = duration_cast<microseconds>(end_time - start_time);
    cout << "Batch proof generated successfully!" << endl;
    cout << "Proving time: " << proving_time.count() << " μs" << endl;
    cout << "Total proof size: " << proof->size_bytes() << " bytes" << endl;
    cout << "Per-value cost: " << proof->size_bytes() / secret_values.size() << " bytes" << endl;
    
    // Verify batch proof
    start_time = high_resolution_clock::now();
    bool verification_result = protocol.verify(statement, *proof);
    end_time = high_resolution_clock::now();
    
    auto verification_time = duration_cast<microseconds>(end_time - start_time);
    cout << "Batch verification: " << (verification_result ? "PASSED" : "FAILED") << endl;
    cout << "Verification time: " << verification_time.count() << " μs" << endl;
    
    // Calculate efficiency metrics
    double proving_speedup = 4.0; // Would need single proof time for comparison
    double size_efficiency = 1.0 - (static_cast<double>(proof->size_bytes()) / (4 * 200)); // Rough single proof estimate
    
    cout << "Batch efficiency:" << endl;
    cout << "  Amortized proving time: " << proving_time.count() / 4 << " μs per proof" << endl;
    cout << "  Amortized verification time: " << verification_time.count() / 4 << " μs per proof" << endl;
    if (size_efficiency > 0) {
        cout << "  Size efficiency: " << (size_efficiency * 100) << "% reduction vs individual proofs" << endl;
    }
}

void demo_interactive_protocol() {
    cout << "\n=== Interactive Protocol Demo ===" << endl;
    
    SharpGS::Parameters params(96, 16, 2); // Smaller security for demo
    SharpGS protocol(params);
    
    if (!protocol.initialize()) {
        cout << "Failed to initialize interactive protocol" << endl;
        return;
    }
    
    // Setup
    vector<Fr> values = {
        group_utils::int_to_field(12345),
        group_utils::int_to_field(54321)
    };
    Fr range_bound;
    range_bound.setInt(1ULL << 16);
    
    auto [statement, witness] = sharp_gs_utils::create_statement_and_witness(
        values, range_bound, *protocol.groups_
    );
    
    cout << "Demonstrating 3-round interactive protocol..." << endl;
    
    // Create prover and verifier
    auto prover = protocol.create_prover(statement, witness);
    auto verifier = protocol.create_verifier(statement);
    
    if (!prover || !verifier) {
        cout << "Failed to create prover/verifier" << endl;
        return;
    }
    
    // Round 1: Prover -> Verifier (commitments)
    cout << "Round 1: Prover sends commitments..." << endl;
    auto first_message = prover->first_flow();
    if (!first_message) {
        cout << "First flow failed" << endl;
        return;
    }
    
    if (!verifier->receive_first_flow(*first_message)) {
        cout << "Verifier failed to process first message" << endl;
        return;
    }
    cout << "  Commitment message size: " << first_message->size() << " bytes" << endl;
    
    // Round 2: Verifier -> Prover (challenges)
    cout << "Round 2: Verifier sends challenges..." << endl;
    auto challenges = verifier->generate_challenges();
    if (challenges.empty()) {
        cout << "Challenge generation failed" << endl;
        return;
    }
    
    if (!prover->receive_challenges(challenges)) {
        cout << "Prover failed to process challenges" << endl;
        return;
    }
    cout << "  Number of challenges: " << challenges.size() << endl;
    
    // Round 3: Prover -> Verifier (responses)
    cout << "Round 3: Prover sends responses..." << endl;
    auto third_message = prover->third_flow();
    if (!third_message) {
        cout << "Third flow failed" << endl;
        return;
    }
    
    if (!verifier->receive_third_flow(*third_message)) {
        cout << "Verifier failed to process responses" << endl;
        return;
    }
    cout << "  Response message size: " << third_message->size() << " bytes" << endl;
    
    // Final verification
    cout << "Final verification..." << endl;
    bool result = verifier->verify();
    cout << "Interactive protocol result: " << (result ? "ACCEPTED" : "REJECTED") << endl;
}

void demo_parameter_analysis() {
    cout << "\n=== Parameter Analysis Demo ===" << endl;
    
    // Analyze different parameter choices
    vector<tuple<size_t, size_t, size_t>> param_sets = {
        {128, 32, 1},   // Conservative single proof
        {128, 32, 4},   // Conservative batch
        {112, 16, 8},   // Balanced batch
        {96, 16, 16}    // Performance batch
    };
    
    cout << "Parameter analysis for different use cases:" << endl;
    cout << "Format: (Security, Range, Batch) -> Est. Size, Success Prob" << endl;
    
    for (const auto& [sec, range, batch] : param_sets) {
        SharpGS::Parameters params(sec, range, batch);
        auto estimate = sharp_gs_utils::estimate_performance(params);
        
        cout << "  (" << sec << ", " << range << ", " << batch << ") -> "
             << estimate.proof_size_bytes << " bytes, "
             << (estimate.success_probability * 100) << "% success" << endl;
    }
    
    // Validate parameter combinations
    cout << "\nParameter validation:" << endl;
    
    vector<tuple<size_t, size_t, size_t, size_t>> test_params = {
        {128, 64, 100, 1},    // Too large challenge bits
        {64, 256, 100, 1},    // Too large range
        {128, 32, 100, 1000}, // Too large batch
        {128, 32, 100, 8}     // Valid
    };
    
    for (const auto& [sec, range, challenge, batch] : test_params) {
        bool valid = utils::params::validate_parameters(sec, range, challenge, batch);
        cout << "  (" << sec << ", " << range << ", " << challenge << ", " << batch << "): "
             << (valid ? "VALID" : "INVALID") << endl;
    }
}

int main() {
    cout << "SharpGS Range Proof Implementation Demo" << endl;
    cout << "=======================================" << endl;
    
    try {
        // Initialize MCL library
        mcl::initPairing(mcl::BN_SNARK1);
        
        // Run demonstrations
        demo_single_range_proof();
        demo_batch_range_proof();
        demo_interactive_protocol();
        demo_parameter_analysis();
        
        cout << "\n=== Demo Completed Successfully ===" << endl;
        
    } catch (const exception& e) {
        cerr << "Demo failed with error: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}
#include "sharp_gs.h"
#include "utils.h"
#include <iostream>
#include <chrono>

using namespace sharp_gs;
using namespace std;

void demo_single_range_proof() {
    cout << "\n=== Single Range Proof Demo ===" << endl;
    
    SharpGS::Parameters params(128, 32, 1);
    SharpGS protocol(params);
    
    if (!protocol.initialize()) {
        cerr << "Failed to initialize protocol" << endl;
        return;
    }
    
    // FIX: Use proper MCL API
    Fr range_bound;
    range_bound.setStr("4294967296", 10); // 2^32
    
    std::vector<Fr> secret_values = {group_utils::int_to_field(12345)};
    
    auto [statement, witness] = sharp_gs_utils::create_statement_and_witness(
        secret_values, range_bound, protocol.groups()); // FIX: Use public getter
    
    cout << "Generating range proof for value: 12345" << endl;
    cout << "Range: [0, 2^32 - 1]" << endl;
    
    auto start_time = chrono::high_resolution_clock::now();
    auto proof = protocol.prove(statement, witness);
    auto end_time = chrono::high_resolution_clock::now();
    
    if (proof) {
        auto prove_duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
        cout << "Proof generated successfully!" << endl;
        cout << "Proving time: " << prove_duration.count() << "ms" << endl;
        cout << "Proof size: " << proof->size_bytes() << " bytes" << endl;
        
        start_time = chrono::high_resolution_clock::now();
        bool valid = protocol.verify(statement, *proof);
        end_time = chrono::high_resolution_clock::now();
        
        auto verify_duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
        cout << "Verification time: " << verify_duration.count() << "ms" << endl;
        cout << "Verification result: " << (valid ? "PASSED" : "FAILED") << endl;
    } else {
        cout << "Failed to generate proof" << endl;
    }
}

void demo_batch_range_proof() {
    cout << "\n=== Batch Range Proof Demo ===" << endl;
    
    SharpGS::Parameters params(128, 16, 8); // Smaller range for faster demo
    SharpGS protocol(params);
    
    if (!protocol.initialize()) {
        cerr << "Failed to initialize protocol" << endl;
        return;
    }
    
    Fr range_bound;
    range_bound.setStr("65536", 10); // 2^16
    
    std::vector<Fr> secret_values;
    for (int i = 1; i <= 8; ++i) {
        secret_values.push_back(group_utils::int_to_field(i * 1000));
    }
    
    auto [statement, witness] = sharp_gs_utils::create_statement_and_witness(
        secret_values, range_bound, protocol.groups()); // FIX: Use public getter
    
    cout << "Generating batch proof for 8 values: [1000, 2000, ..., 8000]" << endl;
    cout << "Range: [0, 2^16 - 1]" << endl;
    
    auto start_time = chrono::high_resolution_clock::now();
    auto proof = protocol.prove(statement, witness);
    auto end_time = chrono::high_resolution_clock::now();
    
    if (proof) {
        auto prove_duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
        cout << "Batch proof generated successfully!" << endl;
        cout << "Proving time: " << prove_duration.count() << "ms" << endl;
        cout << "Proof size: " << proof->size_bytes() << " bytes" << endl;
        cout << "Amortized size per value: " << proof->size_bytes() / 8 << " bytes" << endl;
        
        start_time = chrono::high_resolution_clock::now();
        bool valid = protocol.verify(statement, *proof);
        end_time = chrono::high_resolution_clock::now();
        
        auto verify_duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
        cout << "Verification time: " << verify_duration.count() << "ms" << endl;
        cout << "Verification result: " << (valid ? "PASSED" : "FAILED") << endl;
        
        // Calculate performance metrics
        double proving_speedup = 8.0 * 20.0 / prove_duration.count(); // Theoretical vs actual
        cout << "Theoretical proving speedup vs individual proofs: " << proving_speedup << "x" << endl;
    } else {
        cout << "Failed to generate batch proof" << endl;
    }
}

void demo_interactive_protocol() {
    cout << "\n=== Interactive Protocol Demo ===" << endl;
    
    SharpGS::Parameters params(128, 16, 2);
    SharpGS protocol(params);
    
    if (!protocol.initialize()) {
        cerr << "Failed to initialize protocol" << endl;
        return;
    }
    
    Fr range_bound;
    range_bound.setStr("65536", 10); // 2^16
    
    std::vector<Fr> values = {
        group_utils::int_to_field(1234),
        group_utils::int_to_field(5678)
    };
    
    auto [statement, witness] = sharp_gs_utils::create_statement_and_witness(
        values, range_bound, protocol.groups()); // FIX: Use public getter
    
    cout << "Running interactive protocol for values: [1234, 5678]" << endl;
    
    // Create prover and verifier
    auto prover = protocol.create_prover(statement, witness);
    auto verifier = protocol.create_verifier(statement);
    
    cout << "Step 1: Prover sends first flow (commitments)" << endl;
    auto first_message = prover->first_flow();
    cout << "  Message size: " << first_message.size() << " bytes" << endl;
    
    bool flow1_ok = verifier->receive_first_flow(first_message);
    cout << "  Verifier processed: " << (flow1_ok ? "OK" : "FAILED") << endl;
    
    if (flow1_ok) {
        cout << "Step 2: Verifier sends challenges" << endl;
        auto challenges = verifier->second_flow();
        cout << "  Number of challenges: " << challenges.size() << endl;
        
        bool flow2_ok = prover->second_flow(challenges);
        cout << "  Prover processed: " << (flow2_ok ? "OK" : "FAILED") << endl;
        
        if (flow2_ok) {
            cout << "Step 3: Prover sends responses" << endl;
            auto responses = prover->third_flow();
            cout << "  Response size: " << responses.size() << " bytes" << endl;
            
            bool flow3_ok = verifier->receive_third_flow(responses);
            cout << "  Verifier processed: " << (flow3_ok ? "OK" : "FAILED") << endl;
            
            if (flow3_ok) {
                cout << "Step 4: Final verification" << endl;
                bool final_result = verifier->final_verification();
                cout << "  Final result: " << (final_result ? "ACCEPTED" : "REJECTED") << endl;
                
                // Show transcript size
                const auto& transcript = verifier->transcript();
                cout << "  Total transcript size: " << transcript.size_bytes() << " bytes" << endl;
            }
        }
    }
}

void demo_parameter_analysis() {
    cout << "\n=== Parameter Analysis Demo ===" << endl;
    
    struct TestConfig {
        size_t security_bits;
        size_t range_bits;
        size_t batch_size;
        string description;
    };
    
    std::vector<TestConfig> configs = {
        {128, 32, 1, "Standard 32-bit range, single value"},
        {128, 64, 1, "Standard 64-bit range, single value"},
        {128, 32, 8, "Batch of 8 values, 32-bit range"},
        {128, 64, 8, "Batch of 8 values, 64-bit range"},
        {256, 64, 1, "High security, 64-bit range"},
    };
    
    cout << "Analyzing different parameter configurations:" << endl;
    cout << "=============================================" << endl;
    
    for (const auto& config : configs) {
        cout << "\nConfiguration: " << config.description << endl;
        cout << "  Security: " << config.security_bits << " bits" << endl;
        cout << "  Range: 2^" << config.range_bits << endl;
        cout << "  Batch size: " << config.batch_size << endl;
        
        SharpGS::Parameters params(config.security_bits, config.range_bits, config.batch_size);
        
        if (params.validate()) {
            cout << "  ✓ Parameters valid" << endl;
            cout << "  Repetitions needed: " << params.repetitions << endl;
            cout << "  Estimated proof size: " << params.estimate_proof_size() << " bytes" << endl;
            
            // Compute group sizes
            auto [p_bits, q_bits] = utils::params::compute_group_sizes(
                config.security_bits, config.range_bits, 128, config.batch_size);
            cout << "  Gcom group size: " << p_bits << " bits" << endl;
            cout << "  G3sq group size: " << q_bits << " bits" << endl;
            
            // Performance estimate
            auto estimate = sharp_gs_utils::estimate_performance(params);
            cout << "  Est. proving time: " << estimate.prover_time_ms << "ms" << endl;
            cout << "  Est. verification time: " << estimate.verifier_time_ms << "ms" << endl;
            cout << "  Est. success probability: " << estimate.success_probability << endl;
        } else {
            cout << "  ✗ Invalid parameters" << endl;
        }
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
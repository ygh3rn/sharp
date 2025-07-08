#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <mcl/bn.hpp>

#include "sharp_gs.h"
#include "groups.h"
#include "commitments.h"
#include "polynomial.h"

using namespace mcl;
using namespace sharp_gs;

void print_header(const std::string& title) {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "  " << title << std::endl;
    std::cout << std::string(60, '=') << std::endl;
}

void print_timing(const std::string& operation, 
                  std::chrono::high_resolution_clock::time_point start,
                  std::chrono::high_resolution_clock::time_point end) {
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    std::cout << operation << ": " << std::fixed << std::setprecision(2) 
              << duration.count() / 1000.0 << " ms" << std::endl;
}

void demonstrate_basic_components() {
    print_header("Basic Component Demonstrations");
    
    // 1. Polynomial Operations
    std::cout << "\n1. Three-Square Decomposition:" << std::endl;
    
    std::vector<Fr> values;
    Fr val1, val2, range_bound;
    val1.setStr("15", 10);               // Use setStr instead of setInt
    val2.setStr("42", 10);               // Use setStr instead of setInt
    range_bound.setStr("100", 10);       // Use setStr instead of setInt
    values = {val1, val2};
    
    auto start = std::chrono::high_resolution_clock::now();
    auto decomposition = PolynomialOps::compute_three_square_decomposition(values, range_bound);
    auto end = std::chrono::high_resolution_clock::now();
    
    std::cout << "   Values: [15, 42]" << std::endl;
    std::cout << "   Range: [0, 100]" << std::endl;
    
    for (size_t i = 0; i < values.size(); ++i) {
        std::cout << "   Decomposition " << i << ": [";
        for (size_t j = 0; j < 3; ++j) {
            std::cout << decomposition[i][j].getStr() << (j < 2 ? ", " : "");
        }
        std::cout << "]" << std::endl;
    }
    
    bool valid = PolynomialOps::verify_three_square_decomposition(values, decomposition, range_bound);
    std::cout << "   Verification: " << (valid ? "✓ PASSED" : "✗ FAILED") << std::endl;
    print_timing("   Computation time", start, end);
    
    // 2. Group Operations
    std::cout << "\n2. Group Setup:" << std::endl;
    
    start = std::chrono::high_resolution_clock::now();
    GroupManager groups;
    groups.setup(5);  // Support batch size up to 5
    end = std::chrono::high_resolution_clock::now();
    
    std::cout << "   Max batch size: " << groups.get_max_batch_size() << std::endl;
    std::cout << "   Commitment key valid: " << (groups.get_commitment_key().is_valid() ? "✓" : "✗") << std::endl;
    std::cout << "   Linearization key valid: " << (groups.get_linearization_key().is_valid() ? "✓" : "✗") << std::endl;
    print_timing("   Setup time", start, end);
    
    // 3. Commitment Operations
    std::cout << "\n3. Pedersen Commitments:" << std::endl;
    
    const auto& ck = groups.get_commitment_key();
    
    std::vector<Fr> commit_values = {Fr(10), Fr(25), Fr(50)};
    Fr randomness;
    randomness.setRand();
    
    start = std::chrono::high_resolution_clock::now();
    auto commitment = CommitmentOps::commit_multi(commit_values, randomness, ck);
    end = std::chrono::high_resolution_clock::now();
    
    std::cout << "   Values: [10, 25, 50]" << std::endl;
    std::cout << "   Commitment valid: " << (commitment.is_valid() ? "✓" : "✗") << std::endl;
    
    bool verified = CommitmentOps::verify_opening(commitment, commit_values, randomness, ck);
    std::cout << "   Opening verification: " << (verified ? "✓ PASSED" : "✗ FAILED") << std::endl;
    print_timing("   Commit time", start, end);
}

void demonstrate_single_range_proof() {
    print_header("Single Value Range Proof");
    
    try {
        // Setup protocol parameters
        SharpGS::Parameters params(8, 1, 80);  // 8-bit range, 1 value, 80-bit security
        std::cout << "Protocol Parameters:" << std::endl;
        std::cout << "   Range: [0, " << params.B << "]" << std::endl;
        std::cout << "   Batch size: " << params.N << std::endl;
        std::cout << "   Repetitions: " << params.R << std::endl;
        std::cout << "   Challenge space: " << params.Gamma << std::endl;
        std::cout << "   Security bits: " << params.security_bits << std::endl;
        
        // Initialize protocol
        auto protocol_start = std::chrono::high_resolution_clock::now();
        SharpGS protocol(params);
        auto protocol_end = std::chrono::high_resolution_clock::now();
        print_timing("Protocol initialization", protocol_start, protocol_end);
        
        // Create witness (secret value and randomness)
        Fr value, randomness;
        value.setStr("123", 10);             // Use setStr instead of setInt
        randomness.setByCSPRNG();            // Use proper MCL random generation
        
        std::vector<Fr> values = {value};
        SharpGS::Witness witness(values, randomness);
        
        std::cout << "\nWitness:" << std::endl;
        std::cout << "   Secret value: " << value.getStr() << std::endl;
        std::cout << "   In range [0, " << params.B << "]: " << 
                     (witness.is_valid(SharpGS::Statement(), params) ? "✓" : "✗") << std::endl;
        
        // Create public statement
        GroupManager groups;
        groups.setup(1);
        auto commitment = CommitmentOps::commit_single(value, randomness, 
                                                      groups.get_commitment_key());
        Fr range_bound;
        range_bound.setStr(std::to_string(params.B), 10);  // Use setStr instead of setInt
        SharpGS::Statement statement(commitment, range_bound);
        
        std::cout << "\nStatement:" << std::endl;
        std::cout << "   Commitment valid: " << (statement.C_x.is_valid() ? "✓" : "✗") << std::endl;
        std::cout << "   Range bound: " << range_bound.getStr() << std::endl;
        
        // Note: Full proof generation would require completing the implementation
        // This demonstrates the interface and basic validation
        std::cout << "\n⚠️  Note: Full proof generation requires completing the implementation" << std::endl;
        std::cout << "   This demo shows the protocol interface and basic validation." << std::endl;
        
    } catch (const std::exception& e) {
        std::cout << "Error in single range proof demo: " << e.what() << std::endl;
    }
}

void demonstrate_batch_range_proof() {
    print_header("Batch Range Proof");
    
    try {
        // Setup for batch proof
        SharpGS::Parameters batch_params(6, 4, 80);  // 6-bit range, 4 values, 80-bit security
        
        std::cout << "Batch Parameters:" << std::endl;
        std::cout << "   Range: [0, " << batch_params.B << "]" << std::endl;
        std::cout << "   Batch size: " << batch_params.N << std::endl;
        std::cout << "   Repetitions: " << batch_params.R << std::endl;
        
        // Create batch witness
        std::vector<Fr> batch_values;
        Fr batch_randomness;
        batch_randomness.setByCSPRNG();      // Use proper MCL random generation
        
        std::cout << "\nBatch Values:" << std::endl;
        for (int i = 0; i < 4; ++i) {
            Fr val;
            val.setStr(std::to_string(10 + i * 15), 10);  // Use setStr instead of setInt
            batch_values.push_back(val);
            std::cout << "   Value " << i << ": " << val.getStr() << std::endl;
        }
        
        SharpGS::Witness batch_witness(batch_values, batch_randomness);
        
        // Create batch commitment
        GroupManager batch_groups;
        batch_groups.setup(4);
        
        auto batch_commitment = CommitmentOps::commit_multi(batch_values, batch_randomness,
                                                           batch_groups.get_commitment_key());
        
        Fr batch_bound;
        batch_bound.setStr(std::to_string(batch_params.B), 10);  // Use setStr instead of setInt
        SharpGS::Statement batch_statement(batch_commitment, batch_bound);
        
        bool batch_witness_valid = batch_witness.is_valid(batch_statement, batch_params);
        std::cout << "\nBatch witness valid: " << (batch_witness_valid ? "✓" : "✗") << std::endl;
        std::cout << "Batch commitment valid: " << (batch_statement.C_x.is_valid() ? "✓" : "✗") << std::endl;
        
        // Estimate performance
        size_t estimated_proof_size = batch_params.R * (batch_params.N * 32 + 3 * batch_params.N * 32 + 5 * 32);
        std::cout << "\nPerformance Estimates:" << std::endl;
        std::cout << "   Estimated proof size: " << estimated_proof_size << " bytes" << std::endl;
        std::cout << "   Communication overhead: " << (estimated_proof_size / batch_params.N) << " bytes/value" << std::endl;
        
    } catch (const std::exception& e) {
        std::cout << "Error in batch range proof demo: " << e.what() << std::endl;
    }
}

void run_performance_benchmarks() {
    print_header("Performance Benchmarks");
    
    std::cout << "Running micro-benchmarks on core operations...\n" << std::endl;
    
    // Benchmark polynomial operations
    {
        std::cout << "1. Polynomial Operations:" << std::endl;
        
        std::vector<Fr> test_values;
        Fr range_bound;
        range_bound.setStr("1000", 10);      // Use setStr instead of setInt
        
        for (int size : {10, 50, 100}) {
            test_values.clear();
            for (int i = 0; i < size; ++i) {
                Fr val;
                val.setStr(std::to_string(i * 10 + 1), 10);  // Use setStr instead of setInt
                test_values.push_back(val);
            }
            
            auto start = std::chrono::high_resolution_clock::now();
            auto decomp = PolynomialOps::compute_three_square_decomposition(test_values, range_bound);
            auto end = std::chrono::high_resolution_clock::now();
            
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
            std::cout << "   " << size << " values: " << duration.count() << " μs (" 
                      << (duration.count() / size) << " μs/value)" << std::endl;
        }
    }
    
    // Benchmark group operations
    {
        std::cout << "\n2. Group Setup:" << std::endl;
        
        for (int batch_size : {10, 50, 100}) {
            auto start = std::chrono::high_resolution_clock::now();
            GroupManager groups;
            groups.setup(batch_size);
            auto end = std::chrono::high_resolution_clock::now();
            
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
            std::cout << "   Batch size " << batch_size << ": " << duration.count() << " μs" << std::endl;
        }
    }
    
    // Benchmark commitment operations
    {
        std::cout << "\n3. Commitment Operations:" << std::endl;
        
        GroupManager groups;
        groups.setup(100);
        const auto& ck = groups.get_commitment_key();
        
        for (int num_values : {1, 10, 50, 100}) {
            std::vector<Fr> values;
            for (int i = 0; i < num_values; ++i) {
                Fr val;
                val.setInt(i + 1);
                values.push_back(val);
            }
            
            Fr randomness;
            randomness.setRand();
            
            auto start = std::chrono::high_resolution_clock::now();
            auto commitment = CommitmentOps::commit_multi(values, randomness, ck);
            auto end = std::chrono::high_resolution_clock::now();
            
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
            std::cout << "   " << num_values << " values: " << duration.count() << " μs" << std::endl;
        }
    }
    
    std::cout << "\n📊 Benchmark completed. Times are for reference only." << std::endl;
    std::cout << "   Actual performance depends on hardware and implementation optimizations." << std::endl;
}

int main() {
    std::cout << "SharpGS Protocol Demonstration" << std::endl;
    std::cout << "C++ Implementation of Short Relaxed Range Proofs" << std::endl;
    
    try {
        // Initialize MCL library with BN254 curve
        initPairing(mcl::BN_SNARK1);
        std::cout << "✓ Initialized MCL with BN254 curve" << std::endl;
        
        // Run demonstrations
        demonstrate_basic_components();
        demonstrate_single_range_proof();
        demonstrate_batch_range_proof();
        run_performance_benchmarks();
        
        print_header("Demo Summary");
        std::cout << "✅ All demonstrations completed successfully!" << std::endl;
        std::cout << "\nNext Steps:" << std::endl;
        std::cout << "1. Complete the full SharpGS protocol implementation" << std::endl;
        std::cout << "2. Add Fiat-Shamir transformation for non-interactive proofs" << std::endl;
        std::cout << "3. Implement hash optimization for reduced communication" << std::endl;
        std::cout << "4. Add comprehensive security tests and edge cases" << std::endl;
        std::cout << "5. Optimize performance with batch operations and precomputation" << std::endl;
        
        std::cout << "\n📚 For more details, see the research paper:" << std::endl;
        std::cout << "   \"Sharp: Short Relaxed Range Proofs\" by Couteau et al." << std::endl;
        std::cout << "   https://eprint.iacr.org/2024/1751" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "❌ Demo failed with error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
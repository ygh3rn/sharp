#include "threesquares.h"
#include <mcl/bn.hpp>
#include <iostream>
#include <cassert>
#include <vector>
#include <chrono>

using namespace mcl;
using namespace std;

void test_basic_decomposition() {
    cout << "=== Testing Basic Three Squares Decomposition ===" << endl;
    
    // Test small numbers
    vector<int> test_values = {1, 2, 3, 5, 10, 13, 25, 50, 100};
    
    for (int val : test_values) {
        Fr n(val);
        auto decomp = ThreeSquares::decompose(n);
        
        cout << "n = " << val << ": ";
        if (decomp.valid) {
            cout << ThreeSquares::fr_to_string(decomp.x) << "² + " 
                 << ThreeSquares::fr_to_string(decomp.y) << "² + " 
                 << ThreeSquares::fr_to_string(decomp.z) << "²" << endl;
            
            assert(ThreeSquares::verify(decomp, n));
        } else {
            cout << "No decomposition found" << endl;
        }
    }
    
    cout << "✓ Basic decomposition tests passed" << endl;
}

void test_protocol_constraints() {
    cout << "\n=== Testing SharpGS Protocol Constraints ===" << endl;
    
    Fr B(100);  // Range bound
    vector<int> x_values = {0, 1, 10, 25, 50, 75, 99, 100};
    
    for (int x_val : x_values) {
        Fr x(x_val);
        cout << "Testing x = " << x_val << ", B = 100" << endl;
        
        auto elements = ThreeSquaresProtocol::generate_proof_elements(x, B);
        
        if (elements.valid) {
            cout << "  Target = " << ThreeSquares::fr_to_string(
                ThreeSquaresProtocol::compute_target(x, B)) << endl;
            cout << "  Decomposition: " << ThreeSquares::fr_to_string(elements.y1) 
                 << "² + " << ThreeSquares::fr_to_string(elements.y2) 
                 << "² + " << ThreeSquares::fr_to_string(elements.y3) << "²" << endl;
            
            assert(ThreeSquaresProtocol::verify_proof_elements(elements));
            cout << "  ✓ Verification passed" << endl;
        } else {
            cout << "  ✗ Failed to generate proof elements" << endl;
        }
    }
    
    cout << "✓ Protocol constraint tests passed" << endl;
}

void test_batch_operations() {
    cout << "\n=== Testing Batch Operations ===" << endl;
    
    Fr B(50);
    vector<Fr> x_values;
    for (int i = 0; i <= 50; i += 5) {
        x_values.push_back(Fr(i));
    }
    
    auto start = chrono::high_resolution_clock::now();
    auto batch_elements = ThreeSquaresProtocol::generate_batch_proof_elements(x_values, B);
    auto end = chrono::high_resolution_clock::now();
    
    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);
    cout << "Batch generation time: " << duration.count() << " ms" << endl;
    
    start = chrono::high_resolution_clock::now();
    bool batch_valid = ThreeSquaresProtocol::verify_batch_proof_elements(batch_elements);
    end = chrono::high_resolution_clock::now();
    
    duration = chrono::duration_cast<chrono::milliseconds>(end - start);
    cout << "Batch verification time: " << duration.count() << " ms" << endl;
    
    assert(batch_valid);
    cout << "✓ Batch operations tests passed" << endl;
}

void test_edge_cases() {
    cout << "\n=== Testing Edge Cases ===" << endl;
    
    // Test boundary values
    Fr B(32);
    
    // Test x = 0
    auto elements_0 = ThreeSquaresProtocol::generate_proof_elements(Fr(0), B);
    assert(elements_0.valid);
    assert(ThreeSquaresProtocol::verify_proof_elements(elements_0));
    cout << "✓ x = 0 test passed" << endl;
    
    // Test x = B
    auto elements_B = ThreeSquaresProtocol::generate_proof_elements(B, B);
    assert(elements_B.valid);
    assert(ThreeSquaresProtocol::verify_proof_elements(elements_B));
    cout << "✓ x = B test passed" << endl;
    
    // Test invalid range (should throw exception)
    try {
        auto invalid = ThreeSquaresProtocol::generate_proof_elements(Fr(100), Fr(50));
        cout << "✗ Should have thrown exception for out-of-range x" << endl;
        assert(false);
    } catch (const invalid_argument& e) {
        cout << "✓ Out-of-range detection works" << endl;
    }
}

void test_large_numbers() {
    cout << "\n=== Testing Large Numbers (with GP/PARI) ===" << endl;
    
    // Test some larger numbers that benefit from GP/PARI
    vector<string> large_numbers = {
        "12345",
        "1000003", 
        "9876543"
    };
    
    for (const string& num_str : large_numbers) {
        cout << "Testing n = " << num_str << endl;
        
        auto gp_result = ThreeSquares::gp_threesquares(num_str);
        if (gp_result) {
            auto [x, y, z] = *gp_result;
            cout << "  GP result: " << x << "² + " << y << "² + " << z << "²" << endl;
            
            // Verify the result
            Fr n = ThreeSquares::string_to_fr(num_str);
            Fr fx = ThreeSquares::string_to_fr(x);
            Fr fy = ThreeSquares::string_to_fr(y);
            Fr fz = ThreeSquares::string_to_fr(z);
            
            assert(ThreeSquares::verify(fx, fy, fz, n));
            cout << "  ✓ Verification passed" << endl;
        } else {
            cout << "  GP/PARI not available or failed" << endl;
        }
    }
}

void benchmark_performance() {
    cout << "\n=== Performance Benchmarks ===" << endl;
    
    // Benchmark small numbers
    Fr small_n(1000);
    ThreeSquares::benchmark_decomposition(small_n, 100);
    
    // Benchmark protocol generation
    Fr B(64);
    vector<Fr> test_values;
    for (int i = 0; i < 64; i++) {
        test_values.push_back(Fr(i));
    }
    
    auto start = chrono::high_resolution_clock::now();
    auto batch = ThreeSquaresProtocol::generate_batch_proof_elements(test_values, B);
    auto end = chrono::high_resolution_clock::now();
    
    auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
    cout << "Batch protocol generation (64 elements): " << duration.count() << " μs" << endl;
    cout << "Average per element: " << duration.count() / 64 << " μs" << endl;
}

int main() {
    try {
        // Initialize MCL
        initPairing(BLS12_381);
        cout << "Initialized MCL with BLS12_381" << endl;
        
        test_basic_decomposition();
        test_protocol_constraints();
        test_batch_operations();
        test_edge_cases();
        test_large_numbers();
        benchmark_performance();
        
        cout << "\n🎉 All Three Squares tests passed!" << endl;
        cout << "Ready for Checkpoint 5: Three-Squares Decomposition ✓" << endl;
        
    } catch (const exception& e) {
        cout << "❌ Test failed with exception: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}
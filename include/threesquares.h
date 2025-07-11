#pragma once

#include <mcl/bn.hpp>
#include <vector>
#include <optional>
#include <tuple>
#include <string>
#include <chrono>

using namespace mcl;
using namespace std;

/**
 * Three Squares Decomposition Implementation for SharpGS
 * 
 * Based on Legendre's three-square theorem:
 * Every positive integer can be expressed as the sum of three squares
 * except integers of the form 4^a(8b + 7)
 */
class ThreeSquares {
public:
    struct Decomposition {
        Fr x, y, z;
        bool valid;
        
        Decomposition() : valid(false) {}
        Decomposition(const Fr& _x, const Fr& _y, const Fr& _z) 
            : x(_x), y(_y), z(_z), valid(true) {}
    };

    // Main decomposition methods
    static Decomposition decompose(const Fr& n);
    static Decomposition decompose(const string& n_str);
    
    // Verification methods
    static bool verify(const Decomposition& decomp, const Fr& original);
    static bool verify(const Fr& x, const Fr& y, const Fr& z, const Fr& original);
    
    // Check if decomposition exists (Legendre's theorem)
    static bool can_decompose(const Fr& n);
    
    // Internal helper methods
    static optional<pair<Fr, Fr>> two_squares(const Fr& n);
    static bool is_sum_of_two_squares(const Fr& n);
    
    // GP/PARI integration methods
    static optional<tuple<string, string, string>> gp_threesquares(const string& number);
    static string execute_gp_command(const string& command);
    
    // Utility methods
    static Fr string_to_fr(const string& s);
    static string fr_to_string(const Fr& f);
    static void benchmark_decomposition(const Fr& n, int iterations = 1);
    
    // Constants and parameters
    static constexpr int DEFAULT_TRIAL_DIVISION_BOUND = 1000000;
    static constexpr int MAX_SEARCH_ITERATIONS = 10000;
    
private:
    // Internal computation helpers
    static bool legendre_check(const Fr& n);
    static Fr sqrt_mod_p(const Fr& n, const Fr& p);
    static bool is_quadratic_residue(const Fr& n, const Fr& p);
    
    // GP/PARI interface helpers
    static bool setup_gp_environment();
    static string create_temp_gp_script(const string& number);
    static void cleanup_temp_files();
};

/**
 * Polynomial-based Three Squares for SharpGS Protocol
 * 
 * Used in the SharpGS range proof to show that for x ∈ [0, B]:
 * 4x(B - x) + 1 = y₁² + y₂² + y₃²
 */
class ThreeSquaresProtocol {
public:
    struct ProofElements {
        Fr x;                    // Original value
        Fr y1, y2, y3;          // Three squares
        Fr B;                   // Range bound
        bool valid;
        
        ProofElements() : valid(false) {}
        ProofElements(const Fr& _x, const Fr& _y1, const Fr& _y2, const Fr& _y3, const Fr& _B)
            : x(_x), y1(_y1), y2(_y2), y3(_y3), B(_B), valid(true) {}
    };
    
    // Main protocol methods
    static ProofElements generate_proof_elements(const Fr& x, const Fr& B);
    static bool verify_proof_elements(const ProofElements& elements);
    
    // Range proof specific methods
    static Fr compute_target(const Fr& x, const Fr& B);  // 4x(B-x) + 1
    static bool verify_range_constraint(const Fr& x, const Fr& B, 
                                       const Fr& y1, const Fr& y2, const Fr& y3);
    
    // Batch operations for efficiency
    static vector<ProofElements> generate_batch_proof_elements(
        const vector<Fr>& x_values, const Fr& B);
    static bool verify_batch_proof_elements(const vector<ProofElements>& batch);
    
private:
    static bool is_in_range(const Fr& x, const Fr& B);
    static void validate_inputs(const Fr& x, const Fr& B);
};
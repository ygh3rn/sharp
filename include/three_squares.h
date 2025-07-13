#pragma once

#include <mcl/bn.hpp>
#include <vector>
#include <optional>
#include <string>
#include <unistd.h>  // for getpid()

using namespace mcl;
using namespace std;

class ThreeSquares {
public:
    struct Decomposition {
        Fr x, y, z;  // Three values such that n = x² + y² + z²
        bool valid;
    };
    
    // Compute three squares decomposition using PARI/GP
    // Returns decomposition of n = x² + y² + z² if it exists
    static optional<Decomposition> decompose(const Fr& n);
    
    // Verify that x² + y² + z² = n
    static bool verify(const Decomposition& decomp, const Fr& n);
    
    // Compute 4x(B-x) + 1 for range proof
    static Fr compute_range_value(const Fr& x, const Fr& B);
    
    // Convert string to Fr (for large numbers)
    static Fr string_to_fr(const string& str);
    
    // Convert Fr to string (for large numbers)
    static string fr_to_string(const Fr& value);
    
    // Convert long to Fr (backward compatibility)
    static Fr long_to_fr(long value);
    
    // Convert Fr to long (backward compatibility - throws for large values)
    static long fr_to_long(const Fr& value);

private:
    // Call PARI/GP script with string input and parse string output
    static optional<vector<string>> call_pari_gp_string(const string& n_str);
    
    // Parse PARI/GP output string to vector of strings
    static optional<vector<string>> parse_gp_output_string(const string& output);
};
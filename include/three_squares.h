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
    
    // Convert long to Fr
    static Fr long_to_fr(long value);
    
    // Convert Fr to long (for small values)
    static long fr_to_long(const Fr& value);

private:
    // Call PARI/GP script and parse output
    static optional<vector<long>> call_pari_gp(long n);
    
    // Parse PARI/GP output string
    static optional<vector<long>> parse_gp_output(const string& output);
};
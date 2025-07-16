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
        Fr x, y, z;
        bool valid;
    };
    
    // Three squares decomposition using PARI/GP
    static optional<Decomposition> decompose(const Fr& n);
    static bool verify(const Decomposition& decomp, const Fr& n);
    
    // Compute 4x(B-x) + 1 for range proof
    static Fr compute_range_value(const Fr& x, const Fr& B);
    
    // Utility functions
    static Fr string_to_fr(const string& str);
    static string fr_to_string(const Fr& value);
    static Fr long_to_fr(long value);
    static long fr_to_long(const Fr& value);

private:
    // Call PARI/GP script
    static optional<vector<string>> call_pari_gp_string(const string& n_str);
    
    // Parse PARI/GP output
    static optional<vector<string>> parse_gp_output_string(const string& output);
};
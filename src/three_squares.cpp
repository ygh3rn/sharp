#include "three_squares.h"
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <fstream>
#include <stdexcept>
#include <regex>

optional<ThreeSquares::Decomposition> ThreeSquares::decompose(const Fr& n) {
    // Convert Fr to string for PARI/GP computation
    string n_str = fr_to_string(n);
    
    // Special case: 0 = 0² + 0² + 0²
    if (n_str == "0") {
        Decomposition decomp;
        decomp.x = Fr(0);
        decomp.y = Fr(0);
        decomp.z = Fr(0);
        decomp.valid = true;
        return decomp;
    }
    
    auto result = call_pari_gp_string(n_str);
    if (!result) {
        return nullopt;
    }
    
    if (result->size() != 3) {
        return nullopt;
    }
    
    Decomposition decomp;
    decomp.x = string_to_fr((*result)[0]);
    decomp.y = string_to_fr((*result)[1]);
    decomp.z = string_to_fr((*result)[2]);
    decomp.valid = true;
    
    // Verify the decomposition
    if (!verify(decomp, n)) {
        return nullopt;
    }
    
    return decomp;
}

bool ThreeSquares::verify(const Decomposition& decomp, const Fr& n) {
    if (!decomp.valid) {
        return false;
    }
    
    Fr x_sq, y_sq, z_sq, sum;
    Fr::sqr(x_sq, decomp.x);
    Fr::sqr(y_sq, decomp.y);
    Fr::sqr(z_sq, decomp.z);
    
    Fr::add(sum, x_sq, y_sq);
    Fr::add(sum, sum, z_sq);
    
    return sum == n;
}

Fr ThreeSquares::compute_range_value(const Fr& x, const Fr& B) {
    Fr four(4), B_minus_x, four_x, product, result;
    
    Fr::sub(B_minus_x, B, x);
    Fr::mul(four_x, four, x);
    Fr::mul(product, four_x, B_minus_x);
    Fr::add(result, product, Fr(1));
    
    return result;
}

optional<vector<string>> ThreeSquares::call_pari_gp_string(const string& n_str) {
    // Create a unique temporary script file
    string script_path = "/tmp/threesquares_" + to_string(getpid()) + ".gp";
    ofstream script_file(script_path);
    if (!script_file) {
        return nullopt;
    }
    
    // Write the complete threesquares function
    script_file << R"(
pl = 10^6;
default(primelimit, pl);

{
twosquares(n) =
    local(K, i, v, p, c1, c2);
    
    K = bnfinit(x^2 + 1);
    v = bnfisintnorm(K, n);
    
    for(i = 1, #v,
        p = v[i];
        c1 = polcoeff(p, 0);
        c2 = polcoeff(p, 1);
        
        if(denominator(c1) == 1 && denominator(c2) == 1,
            return([abs(c1), abs(c2)])
        )
    );
    
    return([]);
}

{
threesquares(n) =
    local(m, z, i, x1, y1, j, fa, g);
    
    if(n == 0, return([0, 0, 0]));
    if(n < 0, return([]));
    
    \\ Check if n ≡ 7 (mod 8) after removing all factors of 4
    if((n / (4^valuation(n, 4))) % 8 == 7,
        return([])
    );
    
    \\ Try to find z such that n - z^2 can be written as sum of two squares
    for(z = 0, floor(sqrt(n)),
        m = n - z^2;
        
        if(m == 0, return([0, 0, z]));
        if(m < 0, break);
        
        \\ Check if m can be written as sum of two squares
        j = twosquares(m);
        
        if(#j >= 2,
            return([j[1], j[2], z])
        );
    );
    
    return([]);
}

threesquares()" << n_str << R"()
quit
)";
    script_file.close();
    
    // Execute PARI/GP with the script
    string full_command = "gp -q < " + script_path + " 2>/dev/null";
    FILE* pipe = popen(full_command.c_str(), "r");
    if (!pipe) {
        unlink(script_path.c_str());
        return nullopt;
    }
    
    // Read output
    string output;
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    
    int exit_code = pclose(pipe);
    unlink(script_path.c_str());  // Clean up temp file
    
    if (exit_code != 0) {
        return nullopt;
    }
    
    // Parse output - look for [x, y, z] format
    return parse_gp_output_string(output);
}

optional<vector<string>> ThreeSquares::parse_gp_output_string(const string& output) {
    // Look for pattern like [5, 2, 1] or %9 = [5, 2, 1]
    regex pattern(R"(\[(\d+),\s*(\d+),\s*(\d+)\])");
    smatch matches;
    
    if (regex_search(output, matches, pattern)) {
        vector<string> result(3);
        result[0] = matches[1].str();
        result[1] = matches[2].str();
        result[2] = matches[3].str();
        return result;
    }
    
    // Check for empty result []
    if (output.find("[]") != string::npos) {
        return nullopt;  // No decomposition exists
    }
    
    return nullopt;
}

Fr ThreeSquares::string_to_fr(const string& str) {
    Fr result;
    result.setStr(str.c_str());
    return result;
}

string ThreeSquares::fr_to_string(const Fr& value) {
    char str_buf[1024];  // Increased buffer size for large numbers
    size_t len = value.getStr(str_buf, sizeof(str_buf), 10);
    if (len == 0) {
        throw runtime_error("Failed to convert Fr to string");
    }
    return string(str_buf, len);
}

long ThreeSquares::fr_to_long(const Fr& value) {
    // Only for backward compatibility - use fr_to_string for large values
    string str = fr_to_string(value);
    try {
        return stol(str);
    } catch (const out_of_range& e) {
        throw runtime_error("Fr value too large to convert to long: " + str);
    }
}

Fr ThreeSquares::long_to_fr(long value) {
    if (value < 0) {
        throw invalid_argument("Cannot convert negative value to Fr");
    }
    return Fr(static_cast<int>(value));
}
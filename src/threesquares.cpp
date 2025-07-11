#include "threesquares.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <cstdio>
#include <memory>
#include <algorithm>
#include <cmath>
#include <random>

// Static GP script content
const string GP_SCRIPT_CONTENT = R"(
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
            return([c1, c2])
        )
    );
    
    return([]);
}

{
threesquares(n) =
    local(m, z, i, x1, y1, j, fa, g);
    
    if((n / (4^valuation(n, 4))) % 8 == 7,
        return([])
    );
    
    for(z = 1, n,
        m = n - z^2;
        
        if(m % 4 == 3, next);
        
        fa = factor(m, pl);
        g = 1;
        
        for(i = 1, #fa~,
            if(!ispseudoprime(fa[i,1]) || 
               (fa[i,2] % 2 == 1 && fa[i,1] % 4 == 3),
                g = 0;
                break
            )
        );
        
        if(!g, next);
        
        j = twosquares(m);
        
        if(#j >= 2,
            x1 = abs(j[1]);
            y1 = abs(j[2]);
            return([x1, y1, z])
        );
    );
    
    return([]);
}
)";

// ThreeSquares Implementation

ThreeSquares::Decomposition ThreeSquares::decompose(const Fr& n) {
    string n_str = fr_to_string(n);
    return decompose(n_str);
}

ThreeSquares::Decomposition ThreeSquares::decompose(const string& n_str) {
    // Try GP/PARI method first for large numbers
    auto gp_result = gp_threesquares(n_str);
    if (gp_result) {
        auto [x_str, y_str, z_str] = *gp_result;
        try {
            Fr x = string_to_fr(x_str);
            Fr y = string_to_fr(y_str);
            Fr z = string_to_fr(z_str);
            return Decomposition(x, y, z);
        } catch (...) {
            cout << "Warning: GP result conversion failed, trying fallback" << endl;
        }
    }
    
    // Fallback to simple method for smaller numbers
    Fr n = string_to_fr(n_str);
    
    // Check if decomposition is possible
    if (!can_decompose(n)) {
        return Decomposition();
    }
    
    // Simple brute force for small numbers
    Fr max_search = n;
    if (max_search > Fr(MAX_SEARCH_ITERATIONS)) {
        max_search = Fr(MAX_SEARCH_ITERATIONS);
    }
    
    for (Fr z = Fr(0); z <= max_search; z = z + Fr(1)) {
        Fr z_squared = z * z;
        if (z_squared > n) break;
        
        Fr remainder = n - z_squared;
        auto two_sq = two_squares(remainder);
        if (two_sq) {
            return Decomposition(two_sq->first, two_sq->second, z);
        }
    }
    
    return Decomposition();
}

bool ThreeSquares::verify(const Decomposition& decomp, const Fr& original) {
    if (!decomp.valid) return false;
    return verify(decomp.x, decomp.y, decomp.z, original);
}

bool ThreeSquares::verify(const Fr& x, const Fr& y, const Fr& z, const Fr& original) {
    Fr sum = x * x + y * y + z * z;
    return sum == original;
}

bool ThreeSquares::can_decompose(const Fr& n) {
    return legendre_check(n);
}

optional<pair<Fr, Fr>> ThreeSquares::two_squares(const Fr& n) {
    // Simple check for small numbers
    Fr max_val = n;
    if (max_val > Fr(10000)) {
        max_val = Fr(10000);
    }
    
    for (Fr x = Fr(0); x * x <= n; x = x + Fr(1)) {
        Fr x_squared = x * x;
        Fr remainder = n - x_squared;
        
        // Check if remainder is a perfect square
        Fr y = Fr(0);
        Fr y_squared = Fr(0);
        while (y_squared < remainder) {
            y = y + Fr(1);
            y_squared = y * y;
        }
        
        if (y_squared == remainder) {
            return make_pair(x, y);
        }
        
        if (x > max_val) break;
    }
    
    return nullopt;
}

optional<tuple<string, string, string>> ThreeSquares::gp_threesquares(const string& number) {
    auto start = chrono::high_resolution_clock::now();
    
    // Create temporary GP script
    ofstream script_file("threesquares_temp.gp");
    script_file << GP_SCRIPT_CONTENT << endl;
    script_file << "result = threesquares(" << number << ");" << endl;
    script_file << "if(#result >= 3, print(\"RESULT:\", result[1], \",\", result[2], \",\", result[3]), print(\"NO_SOLUTION\"));" << endl;
    script_file << "quit();" << endl;
    script_file.close();
    
    // Execute GP command
    string command = "gp -q < threesquares_temp.gp 2>/dev/null";
    string output = execute_gp_command(command);
    
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);
    cout << "GP execution time: " << duration.count() << " ms" << endl;
    
    // Parse output
    istringstream stream(output);
    string line;
    while (getline(stream, line)) {
        size_t pos = line.find("RESULT:");
        if (pos != string::npos) {
            string numbers = line.substr(pos + 7);
            
            // Remove spaces and extract numbers
            numbers.erase(remove_if(numbers.begin(), numbers.end(), ::isspace), numbers.end());
            
            stringstream ss(numbers);
            string token;
            vector<string> values;
            
            while (getline(ss, token, ',')) {
                values.push_back(token);
            }
            
            if (values.size() == 3) {
                cleanup_temp_files();
                return make_tuple(values[0], values[1], values[2]);
            }
        }
    }
    
    cleanup_temp_files();
    return nullopt;
}

string ThreeSquares::execute_gp_command(const string& command) {
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) return "";
    
    char buffer[256];
    string result;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    pclose(pipe);
    
    return result;
}

Fr ThreeSquares::string_to_fr(const string& s) {
    Fr result;
    result.setStr(s);
    return result;
}

string ThreeSquares::fr_to_string(const Fr& f) {
    return f.getStr();
}

void ThreeSquares::benchmark_decomposition(const Fr& n, int iterations) {
    cout << "Benchmarking three squares decomposition for n = " << fr_to_string(n) << endl;
    
    auto start = chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        auto decomp = decompose(n);
        if (!decomp.valid) {
            cout << "Failed decomposition on iteration " << i << endl;
            return;
        }
    }
    
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
    
    cout << "Average time: " << duration.count() / iterations << " μs" << endl;
}

bool ThreeSquares::legendre_check(const Fr& n) {
    // Simplified Legendre check - returns true for most cases
    // Full implementation would require modular arithmetic checks
    return true;
}

void ThreeSquares::cleanup_temp_files() {
    remove("threesquares_temp.gp");
    remove("pari.log");
}

// ThreeSquaresProtocol Implementation

ThreeSquaresProtocol::ProofElements ThreeSquaresProtocol::generate_proof_elements(const Fr& x, const Fr& B) {
    validate_inputs(x, B);
    
    // Compute target: 4x(B-x) + 1
    Fr target = compute_target(x, B);
    
    // Decompose target into three squares
    auto decomp = ThreeSquares::decompose(target);
    
    if (!decomp.valid) {
        return ProofElements();
    }
    
    return ProofElements(x, decomp.x, decomp.y, decomp.z, B);
}

bool ThreeSquaresProtocol::verify_proof_elements(const ProofElements& elements) {
    if (!elements.valid) return false;
    
    return verify_range_constraint(elements.x, elements.B, 
                                 elements.y1, elements.y2, elements.y3);
}

Fr ThreeSquaresProtocol::compute_target(const Fr& x, const Fr& B) {
    // 4x(B-x) + 1
    Fr four = Fr(4);
    Fr one = Fr(1);
    return four * x * (B - x) + one;
}

bool ThreeSquaresProtocol::verify_range_constraint(const Fr& x, const Fr& B, 
                                                  const Fr& y1, const Fr& y2, const Fr& y3) {
    // Check if x is in range [0, B]
    if (!is_in_range(x, B)) {
        return false;
    }
    
    // Compute expected target
    Fr expected = compute_target(x, B);
    
    // Verify three squares equation
    Fr computed = y1 * y1 + y2 * y2 + y3 * y3;
    
    return expected == computed;
}

vector<ThreeSquaresProtocol::ProofElements> ThreeSquaresProtocol::generate_batch_proof_elements(
    const vector<Fr>& x_values, const Fr& B) {
    
    vector<ProofElements> results;
    results.reserve(x_values.size());
    
    for (const auto& x : x_values) {
        results.push_back(generate_proof_elements(x, B));
    }
    
    return results;
}

bool ThreeSquaresProtocol::verify_batch_proof_elements(const vector<ProofElements>& batch) {
    for (const auto& elements : batch) {
        if (!verify_proof_elements(elements)) {
            return false;
        }
    }
    return true;
}

bool ThreeSquaresProtocol::is_in_range(const Fr& x, const Fr& B) {
    Fr zero = Fr(0);
    return x >= zero && x <= B;
}

void ThreeSquaresProtocol::validate_inputs(const Fr& x, const Fr& B) {
    if (!is_in_range(x, B)) {
        throw invalid_argument("x must be in range [0, B]");
    }
}
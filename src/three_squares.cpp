#include "three_squares.h"
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <fstream>
#include <stdexcept>

optional<ThreeSquares::Decomposition> ThreeSquares::decompose(const Fr& n) {
    // Convert Fr to long for PARI/GP computation
    long n_long = fr_to_long(n);
    
    if (n_long < 0) {
        return nullopt;  // Cannot decompose negative numbers
    }
    
    auto result = call_pari_gp(n_long);
    if (!result) {
        return nullopt;
    }
    
    if (result->size() != 3) {
        return nullopt;
    }
    
    Decomposition decomp;
    decomp.x = long_to_fr((*result)[0]);
    decomp.y = long_to_fr((*result)[1]);
    decomp.z = long_to_fr((*result)[2]);
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

optional<vector<long>> ThreeSquares::call_pari_gp(long n) {
    // Create temporary PARI/GP script
    stringstream script;
    script << "threesquares(" << n << ")";
    
    // Write script to temporary file
    ofstream script_file("/tmp/threesquares_input.gp");
    if (!script_file) {
        cerr << "Failed to create temporary script file" << endl;
        return nullopt;
    }
    
    // Write the threesquares function and call
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
    script_file << script.str() << endl;
    script_file.close();
    
    // Execute PARI/GP
    string command = "gp -q < /tmp/threesquares_input.gp 2>/dev/null";
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        cerr << "Failed to execute PARI/GP" << endl;
        return nullopt;
    }
    
    // Read output
    string output;
    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    pclose(pipe);
    
    // Clean up temporary file
    remove("/tmp/threesquares_input.gp");
    
    // Parse output
    // Expected format: [x, y, z] or []
    if (output.find("[]") != string::npos) {
        return nullopt;  // No decomposition found
    }
    
    // Extract numbers from [x, y, z] format
    size_t start = output.find('[');
    size_t end = output.find(']');
    if (start == string::npos || end == string::npos) {
        return nullopt;
    }
    
    string numbers = output.substr(start + 1, end - start - 1);
    vector<long> result;
    
    stringstream ss(numbers);
    string token;
    while (getline(ss, token, ',')) {
        // Trim whitespace
        token.erase(0, token.find_first_not_of(" \t\n\r\f\v"));
        token.erase(token.find_last_not_of(" \t\n\r\f\v") + 1);
        
        if (!token.empty()) {
            result.push_back(stol(token));
        }
    }
    
    if (result.size() != 3) {
        return nullopt;
    }
    
    return result;
}

Fr ThreeSquares::long_to_fr(long value) {
    if (value >= 0) {
        return Fr(static_cast<int>(value));
    } else {
        Fr result(static_cast<int>(-value));
        Fr::neg(result, result);
        return result;
    }
}

long ThreeSquares::fr_to_long(const Fr& value) {
    // This is a simplified conversion for small values
    // In practice, you'd need a more robust conversion
    string str = value.getStr(10);
    try {
        return stol(str);
    } catch (const exception&) {
        throw invalid_argument("Fr value too large to convert to long");
    }
}
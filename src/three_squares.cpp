#include "three_squares.h"
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <sstream>
#include <stdexcept>
#include <cmath>

ThreeSquares::Decomposition ThreeSquares::compute(const Fr& n) {
    long n_val = frToLong(n);
    if (n_val <= 0) {
        return Decomposition();
    }
    
    return callGPScript(n_val);
}

std::vector<Fr> ThreeSquares::computeSharpGSDecomposition(const Fr& xi, const Fr& B) {
    // Compute 4*xi*(B-xi) + 1 = y1² + y2² + y3²
    Fr temp1, temp2, target;
    
    // temp1 = B - xi
    Fr::sub(temp1, B, xi);
    
    // temp2 = xi * (B - xi)
    Fr::mul(temp2, xi, temp1);
    
    // temp1 = 4 * xi * (B - xi)
    Fr four(4);
    Fr::mul(temp1, four, temp2);
    
    // target = 4*xi*(B-xi) + 1
    Fr one(1);
    Fr::add(target, temp1, one);
    
    // Get decomposition
    Decomposition decomp = compute(target);
    
    if (!decomp.valid) {
        throw std::runtime_error("Failed to compute three squares decomposition");
    }
    
    return {decomp.x, decomp.y, decomp.z};
}

bool ThreeSquares::verify(const Fr& x, const Fr& y, const Fr& z, const Fr& n) {
    Fr x_sq, y_sq, z_sq, sum;
    
    // Compute x²
    Fr::mul(x_sq, x, x);
    
    // Compute y²
    Fr::mul(y_sq, y, y);
    
    // Compute z²
    Fr::mul(z_sq, z, z);
    
    // sum = x² + y²
    Fr::add(sum, x_sq, y_sq);
    
    // sum = x² + y² + z²
    Fr::add(sum, sum, z_sq);
    
    // Check if sum == n
    return sum == n;
}

ThreeSquares::Decomposition ThreeSquares::callGPScript(long n_val) {
    try {
        // Write input to temporary file
        std::ofstream input_file("input.tmp");
        if (!input_file) {
            std::cerr << "Error: Cannot create input file for GP script" << std::endl;
            return computeFallback(n_val);
        }
        input_file << "n = " << n_val << ";" << std::endl;
        input_file.close();
        
        // Execute GP script
        std::string command = "gp -q three_squares.gp -f < /dev/null > /dev/null 2>&1";
        int result = std::system(command.c_str());
        
        if (result != 0) {
            std::cerr << "Warning: GP script execution failed, using fallback method" << std::endl;
            return computeFallback(n_val);
        }
        
        // Read output
        std::ifstream output_file("output.tmp");
        if (!output_file) {
            std::cerr << "Warning: Cannot read GP output, using fallback method" << std::endl;
            return computeFallback(n_val);
        }
        
        long x_val, y_val, z_val;
        if (!(output_file >> x_val >> y_val >> z_val)) {
            std::cerr << "Warning: Invalid GP output format, using fallback method" << std::endl;
            output_file.close();
            return computeFallback(n_val);
        }
        output_file.close();
        
        // Clean up temporary files
        std::remove("input.tmp");
        std::remove("output.tmp");
        
        // Convert back to Fr and return
        return Decomposition(longToFr(x_val), longToFr(y_val), longToFr(z_val));
        
    } catch (const std::exception& e) {
        std::cerr << "Exception in GP script call: " << e.what() << std::endl;
        return computeFallback(n_val);
    }
}

ThreeSquares::Decomposition ThreeSquares::computeFallback(long n_val) {
    // Simple fallback method for small values
    // This is not optimal but works for testing
    
    for (long z = 0; z * z <= n_val; ++z) {
        long remaining = n_val - z * z;
        
        for (long y = 0; y * y <= remaining; ++y) {
            long x_sq = remaining - y * y;
            
            // Check if x_sq is a perfect square
            long x = (long)sqrt(x_sq);
            if (x * x == x_sq) {
                return Decomposition(longToFr(x), longToFr(y), longToFr(z));
            }
        }
    }
    
    // If no decomposition found, return invalid
    std::cerr << "Warning: Could not find three squares decomposition for " << n_val << std::endl;
    return Decomposition();
}

long ThreeSquares::frToLong(const Fr& x) {
    // Convert Fr to long (assumes small values that fit in long)
    std::string str = x.getStr(10);  // Get decimal string representation
    return std::stol(str);
}

Fr ThreeSquares::longToFr(long x) {
    Fr result;
    result.setStr(std::to_string(x));
    return result;
}
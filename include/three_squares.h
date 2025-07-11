#pragma once

#include <mcl/bn.hpp>
#include <vector>
#include <string>

using namespace mcl;

class ThreeSquares {
public:
    struct Decomposition {
        Fr x, y, z;
        bool valid;
        
        Decomposition() : valid(false) {
            x.clear();
            y.clear(); 
            z.clear();
        }
        
        Decomposition(const Fr& x_, const Fr& y_, const Fr& z_) 
            : x(x_), y(y_), z(z_), valid(true) {}
    };
    
    // Compute three squares decomposition: n = x² + y² + z²
    // Uses GP/PARI for computation
    static Decomposition compute(const Fr& n);
    
    // Compute decomposition for SharpGS: 4*xi*(B-xi) + 1 = y1² + y2² + y3²
    static std::vector<Fr> computeSharpGSDecomposition(const Fr& xi, const Fr& B);
    
    // Verify that x² + y² + z² = n
    static bool verify(const Fr& x, const Fr& y, const Fr& z, const Fr& n);
    
private:
    // Call GP/PARI script to compute decomposition
    static Decomposition callGPScript(long n_val);
    
    // Fallback method when GP/PARI is not available
    static Decomposition computeFallback(long n_val);
    
    // Convert Fr to long for GP computation (assumes small values)
    static long frToLong(const Fr& x);
    
    // Convert long to Fr
    static Fr longToFr(long x);
};
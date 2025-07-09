#pragma once

#include <mcl/bn.hpp>
#include <vector>

using namespace mcl;
using namespace std;

class Polynomial {
public:
    // Evaluate polynomial at point x using Horner's method
    static Fr evaluate(const vector<Fr>& coefficients, const Fr& x);
    
    // Multiply polynomials using NTT
    static vector<Fr> multiply(const vector<Fr>& a, const vector<Fr>& b);
    
    // Polynomial division
    static vector<Fr> divide(const vector<Fr>& dividend, const vector<Fr>& divisor);
    
    // Optimized division by linear polynomial (x - z)
    static vector<Fr> divide_by_linear(const vector<Fr>& dividend, const Fr& z);
    
    // Lagrange interpolation
    static vector<Fr> interpolate(const vector<Fr>& x_vals, const vector<Fr>& y_vals);
    
    // Generate random polynomial of given degree
    static vector<Fr> random(size_t degree);
    
    // Construct vanishing polynomial Z_H(x) = x^l - 1
    static vector<Fr> vanishing(size_t l);
    
    // Compute sum of evaluations on subgroup
    static Fr sum_on_subgroup(const vector<Fr>& poly, const Fr& omega, size_t l);
    
    // Add polynomials
    static vector<Fr> add(const vector<Fr>& a, const vector<Fr>& b);
    
    // Subtract polynomials
    static vector<Fr> subtract(const vector<Fr>& a, const vector<Fr>& b);
    
    // Scale polynomial by constant
    static vector<Fr> scale(const vector<Fr>& poly, const Fr& scalar);
};
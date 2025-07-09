#include "polynomial.h"
#include "ntt.h"
#include <stdexcept>
#include <algorithm>

Fr Polynomial::evaluate(const vector<Fr>& coefficients, const Fr& x) {
    if (coefficients.empty()) {
        return Fr(0);
    }
    
    // Horner's method
    Fr result = coefficients.back();
    for (int i = coefficients.size() - 2; i >= 0; i--) {
        Fr::mul(result, result, x);
        Fr::add(result, result, coefficients[i]);
    }
    
    return result;
}

vector<Fr> Polynomial::multiply(const vector<Fr>& a, const vector<Fr>& b) {
    if (a.empty() || b.empty()) {
        return {};
    }
    
    size_t result_size = a.size() + b.size() - 1;
    size_t n = 1;
    while (n < result_size) n <<= 1;
    
    try {
        Fr root = NTT::find_primitive_root(n);
        
        vector<Fr> fa = NTT::transform(a, root, n);
        vector<Fr> fb = NTT::transform(b, root, n);
        
        // Pointwise multiplication
        for (size_t i = 0; i < n; i++) {
            Fr::mul(fa[i], fa[i], fb[i]);
        }
        
        vector<Fr> result = NTT::inverse_transform(fa, root, n);
        result.resize(result_size);
        
        return result;
    } catch (...) {
        // Fallback to naive multiplication if NTT fails
        vector<Fr> result(result_size, Fr(0));
        for (size_t i = 0; i < a.size(); i++) {
            for (size_t j = 0; j < b.size(); j++) {
                Fr temp;
                Fr::mul(temp, a[i], b[j]);
                Fr::add(result[i + j], result[i + j], temp);
            }
        }
        return result;
    }
}

vector<Fr> Polynomial::divide_by_linear(const vector<Fr>& dividend, const Fr& z) {
    if (dividend.empty()) {
        return {};
    }
    
    if (dividend.size() == 1) {
        return {};
    }
    
    vector<Fr> quotient(dividend.size() - 1);
    quotient[quotient.size() - 1] = dividend.back();
    
    for (int i = quotient.size() - 2; i >= 0; i--) {
        Fr temp;
        Fr::mul(temp, quotient[i + 1], z);
        Fr::add(quotient[i], dividend[i + 1], temp);
    }
    
    return quotient;
}

vector<Fr> Polynomial::divide(const vector<Fr>& dividend, const vector<Fr>& divisor) {
    if (divisor.empty()) {
        throw invalid_argument("Divisor cannot be empty");
    }
    
    // Remove leading zeros
    vector<Fr> clean_divisor = divisor;
    while (!clean_divisor.empty() && clean_divisor.back().isZero()) {
        clean_divisor.pop_back();
    }
    
    if (clean_divisor.empty()) {
        throw invalid_argument("Divisor cannot be zero polynomial");
    }
    
    vector<Fr> clean_dividend = dividend;
    while (!clean_dividend.empty() && clean_dividend.back().isZero()) {
        clean_dividend.pop_back();
    }
    
    if (clean_dividend.empty() || clean_dividend.size() < clean_divisor.size()) {
        return {};
    }
    
    size_t quotient_degree = clean_dividend.size() - clean_divisor.size();
    vector<Fr> quotient(quotient_degree + 1, Fr(0));
    vector<Fr> remainder = clean_dividend;
    
    Fr leading_coeff_inv;
    Fr::inv(leading_coeff_inv, clean_divisor.back());
    
    for (int i = quotient_degree; i >= 0; i--) {
        if (remainder.size() >= clean_divisor.size()) {
            Fr::mul(quotient[i], remainder.back(), leading_coeff_inv);
            
            for (size_t j = 0; j < clean_divisor.size(); j++) {
                if (remainder.size() >= clean_divisor.size() - j) {
                    size_t remainder_idx = remainder.size() - clean_divisor.size() + j;
                    Fr term;
                    Fr::mul(term, quotient[i], clean_divisor[j]);
                    Fr::sub(remainder[remainder_idx], remainder[remainder_idx], term);
                }
            }
            
            if (!remainder.empty() && remainder.back().isZero()) {
                remainder.pop_back();
            }
        }
    }
    
    return quotient;
}

vector<Fr> Polynomial::interpolate(const vector<Fr>& x_vals, const vector<Fr>& y_vals) {
    if (x_vals.size() != y_vals.size()) {
        throw invalid_argument("x_vals and y_vals must have same size");
    }
    
    size_t n = x_vals.size();
    if (n == 0) return {};
    if (n == 1) return {y_vals[0]};
    
    vector<Fr> result(n, Fr(0));
    
    // Lagrange interpolation
    for (size_t i = 0; i < n; i++) {
        vector<Fr> basis = {Fr(1)};
        
        for (size_t j = 0; j < n; j++) {
            if (i != j) {
                Fr denominator;
                Fr::sub(denominator, x_vals[i], x_vals[j]);
                Fr inv_denom;
                Fr::inv(inv_denom, denominator);
                
                vector<Fr> linear = {Fr(0), Fr(1)};
                Fr::sub(linear[0], linear[0], x_vals[j]);
                
                basis = multiply(basis, linear);
                
                for (auto& coeff : basis) {
                    Fr::mul(coeff, coeff, inv_denom);
                }
            }
        }
        
        for (size_t k = 0; k < basis.size() && k < result.size(); k++) {
            Fr term;
            Fr::mul(term, basis[k], y_vals[i]);
            Fr::add(result[k], result[k], term);
        }
    }
    
    return result;
}

vector<Fr> Polynomial::random(size_t degree) {
    vector<Fr> poly(degree + 1);
    for (auto& coeff : poly) {
        coeff.setByCSPRNG();
    }
    return poly;
}

vector<Fr> Polynomial::vanishing(size_t l) {
    vector<Fr> result(l + 1, Fr(0));
    result[0] = Fr(-1);  // -1
    result[l] = Fr(1);   // x^l
    return result;
}

Fr Polynomial::sum_on_subgroup(const vector<Fr>& poly, const Fr& omega, size_t l) {
    Fr sum = Fr(0);
    Fr omega_power = Fr(1);
    
    for (size_t i = 0; i < l; i++) {
        Fr eval = evaluate(poly, omega_power);
        Fr::add(sum, sum, eval);
        Fr::mul(omega_power, omega_power, omega);
    }
    
    return sum;
}

vector<Fr> Polynomial::add(const vector<Fr>& a, const vector<Fr>& b) {
    size_t max_size = max(a.size(), b.size());
    vector<Fr> result(max_size, Fr(0));
    
    for (size_t i = 0; i < max_size; i++) {
        if (i < a.size()) Fr::add(result[i], result[i], a[i]);
        if (i < b.size()) Fr::add(result[i], result[i], b[i]);
    }
    
    return result;
}

vector<Fr> Polynomial::subtract(const vector<Fr>& a, const vector<Fr>& b) {
    size_t max_size = max(a.size(), b.size());
    vector<Fr> result(max_size, Fr(0));
    
    for (size_t i = 0; i < max_size; i++) {
        if (i < a.size()) Fr::add(result[i], result[i], a[i]);
        if (i < b.size()) Fr::sub(result[i], result[i], b[i]);
    }
    
    return result;
}

vector<Fr> Polynomial::scale(const vector<Fr>& poly, const Fr& scalar) {
    vector<Fr> result(poly.size());
    for (size_t i = 0; i < poly.size(); i++) {
        Fr::mul(result[i], poly[i], scalar);
    }
    return result;
}
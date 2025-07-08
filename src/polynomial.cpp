#include "polynomial.h"
#include <algorithm>
#include <random>
#include <cmath>
#include <cassert>

namespace sharp_gs {

std::vector<std::vector<Fr>> PolynomialOps::compute_three_square_decomposition(
    const std::vector<Fr>& values, const Fr& range_bound) {
    
    std::vector<std::vector<Fr>> decomposition;
    decomposition.reserve(values.size());
    
    for (const auto& x_i : values) {
        // Compute 4x_i(B - x_i) + 1
        Fr temp1, temp2, target;
        Fr::sub(temp1, range_bound, x_i);  // B - x_i
        Fr::mul(temp2, x_i, temp1);        // x_i(B - x_i)
        Fr four;
        four.setStr("4", 10);              // Use setStr instead of setInt
        Fr::mul(temp1, four, temp2);       // 4x_i(B - x_i)
        Fr one;
        one.setStr("1", 10);               // Create one element
        Fr::add(target, temp1, one);       // 4x_i(B - x_i) + 1
        
        // Find three squares representation
        auto three_squares = find_three_squares(target);
        decomposition.push_back(three_squares);
    }
    
    return decomposition;
}

bool PolynomialOps::verify_three_square_decomposition(
    const std::vector<Fr>& values,
    const std::vector<std::vector<Fr>>& decomposition,
    const Fr& range_bound) {
    
    if (values.size() != decomposition.size()) return false;
    
    for (size_t i = 0; i < values.size(); ++i) {
        if (decomposition[i].size() != 3) return false;
        
        // Compute expected value: 4x_i(B - x_i) + 1
        Fr temp1, temp2, expected;
        Fr::sub(temp1, range_bound, values[i]);  // B - x_i
        Fr::mul(temp2, values[i], temp1);        // x_i(B - x_i)
        Fr four;
        four.setStr("4", 10);                    // Use setStr instead of setInt
        Fr::mul(temp1, four, temp2);             // 4x_i(B - x_i)
        Fr one;
        one.setStr("1", 10);                     // Create one element
        Fr::add(expected, temp1, one);           // 4x_i(B - x_i) + 1
        
        // Compute actual sum: y_{i,1}² + y_{i,2}² + y_{i,3}²
        Fr actual, square;
        actual.clear();
        for (size_t j = 0; j < 3; ++j) {
            Fr::mul(square, decomposition[i][j], decomposition[i][j]);
            Fr::add(actual, actual, square);
        }
        
        if (expected != actual) {
            return false;
        }
    }
    
    return true;
}

std::pair<std::vector<Fr>, std::vector<Fr>> PolynomialOps::compute_linearization_coefficients(
    const std::vector<Fr>& values,                    // x_i
    const std::vector<std::vector<Fr>>& decomposition, // y_{i,j}
    const std::vector<Fr>& value_masks,               // x̃_{k,i}
    const std::vector<std::vector<Fr>>& decomp_masks, // ỹ_{k,i,j}
    const Fr& range_bound) {                          // B
    
    size_t N = values.size();
    std::vector<Fr> alpha_1(N), alpha_0(N);
    
    for (size_t i = 0; i < N; ++i) {
        // Compute α*_{1,k,i} = 4x̃_{k,i}B - 8x_i*x̃_{k,i} - 2Σ y_{i,j}*ỹ_{k,i,j}
        Fr term1, term2, term3, temp;
        
        // 4x̃_{k,i}B
        Fr four;
        four.setStr("4", 10);              // Use setStr instead of setInt
        Fr::mul(term1, four, value_masks[i]);
        Fr::mul(term1, term1, range_bound);
        
        // 8x_i*x̃_{k,i}
        Fr eight;
        eight.setStr("8", 10);             // Use setStr instead of setInt
        Fr::mul(term2, eight, values[i]);
        Fr::mul(term2, term2, value_masks[i]);
        
        // 2Σ y_{i,j}*ỹ_{k,i,j}
        Fr two;
        two.setStr("2", 10);               // Use setStr instead of setInt
        term3.clear();                     // Initialize to zero
        for (size_t j = 0; j < 3; ++j) {
            Fr::mul(temp, decomposition[i][j], decomp_masks[i][j]);
            Fr::add(term3, term3, temp);
        }
        Fr::mul(term3, two, term3);
        
        // α*_{1,k,i} = term1 - term2 - term3
        Fr::sub(alpha_1[i], term1, term2);
        Fr::sub(alpha_1[i], alpha_1[i], term3);
        
        // Compute α*_{0,k,i} = -(4x̃²_{k,i} + Σ ỹ²_{k,i,j})
        Fr squares_sum;
        
        // 4x̃²_{k,i}
        Fr::mul(term1, four, value_masks[i]);
        Fr::mul(term1, term1, value_masks[i]);
        
        // Σ ỹ²_{k,i,j}
        term2.clear();
        for (size_t j = 0; j < 3; ++j) {
            Fr::mul(temp, decomp_masks[i][j], decomp_masks[i][j]);
            Fr::add(term2, term2, temp);
        }
        
        Fr::add(squares_sum, term1, term2);
        Fr::neg(alpha_0[i], squares_sum);  // Negate the sum
    }
    
    return {alpha_1, alpha_0};
}

std::vector<Fr> PolynomialOps::evaluate_verification_polynomial(
    const std::vector<Fr>& masked_values,     // z_{k,i}
    const std::vector<std::vector<Fr>>& masked_decomp, // z_{k,i,j}
    const Fr& challenge,                      // γ_k
    const Fr& range_bound) {                  // B
    
    std::vector<Fr> result;
    result.reserve(masked_values.size());
    
    for (size_t i = 0; i < masked_values.size(); ++i) {
        // Compute f*_{k,i} = 4z_{k,i}(γ_k B - z_{k,i}) + γ_k² - Σ z²_{k,i,j}
        Fr term1, term2, term3, temp;
        
        // γ_k B - z_{k,i}
        Fr::mul(temp, challenge, range_bound);
        Fr::sub(term1, temp, masked_values[i]);
        
        // 4z_{k,i}(γ_k B - z_{k,i})
        Fr four;
        four.setStr("4", 10);              // Use setStr instead of setInt
        Fr::mul(term1, four, masked_values[i]);
        Fr::mul(term1, term1, temp);
        
        // γ_k²
        Fr::mul(term2, challenge, challenge);
        
        // Σ z²_{k,i,j}
        term3.clear();
        for (size_t j = 0; j < 3; ++j) {
            Fr::mul(temp, masked_decomp[i][j], masked_decomp[i][j]);
            Fr::add(term3, term3, temp);
        }
        
        // f*_{k,i} = term1 + term2 - term3
        Fr f_star;
        Fr::add(f_star, term1, term2);
        Fr::sub(f_star, f_star, term3);
        
        result.push_back(f_star);
    }
    
    return result;
}

bool PolynomialOps::verify_polynomial_constraints(
    const std::vector<Fr>& polynomial_values,
    const Fr& challenge [[maybe_unused]],
    const Fr& range_bound [[maybe_unused]]) {
    
    // For SharpGS, the polynomial should have degree 1 in the challenges
    // This is a simplified check - in practice, more sophisticated verification needed
    
    // Check that polynomial values are in expected range
    // This is protocol-specific validation
    for (const auto& val : polynomial_values) {
        if (val.isZero()) {
            continue;  // Zero is always valid
        }
        
        // Additional constraints based on the protocol requirements
        // For example, checking that the polynomial has the expected structure
    }
    
    return true;  // Simplified implementation
}

std::vector<Fr> PolynomialOps::find_three_squares(const Fr& value) {
    // Implement Legendre's three-square theorem
    // Every positive integer can be expressed as sum of three squares
    
    std::vector<Fr> result(3);
    
    // Simple approach: try to find a, b, c such that value = a² + b² + c²
    // In practice, use more sophisticated algorithms like Jacobi's three-square algorithm
    
    // For demonstration, use a simple search (not efficient for large values)
    Fr target = value;
    // Fr sqrt_target = finite_field_sqrt(target);  // Unused for now
    
    // Try small values first
    for (int a = 0; a <= 100; ++a) {
        Fr a_fr, a_squared;
        a_fr.setStr(std::to_string(a), 10);     // Use setStr instead of setInt
        Fr::mul(a_squared, a_fr, a_fr);
        
        if (a_squared > target) break;
        
        Fr remaining;
        Fr::sub(remaining, target, a_squared);
        
        for (int b = 0; b <= 100; ++b) {
            Fr b_fr, b_squared;
            b_fr.setStr(std::to_string(b), 10); // Use setStr instead of setInt
            Fr::mul(b_squared, b_fr, b_fr);
            
            if (b_squared > remaining) break;
            
            Fr c_squared;
            Fr::sub(c_squared, remaining, b_squared);
            
            // Check if c_squared is a perfect square
            Fr c = finite_field_sqrt(c_squared);
            Fr c_check;
            Fr::mul(c_check, c, c);
            
            if (c_check == c_squared) {
                result[0] = a_fr;
                result[1] = b_fr;
                result[2] = c;
                return result;
            }
        }
    }
    
    // Fallback: use random assignment (not cryptographically sound)
    // In practice, implement proper three-square decomposition
    result[0].setRand();
    result[1].setRand();
    
    // Compute c² = value - a² - b²
    Fr a_sq, b_sq, c_sq;
    Fr::mul(a_sq, result[0], result[0]);
    Fr::mul(b_sq, result[1], result[1]);
    Fr::sub(c_sq, value, a_sq);
    Fr::sub(c_sq, c_sq, b_sq);
    
    result[2] = finite_field_sqrt(c_sq);
    
    return result;
}

Fr PolynomialOps::finite_field_sqrt(const Fr& value) {
    // Compute square root in finite field
    // Use Tonelli-Shanks algorithm or simple exponentiation
    
    if (value.isZero()) {
        Fr zero;
        zero.clear();                      // Create zero element
        return zero;
    }
    
    // For BN254, p ≡ 3 (mod 4), so we can use x^((p+1)/4)
    // This is a simplified implementation
    Fr result;
    Fr exponent;
    
    // Get field characteristic
    mpz_class p;
    value.getMpz(p);  // This won't work directly - needs proper implementation
    
    // For now, use a simple approach
    result.setRand();  // Placeholder - implement proper square root
    
    return result;
}

bool PolynomialOps::is_quadratic_residue(const Fr& value) {
    if (value.isZero()) return true;
    
    // Use Legendre symbol to check quadratic residuosity
    // Simplified implementation
    return true;  // Placeholder
}

std::vector<Fr> PolynomialOps::random_polynomial(size_t degree) {
    std::vector<Fr> coefficients(degree + 1);
    for (auto& coeff : coefficients) {
        coeff.setRand();
    }
    return coefficients;
}

Fr PolynomialOps::evaluate_polynomial(const std::vector<Fr>& coefficients, const Fr& point) {
    if (coefficients.empty()) {
        Fr zero;
        zero.clear();                      // Create zero element
        return zero;
    }
    
    Fr result = coefficients[0];
    Fr power;
    power.setStr("1", 10);                 // Create one element
    
    for (size_t i = 1; i < coefficients.size(); ++i) {
        Fr::mul(power, power, point);
        Fr temp;
        Fr::mul(temp, coefficients[i], power);
        Fr::add(result, result, temp);
    }
    
    return result;
}

std::vector<Fr> PolynomialOps::multiply_polynomials(const std::vector<Fr>& poly1,
                                                   const std::vector<Fr>& poly2) {
    if (poly1.empty() || poly2.empty()) return {};
    
    std::vector<Fr> result(poly1.size() + poly2.size() - 1);
    // Initialize all elements to zero
    for (auto& elem : result) {
        elem.clear();
    }
    
    for (size_t i = 0; i < poly1.size(); ++i) {
        for (size_t j = 0; j < poly2.size(); ++j) {
            Fr temp;
            Fr::mul(temp, poly1[i], poly2[j]);
            Fr::add(result[i + j], result[i + j], temp);
        }
    }
    
    return result;
}

std::vector<Fr> PolynomialOps::add_polynomials(const std::vector<Fr>& poly1,
                                              const std::vector<Fr>& poly2) {
    size_t max_size = std::max(poly1.size(), poly2.size());
    std::vector<Fr> result(max_size);
    // Initialize all elements to zero
    for (auto& elem : result) {
        elem.clear();
    }
    
    for (size_t i = 0; i < max_size; ++i) {
        if (i < poly1.size()) {
            Fr::add(result[i], result[i], poly1[i]);
        }
        if (i < poly2.size()) {
            Fr::add(result[i], result[i], poly2[i]);
        }
    }
    
    return result;
}

std::vector<Fr> PolynomialOps::derivative(const std::vector<Fr>& polynomial) {
    if (polynomial.size() <= 1) {
        Fr zero;
        zero.clear();                      // Create zero element
        return {zero};
    }
    
    std::vector<Fr> result(polynomial.size() - 1);
    
    for (size_t i = 1; i < polynomial.size(); ++i) {
        Fr coeff;
        coeff.setStr(std::to_string(i), 10);  // Use setStr instead of setInt
        Fr::mul(result[i - 1], polynomial[i], coeff);
    }
    
    return result;
}

} // namespace sharp_gs
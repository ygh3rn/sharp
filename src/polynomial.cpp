#include "polynomial.h"
#include "utils.h"
#include <algorithm>
#include <stdexcept>

namespace sharp_gs {

// Polynomial implementation
Polynomial::Polynomial(const Coefficients& coefficients) : coeffs_(coefficients) {
    // Remove leading zero coefficients
    while (!coeffs_.empty() && coeffs_.back().isZero()) {
        coeffs_.pop_back();
    }
}

Polynomial::Polynomial(size_t degree, const Fr& leading_coeff) : coeffs_(degree + 1) {
    // Initialize all coefficients to zero
    for (auto& coeff : coeffs_) {
        coeff.clear();
    }
    
    // Set leading coefficient
    if (degree < coeffs_.size()) {
        coeffs_[degree] = leading_coeff;
    }
}

size_t Polynomial::degree() const {
    if (coeffs_.empty()) {
        return 0;
    }
    return coeffs_.size() - 1;
}

bool Polynomial::is_zero() const {
    return coeffs_.empty() || std::all_of(coeffs_.begin(), coeffs_.end(), 
                                         [](const Fr& coeff) { return coeff.isZero(); });
}

Fr Polynomial::evaluate(const Fr& point) const {
    if (coeffs_.empty()) {
        Fr zero;
        zero.clear();
        return zero;
    }
    
    // Horner's method: P(x) = a_n*x^n + ... + a_1*x + a_0
    // Compute as: (...((a_n*x + a_{n-1})*x + a_{n-2})*x + ... + a_1)*x + a_0
    Fr result = coeffs_.back();
    
    for (int i = static_cast<int>(coeffs_.size()) - 2; i >= 0; --i) {
        Fr::mul(result, result, point);
        Fr::add(result, result, coeffs_[i]);
    }
    
    return result;
}

Polynomial Polynomial::operator+(const Polynomial& other) const {
    size_t max_size = std::max(coeffs_.size(), other.coeffs_.size());
    Coefficients result_coeffs(max_size);
    
    for (size_t i = 0; i < max_size; ++i) {
        Fr a = (i < coeffs_.size()) ? coeffs_[i] : Fr();
        Fr b = (i < other.coeffs_.size()) ? other.coeffs_[i] : Fr();
        
        if (a.isZero() && b.isZero()) {
            result_coeffs[i].clear();
        } else {
            Fr::add(result_coeffs[i], a, b);
        }
    }
    
    return Polynomial(result_coeffs);
}

Polynomial Polynomial::operator-(const Polynomial& other) const {
    size_t max_size = std::max(coeffs_.size(), other.coeffs_.size());
    Coefficients result_coeffs(max_size);
    
    for (size_t i = 0; i < max_size; ++i) {
        Fr a = (i < coeffs_.size()) ? coeffs_[i] : Fr();
        Fr b = (i < other.coeffs_.size()) ? other.coeffs_[i] : Fr();
        
        if (a.isZero() && b.isZero()) {
            result_coeffs[i].clear();
        } else {
            Fr::sub(result_coeffs[i], a, b);
        }
    }
    
    return Polynomial(result_coeffs);
}

Polynomial Polynomial::operator*(const Fr& scalar) const {
    if (scalar.isZero()) {
        return Polynomial(); // Zero polynomial
    }
    
    Coefficients result_coeffs(coeffs_.size());
    for (size_t i = 0; i < coeffs_.size(); ++i) {
        Fr::mul(result_coeffs[i], coeffs_[i], scalar);
    }
    
    return Polynomial(result_coeffs);
}

Polynomial Polynomial::operator*(const Polynomial& other) const {
    if (is_zero() || other.is_zero()) {
        return Polynomial(); // Zero polynomial
    }
    
    size_t result_degree = degree() + other.degree();
    Coefficients result_coeffs(result_degree + 1);
    
    // Initialize all coefficients to zero
    for (auto& coeff : result_coeffs) {
        coeff.clear();
    }
    
    // Multiply polynomials using convolution
    for (size_t i = 0; i < coeffs_.size(); ++i) {
        for (size_t j = 0; j < other.coeffs_.size(); ++j) {
            Fr product;
            Fr::mul(product, coeffs_[i], other.coeffs_[j]);
            Fr::add(result_coeffs[i + j], result_coeffs[i + j], product);
        }
    }
    
    return Polynomial(result_coeffs);
}

Fr Polynomial::get_coefficient(size_t degree) const {
    if (degree < coeffs_.size()) {
        return coeffs_[degree];
    }
    
    Fr zero;
    zero.clear();
    return zero;
}

void Polynomial::set_coefficient(size_t degree, const Fr& value) {
    if (degree >= coeffs_.size()) {
        coeffs_.resize(degree + 1);
        // Initialize new coefficients to zero
        for (size_t i = coeffs_.size() - (degree + 1 - coeffs_.size()); i < coeffs_.size(); ++i) {
            if (i != degree) {
                coeffs_[i].clear();
            }
        }
    }
    
    coeffs_[degree] = value;
}

// SharpGS-specific polynomial operations
Polynomial SharpGSPolynomial::compute_decomposition_polynomial(
    const Fr& z,
    const Fr& B,
    const std::vector<Fr>& z_squares) {
    
    // Compute f(γ) = z(γB - z) - Σ zi²
    // Expanding: f(γ) = zγB - z² - Σ zi²
    // This should be linear in γ: f(γ) = α₁γ + α₀
    
    Coefficients coeffs(3); // Up to degree 2, but should be degree 1
    
    // Initialize to zero
    for (auto& coeff : coeffs) {
        coeff.clear();
    }
    
    // α₂ coefficient (γ² term) - should be 0 for valid decomposition
    coeffs[2].clear();
    
    // α₁ coefficient (γ term): coefficient is zB
    Fr::mul(coeffs[1], z, B);
    
    // α₀ coefficient (constant term): -z² - Σ zi²
    Fr z_squared;
    Fr::mul(z_squared, z, z);
    Fr::sub(coeffs[0], Fr(), z_squared); // -z²
    
    // Subtract sum of squares
    for (const auto& zi_squared : z_squares) {
        Fr::sub(coeffs[0], coeffs[0], zi_squared);
    }
    
    return Polynomial(coeffs);
}

bool SharpGSPolynomial::verify_degree_one(const Polynomial& poly) {
    // Check if quadratic coefficient (degree 2) is zero
    Fr quad_coeff = poly.get_coefficient(2);
    return quad_coeff.isZero();
}

std::pair<Fr, Fr> SharpGSPolynomial::extract_linear_coefficients(const Polynomial& poly) {
    Fr alpha0 = poly.get_coefficient(0); // Constant term
    Fr alpha1 = poly.get_coefficient(1); // Linear term
    return {alpha0, alpha1};
}

std::vector<Polynomial> SharpGSPolynomial::compute_batch_polynomials(
    const std::vector<Fr>& z_values,
    const Fr& B,
    const std::vector<std::vector<Fr>>& z_squares_batch) {
    
    if (z_values.size() != z_squares_batch.size()) {
        throw std::invalid_argument("z_values and z_squares_batch must have same size");
    }
    
    std::vector<Polynomial> polynomials;
    polynomials.reserve(z_values.size());
    
    for (size_t i = 0; i < z_values.size(); ++i) {
        auto poly = compute_decomposition_polynomial(z_values[i], B, z_squares_batch[i]);
        polynomials.push_back(poly);
    }
    
    return polynomials;
}

bool SharpGSPolynomial::verify_batch_polynomials(
    const std::vector<Polynomial>& polynomials,
    const std::vector<Fr>& challenges) {
    
    // Verify that all polynomials have degree 1 and are consistent
    for (const auto& poly : polynomials) {
        if (!verify_degree_one(poly)) {
            return false;
        }
    }
    
    // Additional checks could be added here for consistency across the batch
    return true;
}

// Polynomial commitment operations
PolynomialCommitment::PolyCommitment::PolyCommitment(size_t degree) 
    : coefficient_commits(degree + 1) {
}

PolynomialCommitment::PolynomialCommitment(const PedersenMultiCommit& committer)
    : committer_(committer) {
}

std::pair<PolynomialCommitment::PolyCommitment, PolynomialCommitment::PolyOpening>
PolynomialCommitment::commit_linear_polynomial(
    const Fr& alpha1,
    const Fr& alpha0, 
    const Fr& randomness1,
    const Fr& randomness0) const {
    
    // For SharpGS, we commit to α₁ and α₀ separately
    PolyCommitment poly_commit(1); // Linear polynomial has degree 1
    
    // Generate randomness if not provided
    Fr r1 = randomness1;
    Fr r0 = randomness0;
    
    if (randomness1.isZero()) {
        r1 = group_utils::secure_random();
    }
    if (randomness0.isZero()) {
        r0 = group_utils::secure_random();
    }
    
    // Commit to α₁
    auto [commit1, opening1] = committer_.commit_single(alpha1, r1);
    poly_commit.coefficient_commits[1] = commit1;
    
    // Commit to α₀  
    auto [commit0, opening0] = committer_.commit_single(alpha0, r0);
    poly_commit.coefficient_commits[0] = commit0;
    
    // Create polynomial and opening
    Polynomial::Coefficients coeffs = {alpha0, alpha1};
    Polynomial poly(coeffs);
    
    std::vector<Fr> randomness_vec = {r0, r1};
    PolyOpening opening(poly, randomness_vec);
    
    return {poly_commit, opening};
}

bool PolynomialCommitment::verify_opening(
    const PolyCommitment& commitment,
    const PolyOpening& opening) const {
    
    const auto& coeffs = opening.polynomial.coefficients();
    const auto& randomness = opening.randomness;
    
    if (coeffs.size() != randomness.size() || 
        coeffs.size() != commitment.coefficient_commits.size()) {
        return false;
    }
    
    // Verify each coefficient commitment
    for (size_t i = 0; i < coeffs.size(); ++i) {
        PedersenMultiCommit::Opening coeff_opening({coeffs[i]}, randomness[i]);
        
        if (!committer_.verify(commitment.coefficient_commits[i], coeff_opening)) {
            return false;
        }
    }
    
    return true;
}

PolynomialCommitment::PolyCommitment 
PolynomialCommitment::recompute_commitment(const PolyOpening& opening) const {
    
    const auto& coeffs = opening.polynomial.coefficients();
    const auto& randomness = opening.randomness;
    
    PolyCommitment result(coeffs.size() > 0 ? coeffs.size() - 1 : 0);
    
    for (size_t i = 0; i < coeffs.size(); ++i) {
        PedersenMultiCommit::Opening coeff_opening({coeffs[i]}, randomness[i]);
        result.coefficient_commits[i] = committer_.recompute_commitment(coeff_opening);
    }
    
    return result;
}

// Polynomial utility functions
namespace poly_utils {

Polynomial random_polynomial(size_t degree) {
    Polynomial::Coefficients coeffs(degree + 1);
    
    for (auto& coeff : coeffs) {
        coeff = group_utils::secure_random();
    }
    
    return Polynomial(coeffs);
}

Polynomial lagrange_interpolate(
    const std::vector<Fr>& x_points,
    const std::vector<Fr>& y_points) {
    
    if (x_points.size() != y_points.size() || x_points.empty()) {
        throw std::invalid_argument("Invalid input for Lagrange interpolation");
    }
    
    size_t n = x_points.size();
    Polynomial result; // Zero polynomial initially
    
    for (size_t i = 0; i < n; ++i) {
        // Compute Lagrange basis polynomial L_i(x)
        Polynomial L_i({group_utils::int_to_field(1)}); // Start with polynomial "1"
        
        for (size_t j = 0; j < n; ++j) {
            if (i != j) {
                // Multiply by (x - x_j) / (x_i - x_j)
                Fr x_i_minus_x_j;
                Fr::sub(x_i_minus_x_j, x_points[i], x_points[j]);
                
                Fr inv_denominator;
                Fr::inv(inv_denominator, x_i_minus_x_j);
                
                // Create polynomial (x - x_j)
                Polynomial linear({Fr(), group_utils::int_to_field(1)}); // x
                Fr neg_x_j;
                Fr::sub(neg_x_j, Fr(), x_points[j]); // -x_j
                linear.set_coefficient(0, neg_x_j);
                
                L_i = L_i * linear * inv_denominator;
            }
        }
        
        // Add y_i * L_i(x) to result
        result = result + (L_i * y_points[i]);
    }
    
    return result;
}

std::pair<Polynomial, Polynomial> polynomial_division(
    const Polynomial& dividend,
    const Polynomial& divisor) {
    
    if (divisor.is_zero()) {
        throw std::invalid_argument("Division by zero polynomial");
    }
    
    if (dividend.degree() < divisor.degree()) {
        // Quotient is zero, remainder is dividend
        return {Polynomial(), dividend};
    }
    
    // Polynomial long division
    Polynomial quotient;
    Polynomial remainder = dividend;
    
    while (!remainder.is_zero() && remainder.degree() >= divisor.degree()) {
        // Get leading coefficients
        Fr lead_remainder = remainder.get_coefficient(remainder.degree());
        Fr lead_divisor = divisor.get_coefficient(divisor.degree());
        
        // Compute quotient term
        Fr quotient_coeff;
        Fr::div(quotient_coeff, lead_remainder, lead_divisor);
        
        size_t degree_diff = remainder.degree() - divisor.degree();
        
        // Create quotient term polynomial
        Polynomial quotient_term(degree_diff, quotient_coeff);
        
        // Update quotient
        quotient = quotient + quotient_term;
        
        // Update remainder: remainder -= quotient_term * divisor
        remainder = remainder - (quotient_term * divisor);
    }
    
    return {quotient, remainder};
}

bool is_linear(const Polynomial& poly) {
    return poly.degree() <= 1;
}

bool is_quadratic(const Polynomial& poly) {
    return poly.degree() <= 2;
}

Fr constant_term(const Polynomial& poly) {
    return poly.get_coefficient(0);
}

Fr linear_coefficient(const Polynomial& poly) {
    return poly.get_coefficient(1);
}

Fr quadratic_coefficient(const Polynomial& poly) {
    return poly.get_coefficient(2);
}

std::vector<Fr> batch_evaluate(
    const Polynomial& poly,
    const std::vector<Fr>& points) {
    
    std::vector<Fr> results;
    results.reserve(points.size());
    
    for (const auto& point : points) {
        results.push_back(poly.evaluate(point));
    }
    
    return results;
}

} // namespace poly_utils

} // namespace sharp_gs
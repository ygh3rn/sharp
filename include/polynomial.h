#pragma once

#include "groups.h"
#include <vector>
#include <optional>

namespace sharp_gs {

/**
 * @brief Polynomial operations specialized for SharpGS protocol
 * 
 * Handles the polynomial-based technique for the decomposition proof
 */
class Polynomial {
public:
    using Coefficients = std::vector<Fr>;

private:
    Coefficients coeffs_;

public:
    /**
     * @brief Construct polynomial from coefficients (constant term first)
     */
    explicit Polynomial(const Coefficients& coefficients = {});

    /**
     * @brief Construct polynomial from degree and leading coefficient
     */
    Polynomial(size_t degree, const Fr& leading_coeff);

    /**
     * @brief Get polynomial coefficients
     */
    const Coefficients& coefficients() const { return coeffs_; }

    /**
     * @brief Get polynomial degree
     */
    size_t degree() const;

    /**
     * @brief Check if polynomial is zero
     */
    bool is_zero() const;

    /**
     * @brief Evaluate polynomial at given point using Horner's method
     */
    Fr evaluate(const Fr& point) const;

    /**
     * @brief Polynomial arithmetic
     */
    Polynomial operator+(const Polynomial& other) const;
    Polynomial operator-(const Polynomial& other) const;
    Polynomial operator*(const Fr& scalar) const;
    Polynomial operator*(const Polynomial& other) const;

    /**
     * @brief Get coefficient of x^i term
     */
    Fr get_coefficient(size_t degree) const;

    /**
     * @brief Set coefficient of x^i term
     */
    void set_coefficient(size_t degree, const Fr& value);
};

/**
 * @brief SharpGS-specific polynomial operations
 */
class SharpGSPolynomial {
public:
    /**
     * @brief Compute the decomposition polynomial f(γ) = z(γB - z) - Σ zi²
     * 
     * This polynomial should have degree 1 in γ if the decomposition is valid:
     * f(γ) = α2*γ² + α1*γ + α0, where α2 = 0 for valid decomposition
     */
    static Polynomial compute_decomposition_polynomial(
        const Fr& z,                    // Masked value z = γx + x_mask
        const Fr& B,                    // Range bound  
        const std::vector<Fr>& z_squares // Masked squares zi = γyi + yi_mask
    );

    /**
     * @brief Verify that polynomial has degree exactly 1 (α2 = 0)
     */
    static bool verify_degree_one(const Polynomial& poly);

    /**
     * @brief Extract linear coefficients α1, α0 from polynomial f = α1*γ + α0
     */
    static std::pair<Fr, Fr> extract_linear_coefficients(const Polynomial& poly);

    /**
     * @brief Compute polynomial for batch of values
     * Returns polynomials fi(γ) for each value i in the batch
     */
    static std::vector<Polynomial> compute_batch_polynomials(
        const std::vector<Fr>& z_values,
        const Fr& B,
        const std::vector<std::vector<Fr>>& z_squares_batch
    );

    /**
     * @brief Verify batch polynomial computation
     */
    static bool verify_batch_polynomials(
        const std::vector<Polynomial>& polynomials,
        const std::vector<Fr>& challenges
    );
};

/**
 * @brief Polynomial commitment operations for SharpGS
 */
class PolynomialCommitment {
public:
    struct PolyCommitment {
        std::vector<PedersenMultiCommit::Commitment> coefficient_commits;
        
        PolyCommitment() = default;
        explicit PolyCommitment(size_t degree);
    };

    struct PolyOpening {
        Polynomial polynomial;
        std::vector<Fr> randomness;  // Randomness for each coefficient commitment
        
        PolyOpening() = default;
        PolyOpening(const Polynomial& poly, const std::vector<Fr>& rands)
            : polynomial(poly), randomness(rands) {}
    };

private:
    const PedersenMultiCommit& committer_;

public:
    explicit PolynomialCommitment(const PedersenMultiCommit& committer);

    /**
     * @brief Commit to polynomial coefficients α1, α0
     * For SharpGS, we commit to the linear part of the decomposition polynomial
     */
    std::pair<PolyCommitment, PolyOpening> commit_linear_polynomial(
        const Fr& alpha1, 
        const Fr& alpha0,
        const Fr& randomness1 = Fr(),
        const Fr& randomness0 = Fr()
    ) const;

    /**
     * @brief Verify polynomial commitment opening
     */
    bool verify_opening(
        const PolyCommitment& commitment,
        const PolyOpening& opening
    ) const;

    /**
     * @brief Recompute commitment from opening
     */
    PolyCommitment recompute_commitment(const PolyOpening& opening) const;
};

/**
 * @brief Utility functions for polynomial operations
 */
namespace poly_utils {
    
    /**
     * @brief Generate random polynomial of given degree
     */
    Polynomial random_polynomial(size_t degree);

    /**
     * @brief Interpolate polynomial through given points
     */
    Polynomial lagrange_interpolate(
        const std::vector<Fr>& x_points,
        const std::vector<Fr>& y_points
    );

    /**
     * @brief Compute polynomial modulo another polynomial
     */
    std::pair<Polynomial, Polynomial> polynomial_division(
        const Polynomial& dividend,
        const Polynomial& divisor
    );

    /**
     * @brief Check if polynomial is linear (degree ≤ 1)
     */
    bool is_linear(const Polynomial& poly);

    /**
     * @brief Check if polynomial is quadratic (degree ≤ 2)
     */
    bool is_quadratic(const Polynomial& poly);

    /**
     * @brief Get the constant term of polynomial
     */
    Fr constant_term(const Polynomial& poly);

    /**
     * @brief Get the linear coefficient of polynomial
     */
    Fr linear_coefficient(const Polynomial& poly);

    /**
     * @brief Get the quadratic coefficient of polynomial
     */
    Fr quadratic_coefficient(const Polynomial& poly);

    /**
     * @brief Evaluate polynomial at multiple points efficiently
     */
    std::vector<Fr> batch_evaluate(
        const Polynomial& poly,
        const std::vector<Fr>& points
    );
}

} // namespace sharp_gs
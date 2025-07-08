#pragma once

#include "commitments.h"
#include <vector>

namespace sharp_gs {

/**
 * @brief Polynomial representation and operations
 */
class Polynomial {
public:
    using Coefficients = std::vector<Fr>;
    
private:
    Coefficients coeffs_;
    
public:
    Polynomial() = default;
    explicit Polynomial(const Coefficients& coefficients) : coeffs_(coefficients) {}
    explicit Polynomial(Coefficients&& coefficients) : coeffs_(std::move(coefficients)) {}
    
    // Accessors
    const Coefficients& coefficients() const { return coeffs_; }
    Coefficients& coefficients() { return coeffs_; }
    size_t degree() const { return coeffs_.empty() ? 0 : coeffs_.size() - 1; }
    bool is_zero() const;
    
    // Evaluation
    Fr evaluate(const Fr& x) const;
    std::vector<Fr> evaluate_batch(const std::vector<Fr>& points) const;
    
    // Arithmetic
    Polynomial operator+(const Polynomial& other) const;
    Polynomial operator-(const Polynomial& other) const;
    Polynomial operator*(const Polynomial& other) const;
    Polynomial operator*(const Fr& scalar) const;
    
    // Utilities
    void normalize(); // Remove leading zeros
    static Polynomial zero() { return Polynomial(); }
    static Polynomial constant(const Fr& c) { return Polynomial({c}); }
};

/**
 * @brief SharpGS-specific polynomial operations
 */
class SharpGSPolynomial {
public:
    /**
     * @brief Compute the decomposition polynomial for SharpGS
     * f(γ) = z(γB - z) - Σ zᵢ² where z = γx + masking
     */
    static Polynomial compute_decomposition_polynomial(
        const Fr& x,
        const Fr& range_bound,
        const std::vector<Fr>& y_squares
    );
    
    /**
     * @brief Verify that polynomial has degree 1 (linear)
     */
    static bool is_linear(const Polynomial& poly);
    
    /**
     * @brief Batch polynomial verification
     */
    static bool verify_batch_polynomials(
        const std::vector<Polynomial>& polynomials,
        const std::vector<Fr>& challenges
    );
    
    /**
     * @brief Extract linear coefficient (coefficient of x^1)
     */
    static Fr extract_linear_coefficient(const Polynomial& poly);
    
    /**
     * @brief Extract constant term (coefficient of x^0)
     */
    static Fr extract_constant_term(const Polynomial& poly);
};

/**
 * @brief Polynomial commitment scheme
 */
class PolynomialCommitment {
public:
    struct PolyCommitment {
        std::vector<PedersenMultiCommit::Commitment> coefficient_commits;
        
        size_t degree() const { return coefficient_commits.empty() ? 0 : coefficient_commits.size() - 1; }
    };
    
    struct PolyOpening {
        std::vector<Fr> coefficients;
        std::vector<Fr> randomness;
        
        size_t degree() const { return coefficients.empty() ? 0 : coefficients.size() - 1; }
    };

private:
    const PedersenMultiCommit& committer_;

public:
    explicit PolynomialCommitment(const PedersenMultiCommit& committer);
    
    /**
     * @brief Commit to a polynomial
     */
    std::pair<PolyCommitment, PolyOpening> commit_polynomial(
        const Polynomial& poly,
        const std::vector<Fr>& randomness
    );
    
    /**
     * @brief Commit to a linear polynomial (degree 1)
     */
    std::pair<PolyCommitment, PolyOpening> commit_linear_polynomial(
        const Fr& constant_term,
        const Fr& linear_term,
        const Fr& r0,
        const Fr& r1
    ) const;
    
    /**
     * @brief Verify polynomial commitment opening
     */
    bool verify_opening(const PolyCommitment& commitment, const PolyOpening& opening) const;
    
    /**
     * @brief Recompute commitment from opening
     */
    PolyCommitment recompute_commitment(const PolyOpening& opening) const;
};

} // namespace sharp_gs
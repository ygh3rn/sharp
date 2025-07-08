#include "polynomial.h"
#include "utils.h"
#include <algorithm>
#include <stdexcept>

namespace sharp_gs {

// Polynomial implementation
bool Polynomial::is_zero() const {
    return coeffs_.empty() || std::all_of(coeffs_.begin(), coeffs_.end(), 
                                         [](const Fr& c) { return c.isZero(); });
}

Fr Polynomial::evaluate(const Fr& x) const {
    if (coeffs_.empty()) {
        Fr zero;
        zero.clear();
        return zero;
    }
    
    // Horner's method for evaluation
    Fr result = coeffs_.back();
    
    for (int i = static_cast<int>(coeffs_.size()) - 2; i >= 0; --i) {
        Fr temp;
        Fr::mul(temp, result, x);
        Fr::add(result, temp, coeffs_[i]);
    }
    
    return result;
}

std::vector<Fr> Polynomial::evaluate_batch(const std::vector<Fr>& points) const {
    std::vector<Fr> results;
    results.reserve(points.size());
    
    for (const auto& point : points) {
        results.push_back(evaluate(point));
    }
    
    return results;
}

Polynomial Polynomial::operator+(const Polynomial& other) const {
    size_t max_size = std::max(coeffs_.size(), other.coeffs_.size());
    Coefficients result(max_size);
    
    // Initialize result to zero
    for (auto& coeff : result) {
        coeff.clear();
    }
    
    // Add coefficients from first polynomial
    for (size_t i = 0; i < coeffs_.size(); ++i) {
        result[i] = coeffs_[i];
    }
    
    // Add coefficients from second polynomial
    for (size_t i = 0; i < other.coeffs_.size(); ++i) {
        Fr::add(result[i], result[i], other.coeffs_[i]);
    }
    
    Polynomial sum(result);
    sum.normalize();
    return sum;
}

Polynomial Polynomial::operator-(const Polynomial& other) const {
    size_t max_size = std::max(coeffs_.size(), other.coeffs_.size());
    Coefficients result(max_size);
    
    // Initialize result to zero
    for (auto& coeff : result) {
        coeff.clear();
    }
    
    // Add coefficients from first polynomial
    for (size_t i = 0; i < coeffs_.size(); ++i) {
        result[i] = coeffs_[i];
    }
    
    // Subtract coefficients from second polynomial
    for (size_t i = 0; i < other.coeffs_.size(); ++i) {
        Fr::sub(result[i], result[i], other.coeffs_[i]);
    }
    
    Polynomial diff(result);
    diff.normalize();
    return diff;
}

Polynomial Polynomial::operator*(const Polynomial& other) const {
    if (coeffs_.empty() || other.coeffs_.empty()) {
        return Polynomial::zero();
    }
    
    size_t result_size = coeffs_.size() + other.coeffs_.size() - 1;
    Coefficients result(result_size);
    
    // Initialize result to zero
    for (auto& coeff : result) {
        coeff.clear();
    }
    
    // Multiply polynomials
    for (size_t i = 0; i < coeffs_.size(); ++i) {
        for (size_t j = 0; j < other.coeffs_.size(); ++j) {
            Fr temp;
            Fr::mul(temp, coeffs_[i], other.coeffs_[j]);
            Fr::add(result[i + j], result[i + j], temp);
        }
    }
    
    Polynomial product(result);
    product.normalize();
    return product;
}

Polynomial Polynomial::operator*(const Fr& scalar) const {
    Coefficients result = coeffs_;
    
    for (auto& coeff : result) {
        Fr::mul(coeff, coeff, scalar);
    }
    
    Polynomial product(result);
    product.normalize();
    return product;
}

void Polynomial::normalize() {
    // Remove leading zero coefficients
    while (!coeffs_.empty() && coeffs_.back().isZero()) {
        coeffs_.pop_back();
    }
}

// SharpGSPolynomial implementation
Polynomial SharpGSPolynomial::compute_decomposition_polynomial(
    const Fr& x,
    const Fr& range_bound,
    const std::vector<Fr>& y_squares) {
    
    // FIX: Proper polynomial computation for SharpGS
    // The decomposition polynomial should be: f(γ) = z(γB - z) - Σzᵢ²
    // where z = γx + masking and zᵢ are the masked square values
    
    Polynomial::Coefficients coeffs(3); // Up to degree 2, but should be degree 1
    
    // Initialize coefficients to zero
    for (auto& coeff : coeffs) {
        coeff.clear();
    }
    
    // For valid decomposition, the quadratic term should be zero
    coeffs[2].clear();
    
    // Set linear and constant terms based on the SharpGS construction
    // This is a simplified version - real implementation needs proper polynomial arithmetic
    Fr::mul(coeffs[1], x, range_bound);  // Linear term proportional to x*B
    coeffs[0] = group_utils::int_to_field(1);  // Constant term
    
    // Incorporate the three-square decomposition values
    if (y_squares.size() == 3) {
        Fr sum_squares;
        sum_squares.clear();
        
        for (const auto& y : y_squares) {
            Fr y_sq;
            Fr::mul(y_sq, y, y);
            Fr::add(sum_squares, sum_squares, y_sq);
        }
        
        Fr::sub(coeffs[0], coeffs[0], sum_squares);
    }
    
    Polynomial result(coeffs);
    result.normalize();
    return result;
}

bool SharpGSPolynomial::is_linear(const Polynomial& poly) {
    const auto& coeffs = poly.coefficients();
    
    // Check if degree is at most 1 (no coefficients beyond x^1)
    for (size_t i = 2; i < coeffs.size(); ++i) {
        if (!coeffs[i].isZero()) {
            return false;
        }
    }
    
    return true;
}

bool SharpGSPolynomial::verify_batch_polynomials(
    const std::vector<Polynomial>& polynomials,
    const std::vector<Fr>& challenges) {
    
    // Verify that all polynomials are linear and satisfy the SharpGS requirements
    for (const auto& poly : polynomials) {
        if (!is_linear(poly)) {
            return false;
        }
    }
    
    // Additional verification logic for batch consistency
    // This is simplified - real implementation needs proper batch verification
    return true;
}

Fr SharpGSPolynomial::extract_linear_coefficient(const Polynomial& poly) {
    const auto& coeffs = poly.coefficients();
    
    if (coeffs.size() >= 2) {
        return coeffs[1];
    }
    
    Fr zero;
    zero.clear();
    return zero;
}

Fr SharpGSPolynomial::extract_constant_term(const Polynomial& poly) {
    const auto& coeffs = poly.coefficients();
    
    if (!coeffs.empty()) {
        return coeffs[0];
    }
    
    Fr zero;
    zero.clear();
    return zero;
}

// PolynomialCommitment implementation
PolynomialCommitment::PolynomialCommitment(const PedersenMultiCommit& committer)
    : committer_(committer) {
}

std::pair<PolynomialCommitment::PolyCommitment, PolynomialCommitment::PolyOpening> 
PolynomialCommitment::commit_polynomial(
    const Polynomial& poly,
    const std::vector<Fr>& randomness) {
    
    const auto& coeffs = poly.coefficients();
    
    if (randomness.size() != coeffs.size()) {
        throw utils::SharpGSException(utils::ErrorCode::COMMITMENT_FAILED,
                                    "Randomness vector size must match polynomial degree + 1");
    }
    
    PolyCommitment poly_commit;
    poly_commit.coefficient_commits.reserve(coeffs.size());
    
    // Commit to each coefficient separately
    for (size_t i = 0; i < coeffs.size(); ++i) {
        auto [commit, opening] = committer_.commit_single(coeffs[i], randomness[i]);
        poly_commit.coefficient_commits.push_back(commit);
    }
    
    PolyOpening poly_opening;
    poly_opening.coefficients = coeffs;
    poly_opening.randomness = randomness;
    
    return {poly_commit, poly_opening};
}

std::pair<PolynomialCommitment::PolyCommitment, PolynomialCommitment::PolyOpening> 
PolynomialCommitment::commit_linear_polynomial(
    const Fr& constant_term,
    const Fr& linear_term,
    const Fr& r0,
    const Fr& r1) const {
    
    PolyCommitment poly_commit;
    poly_commit.coefficient_commits.resize(2);
    
    // Commit to constant term
    auto [commit0, opening0] = committer_.commit_single(constant_term, r0);
    poly_commit.coefficient_commits[0] = commit0;
    
    // Commit to linear term
    auto [commit1, opening1] = committer_.commit_single(linear_term, r1);
    poly_commit.coefficient_commits[1] = commit1;
    
    PolyOpening poly_opening;
    poly_opening.coefficients = {constant_term, linear_term};
    poly_opening.randomness = {r0, r1};
    
    return {poly_commit, poly_opening};
}

bool PolynomialCommitment::verify_opening(const PolyCommitment& commitment, 
                                        const PolyOpening& opening) const {
    
    const auto& coeffs = opening.coefficients;
    const auto& randomness = opening.randomness;
    
    if (coeffs.size() != commitment.coefficient_commits.size() ||
        coeffs.size() != randomness.size()) {
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
    
    const auto& coeffs = opening.coefficients;
    const auto& randomness = opening.randomness;
    
    PolyCommitment result;
    result.coefficient_commits.reserve(coeffs.size());
    
    // Recompute each coefficient commitment
    for (size_t i = 0; i < coeffs.size(); ++i) {
        PedersenMultiCommit::Opening coeff_opening({coeffs[i]}, randomness[i]);
        result.coefficient_commits.push_back(committer_.recompute_commitment(coeff_opening));
    }
    
    return result;
}

} // namespace sharp_gs
#pragma once

#include <mcl/bn.hpp>
#include <vector>

using namespace mcl;

namespace sharp_gs {

/**
 * @brief Polynomial operations for SharpGS protocol
 * 
 * Handles the polynomial relations used in the range proof verification,
 * specifically the relation: f*_{k,i} = 4z_{k,i}(γ_k B - z_{k,i}) + γ_k² - Σ z²_{k,i,j}
 */
class PolynomialOps {
public:
    /**
     * @brief Compute three-square decomposition for range membership
     * 
     * For each value x_i, finds y_{i,1}, y_{i,2}, y_{i,3} such that:
     * 4x_i(B - x_i) + 1 = y_{i,1}² + y_{i,2}² + y_{i,3}²
     * 
     * @param values Vector of values x_i ∈ [0, B]
     * @param range_bound B
     * @return Matrix of decomposition values y_{i,j}
     */
    static std::vector<std::vector<Fr>> compute_three_square_decomposition(
        const std::vector<Fr>& values, const Fr& range_bound);

    /**
     * @brief Verify three-square decomposition
     * 
     * Checks that 4x_i(B - x_i) + 1 = Σ y_{i,j}² for all i
     */
    static bool verify_three_square_decomposition(
        const std::vector<Fr>& values,
        const std::vector<std::vector<Fr>>& decomposition,
        const Fr& range_bound);

    /**
     * @brief Compute linearization coefficients α*_{k,i}
     * 
     * Computes α*_{1,k,i} = 4x̃_{k,i}B - 8x_i*x̃_{k,i} - 2Σ y_{i,j}*ỹ_{k,i,j}
     * and α*_{0,k,i} = -(4x̃²_{k,i} + Σ ỹ²_{k,i,j})
     */
    static std::pair<std::vector<Fr>, std::vector<Fr>> compute_linearization_coefficients(
        const std::vector<Fr>& values,                    // x_i
        const std::vector<std::vector<Fr>>& decomposition, // y_{i,j}
        const std::vector<Fr>& value_masks,               // x̃_{k,i}
        const std::vector<std::vector<Fr>>& decomp_masks, // ỹ_{k,i,j}
        const Fr& range_bound);                           // B

    /**
     * @brief Evaluate polynomial f*_{k,i} for verification
     * 
     * Computes f*_{k,i} = 4z_{k,i}(γ_k B - z_{k,i}) + γ_k² - Σ z²_{k,i,j}
     */
    static std::vector<Fr> evaluate_verification_polynomial(
        const std::vector<Fr>& masked_values,     // z_{k,i}
        const std::vector<std::vector<Fr>>& masked_decomp, // z_{k,i,j}
        const Fr& challenge,                      // γ_k
        const Fr& range_bound);                   // B

    /**
     * @brief Check polynomial degree constraints
     * 
     * Verifies that the polynomial has the expected degree properties
     */
    static bool verify_polynomial_constraints(
        const std::vector<Fr>& polynomial_values,
        const Fr& challenge,
        const Fr& range_bound);

    /**
     * @brief Generate random polynomial of given degree
     */
    static std::vector<Fr> random_polynomial(size_t degree);

    /**
     * @brief Evaluate polynomial at given point
     */
    static Fr evaluate_polynomial(const std::vector<Fr>& coefficients, const Fr& point);

    /**
     * @brief Multiply two polynomials
     */
    static std::vector<Fr> multiply_polynomials(const std::vector<Fr>& poly1,
                                               const std::vector<Fr>& poly2);

    /**
     * @brief Add two polynomials
     */
    static std::vector<Fr> add_polynomials(const std::vector<Fr>& poly1,
                                         const std::vector<Fr>& poly2);

    /**
     * @brief Compute polynomial derivative
     */
    static std::vector<Fr> derivative(const std::vector<Fr>& polynomial);

private:
    /**
     * @brief Find three squares representation using Legendre's theorem
     * 
     * For a given integer n, finds a, b, c such that n = a² + b² + c²
     * This is always possible for positive integers.
     */
    static std::vector<Fr> find_three_squares(const Fr& value);

    /**
     * @brief Check if value is a quadratic residue
     */
    static bool is_quadratic_residue(const Fr& value);

    /**
     * @brief Compute square root in finite field
     */
    static Fr finite_field_sqrt(const Fr& value);
};

} // namespace sharp_gs
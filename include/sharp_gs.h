#pragma once

#include <mcl/bn.hpp>
#include <vector>
#include "groups.h"
#include "commitments.h"
#include "masking.h"

using namespace mcl;

namespace sharp_gs {

/**
 * @brief SharpGS Range Proof Protocol Implementation
 * 
 * Implements the optimized range proof with group switching as described
 * in Algorithm 1 of the Sharp paper: "Sharp: Short Relaxed Range Proofs"
 */
class SharpGS {
public:
    /**
     * @brief Protocol parameters following Sharp paper notation
     */
    struct Parameters {
        size_t N;              // Number of values to prove simultaneously
        size_t R;              // Number of protocol repetitions
        size_t B;              // Range bound [0, B]
        size_t Gamma;          // Challenge space size
        size_t L_x;            // Masking overhead for values
        size_t L_r;            // Masking overhead for randomness
        size_t S;              // Hiding parameter for commitments
        size_t security_bits;  // Security parameter λ
        
        Parameters(size_t range_bits = 32, size_t batch_size = 1, size_t sec_bits = 128);
        void compute_dependent_params();
        bool validate() const;
    };

    /**
     * @brief Public statement for range proof
     */
    struct Statement {
        PedersenCommitment C_x;  // Commitment to values x_i
        Fr range_bound;          // Range bound B
        
        Statement() = default;
        Statement(const PedersenCommitment& commit, const Fr& bound) 
            : C_x(commit), range_bound(bound) {}
    };

    /**
     * @brief Secret witness for range proof
     */
    struct Witness {
        std::vector<Fr> values;      // x_i values in range [0, B]
        Fr commitment_randomness;     // r_x for commitment randomness
        
        Witness() = default;
        Witness(const std::vector<Fr>& vals, const Fr& rand)
            : values(vals), commitment_randomness(rand) {}
            
        bool is_valid(const Statement& statement, const Parameters& params) const;
    };

    /**
     * @brief First flow commitments (Prover → Verifier)
     */
    struct FirstFlow {
        PedersenCommitment C_y;                    // Commitment to decomposition
        std::vector<PedersenCommitment> C_k_star;  // Linearization commitments
        std::vector<PedersenCommitment> D_k_x;     // Value mask commitments
        std::vector<PedersenCommitment> D_k_y;     // Decomposition mask commitments
        std::vector<PedersenCommitment> D_k_star;  // Linearization mask commitments
    };

    /**
     * @brief Second flow challenges (Verifier → Prover)
     */
    struct SecondFlow {
        std::vector<Fr> gamma;  // Random challenges γ_k ∈ [0, Γ]
    };

    /**
     * @brief Third flow responses (Prover → Verifier)
     */
    struct ThirdFlow {
        std::vector<std::vector<Fr>> z_values;     // Masked values z_{k,i}
        std::vector<std::vector<std::vector<Fr>>> z_decomp;  // Masked decomp z_{k,i,j}
        std::vector<Fr> t_x;                       // Masked commitment randomness
        std::vector<Fr> t_y;                       // Masked decomp randomness
        std::vector<Fr> t_star;                    // Masked linearization randomness
    };

    /**
     * @brief Complete proof transcript
     */
    struct Proof {
        FirstFlow first_flow;
        SecondFlow second_flow;
        ThirdFlow third_flow;
        
        size_t size_bytes() const;
    };

private:
    Parameters params_;
    GroupManager groups_;
    MaskingScheme masking_;

public:
    explicit SharpGS(const Parameters& params);

    /**
     * @brief Generate a range proof
     */
    Proof prove(const Statement& statement, const Witness& witness);

    /**
     * @brief Verify a range proof
     */
    bool verify(const Statement& statement, const Proof& proof);

    /**
     * @brief Get protocol parameters
     */
    const Parameters& get_parameters() const { return params_; }

private:
    /**
     * @brief Compute three-square decomposition: 4x_i(B - x_i) + 1 = Σ y_{i,j}²
     */
    std::vector<std::vector<Fr>> compute_decomposition(const std::vector<Fr>& values);

    /**
     * @brief Generate first flow commitments
     */
    FirstFlow generate_first_flow(const Witness& witness, 
                                  const std::vector<std::vector<Fr>>& decomposition);

    /**
     * @brief Generate challenges (for Fiat-Shamir)
     */
    SecondFlow generate_challenges(const Statement& statement, const FirstFlow& first_flow);

    /**
     * @brief Generate third flow responses
     */
    ThirdFlow generate_third_flow(const Witness& witness,
                                  const std::vector<std::vector<Fr>>& decomposition,
                                  const SecondFlow& challenges,
                                  const FirstFlow& first_flow);

    /**
     * @brief Verify the polynomial relation f*_{k,i} = 4z_{k,i}(γ_k B - z_{k,i}) + γ_k² - Σ z²_{k,i,j}
     */
    bool verify_polynomial_relation(const SecondFlow& challenges, const ThirdFlow& responses);

    /**
     * @brief Verify range checks on masked values
     */
    bool verify_range_checks(const ThirdFlow& responses);
};

} // namespace sharp_gs
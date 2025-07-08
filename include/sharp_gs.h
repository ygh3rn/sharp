#pragma once

#include "groups.h"
#include "commitments.h"
#include "masking.h"
#include "polynomial.h"
#include <vector>
#include <optional>
#include <memory>

namespace sharp_gs {

/**
 * @brief SharpGS Range Proof Protocol Implementation
 * 
 * Implements the optimized range proof with group switching and batching
 * as described in Algorithm 1 of the Sharp paper.
 */
class SharpGS {
public:
    /**
     * @brief Protocol parameters
     */
    struct Parameters {
        size_t security_bits;      // λ (e.g., 128)
        size_t range_bits;         // log₂(B) - range is [0, 2^range_bits - 1]
        size_t challenge_bits;     // log₂(Γ) - challenge space size
        size_t batch_size;         // N - number of values to prove simultaneously
        size_t repetitions;        // R - number of protocol repetitions
        size_t masking_overhead;   // L - masking overhead factor
        bool use_hash_optimization; // Whether to use hash optimization
        
        Parameters(size_t sec_bits = 128, size_t range_bits = 64, size_t batch_size = 1);
        
        // Validation and computation
        bool validate() const;
        void compute_dependent_params();
        size_t estimate_proof_size() const;
    };

    /**
     * @brief Public statement for range proof
     */
    struct Statement {
        std::vector<PedersenMultiCommit::Commitment> value_commitments; // Cx for each xi
        Fr range_bound;                                                 // B
        
        Statement() = default;
        Statement(const std::vector<PedersenMultiCommit::Commitment>& commits, const Fr& bound)
            : value_commitments(commits), range_bound(bound) {}
            
        bool is_valid() const;
        size_t batch_size() const { return value_commitments.size(); }
        size_t size_bytes() const;
    };

    /**
     * @brief Secret witness for range proof
     */
    struct Witness {
        std::vector<Fr> values;      // xi values in range [0, B]
        std::vector<Fr> randomness;  // Commitment randomness for each xi
        
        Witness() = default;
        Witness(const std::vector<Fr>& vals, const std::vector<Fr>& rands)
            : values(vals), randomness(rands) {}
            
        bool is_valid(const Statement& statement) const;
        size_t batch_size() const { return values.size(); }
    };

    /**
     * @brief Protocol transcript
     */
    struct Transcript {
        // First flow (Prover -> Verifier)
        PedersenMultiCommit::Commitment decomposition_commitment;  // Cy
        std::vector<std::vector<PedersenMultiCommit::Commitment>> round_commitments; // Per round commitments
        std::optional<std::vector<uint8_t>> commitment_hash;       // Hash optimization
        
        // Second flow (Verifier -> Prover) 
        std::vector<Fr> challenges;  // γ₁, ..., γᵣ
        
        // Third flow (Prover -> Verifier)
        std::vector<std::vector<Fr>> masked_values;     // z values per round
        std::vector<std::vector<Fr>> masked_randomness; // Masked commitment randomness
        
        bool is_complete() const;
        size_t size_bytes() const;
    };

    /**
     * @brief Zero-knowledge proof
     */
    struct Proof {
        Transcript transcript;
        
        bool is_valid() const { return transcript.is_complete(); }
        size_t size_bytes() const { return transcript.size_bytes(); }
        
        // Serialization
        std::vector<uint8_t> serialize() const;
        static std::optional<Proof> deserialize(const std::vector<uint8_t>& data);
    };

private:
    Parameters params_;
    std::unique_ptr<GroupManager> groups_;             // FIX: Made accessible via getter
    std::unique_ptr<PedersenMultiCommit> gcom_committer_;
    std::unique_ptr<PedersenMultiCommit> g3sq_committer_;
    std::unique_ptr<SharpGSMasking> masking_;
    bool initialized_;

public:
    explicit SharpGS(const Parameters& params);
    ~SharpGS() = default;
    
    // Non-copyable but movable
    SharpGS(const SharpGS&) = delete;
    SharpGS& operator=(const SharpGS&) = delete;
    SharpGS(SharpGS&&) = default;
    SharpGS& operator=(SharpGS&&) = default;
    
    /**
     * @brief Initialize the protocol with computed parameters
     */
    bool initialize();
    
    /**
     * @brief Check if protocol is properly initialized
     */
    bool is_initialized() const { return initialized_; }
    
    /**
     * @brief Get protocol parameters
     */
    const Parameters& params() const { return params_; }
    
    /**
     * @brief FIX: Added public getter for groups
     */
    const GroupManager& groups() const { return *groups_; }
    
    /**
     * @brief Generate a range proof
     */
    std::optional<Proof> prove(const Statement& statement, const Witness& witness);
    
    /**
     * @brief Verify a range proof
     */
    bool verify(const Statement& statement, const Proof& proof);
    
    /**
     * @brief Batch operations - prove multiple statements together
     */
    std::optional<Proof> prove_batch(const std::vector<Statement>& statements, 
                                    const std::vector<Witness>& witnesses);
    
    /**
     * @brief Batch verification
     */
    bool verify_batch(const std::vector<Statement>& statements, const Proof& proof);

    /**
     * @brief Interactive protocol interfaces
     */
    class InteractiveProver {
    private:
        const SharpGS& protocol_;
        Statement statement_;
        Witness witness_;
        Transcript transcript_;
        std::vector<std::vector<Fr>> decomposition_values_;
        bool state_valid_;
        
    public:
        InteractiveProver(const SharpGS& protocol, const Statement& stmt, const Witness& wit);
        
        std::vector<uint8_t> first_flow();
        bool second_flow(const std::vector<Fr>& challenges);
        std::vector<uint8_t> third_flow();
        
        const Transcript& transcript() const { return transcript_; }
        bool is_valid_state() const { return state_valid_; }
    };

    class InteractiveVerifier {
    private:
        const SharpGS& protocol_;
        Statement statement_;
        Transcript transcript_;
        bool state_valid_;
        
    public:
        InteractiveVerifier(const SharpGS& protocol, const Statement& stmt);
        
        bool receive_first_flow(const std::vector<uint8_t>& message);
        std::vector<Fr> second_flow();
        bool receive_third_flow(const std::vector<uint8_t>& message);
        
        bool final_verification();
        const Transcript& transcript() const { return transcript_; }
        bool is_valid_state() const { return state_valid_; }
    };

    /**
     * @brief Create interactive prover
     */
    std::unique_ptr<InteractiveProver> create_prover(
        const Statement& statement, 
        const Witness& witness
    );

    /**
     * @brief Create interactive verifier
     */
    std::unique_ptr<InteractiveVerifier> create_verifier(const Statement& statement);

private:
    // Internal helper methods
    bool setup_groups();
    bool setup_commitments();
    bool setup_masking();
    
    std::vector<std::vector<Fr>> compute_three_square_decomposition(
        const std::vector<Fr>& values, 
        const Fr& range_bound
    ) const;  // FIX: Added const
    
    bool verify_decomposition_commitments(
        const Transcript& transcript,
        const Statement& statement
    ) const;  // FIX: Added const
    
    bool verify_polynomial_relations(
        const Transcript& transcript,
        const Statement& statement
    ) const;  // FIX: Added const
    
    std::vector<Fr> compute_polynomial_coefficients(
        const std::vector<Fr>& masked_values,
        const std::vector<Fr>& masked_squares,
        const Fr& challenge,
        const Fr& range_bound
    ) const;  // FIX: Added const
};

/**
 * @brief Utility functions for SharpGS
 */
namespace sharp_gs_utils {
    
    /**
     * @brief Create statement from values and generate commitments
     */
    std::pair<SharpGS::Statement, SharpGS::Witness> create_statement_and_witness(
        const std::vector<Fr>& values,
        const Fr& range_bound,
        const GroupManager& groups
    );

    /**
     * @brief Validate range proof parameters
     */
    bool validate_sharp_gs_parameters(const SharpGS::Parameters& params);

    /**
     * @brief Estimate performance metrics
     */
    struct PerformanceEstimate {
        double prover_time_ms;
        double verifier_time_ms;
        size_t proof_size_bytes;
        double success_probability;
    };
    
    PerformanceEstimate estimate_performance(const SharpGS::Parameters& params);
    
    /**
     * @brief Generate test vectors
     */
    std::vector<std::pair<SharpGS::Statement, SharpGS::Witness>> generate_test_cases(
        const SharpGS::Parameters& params,
        size_t num_cases = 10
    );
}

} // namespace sharp_gs
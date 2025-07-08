#pragma once

#include "groups.h"
#include "commitments.h"
#include "masking.h"
#include "polynomial.h"
#include "utils.h"
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
        std::vector<std::vector<PedersenMultiCommit::Commitment>> round_commitments; // Per repetition
        std::optional<std::vector<uint8_t>> commitment_hash;      // Hash optimization
        
        // Second flow (Verifier -> Prover)  
        std::vector<Fr> challenges;  // γk for k ∈ [1, R]
        
        // Third flow (Prover -> Verifier)
        std::vector<std::vector<Fr>> masked_values;      // zk,i for each repetition k
        std::vector<std::vector<Fr>> masked_randomness;  // tk,x, tk,y, tk,* for each k
        
        Transcript() = default;
        bool is_complete() const;
        size_t size_bytes() const;
    };

    /**
     * @brief Proof structure
     */
    struct Proof {
        Transcript transcript;
        Parameters parameters;
        
        Proof() = default;
        Proof(const Transcript& trans, const Parameters& params)
            : transcript(trans), parameters(params) {}
            
        bool is_valid() const;
        size_t size_bytes() const { return transcript.size_bytes(); }
    };

private:
    Parameters params_;
    std::unique_ptr<GroupManager> groups_;
    std::unique_ptr<PedersenMultiCommit> gcom_committer_;
    std::unique_ptr<PedersenMultiCommit> g3sq_committer_;
    std::unique_ptr<SharpGSMasking> masking_;
    bool initialized_;

public:
    /**
     * @brief Constructor
     */
    explicit SharpGS(const Parameters& params = Parameters());
    
    /**
     * @brief Destructor
     */
    ~SharpGS();

    /**
     * @brief Initialize the protocol with given parameters
     */
    bool initialize();

    /**
     * @brief Check if protocol is properly initialized
     */
    bool is_initialized() const { return initialized_; }

    /**
     * @brief Get protocol parameters
     */
    const Parameters& parameters() const { return params_; }

    /**
     * @brief Generate a range proof
     * @param statement Public statement (commitments and range bound)
     * @param witness Secret witness (values and randomness)
     * @return Proof or nullopt if proof generation failed
     */
    std::optional<Proof> prove(const Statement& statement, const Witness& witness);

    /**
     * @brief Verify a range proof
     * @param statement Public statement
     * @param proof Proof to verify
     * @return True if proof is valid
     */
    bool verify(const Statement& statement, const Proof& proof);

    /**
     * @brief Interactive prover interface
     */
    class InteractiveProver {
    private:
        SharpGS& protocol_;
        Statement statement_;
        Witness witness_;
        Transcript transcript_;
        std::vector<std::vector<Fr>> decomposition_values_; // yi,j for each i
        std::vector<Fr> decomp_randomness_;
        bool state_valid_;

    public:
        InteractiveProver(SharpGS& protocol, const Statement& stmt, const Witness& wit);
        
        /**
         * @brief First flow: compute and send commitments
         */
        std::optional<std::vector<uint8_t>> first_flow();
        
        /**
         * @brief Second flow: receive challenges
         */
        bool receive_challenges(const std::vector<Fr>& challenges);
        
        /**
         * @brief Third flow: compute and send responses
         */
        std::optional<std::vector<uint8_t>> third_flow();
        
        /**
         * @brief Get completed transcript
         */
        const Transcript& get_transcript() const { return transcript_; }
        
        bool is_valid_state() const { return state_valid_; }
    };

    /**
     * @brief Interactive verifier interface  
     */
    class InteractiveVerifier {
    private:
        SharpGS& protocol_;
        Statement statement_;
        Transcript transcript_;
        bool state_valid_;

    public:
        InteractiveVerifier(SharpGS& protocol, const Statement& stmt);
        
        /**
         * @brief First flow: receive commitments
         */
        bool receive_first_flow(const std::vector<uint8_t>& message);
        
        /**
         * @brief Second flow: generate and send challenges
         */
        std::vector<Fr> generate_challenges();
        
        /**
         * @brief Third flow: receive and verify responses
         */
        bool receive_third_flow(const std::vector<uint8_t>& message);
        
        /**
         * @brief Final verification
         */
        bool verify();
        
        const Transcript& get_transcript() const { return transcript_; }
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
    );
    
    bool verify_decomposition_commitments(
        const Transcript& transcript,
        const Statement& statement
    );
    
    bool verify_polynomial_relations(
        const Transcript& transcript,
        const Statement& statement
    );
    
    std::vector<Fr> compute_polynomial_coefficients(
        const std::vector<Fr>& masked_values,
        const std::vector<Fr>& masked_squares,
        const Fr& challenge,
        const Fr& range_bound
    );
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
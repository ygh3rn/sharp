#pragma once

#include <mcl/bn.hpp>
#include <vector>
#include "commitments.h"
#include "polynomial.h"

using namespace mcl;
using namespace std;

// SharpGS Protocol Parameters
struct SharpGSParams {
    size_t security_level;      // λ (security parameter)
    size_t range_bits;          // B (range bound)
    size_t challenge_bits;      // Γ (challenge space)
    size_t masking_bits;        // L (masking overhead)
    size_t repetitions;         // R (number of repetitions)
    
    // Group orders
    Fr p_order;                 // Order of commitment group
    Fr q_order;                 // Order of decomposition group
    
    SharpGSParams(size_t sec_level = 128, size_t range_b = 32);
    
    // Validate parameters according to paper constraints
    bool validate_parameters() const;
    
    // Get actual bounds
    size_t get_range_bound() const { return 1UL << range_bits; }
    size_t get_challenge_bound() const { return (1UL << challenge_bits) - 1; }
    size_t get_masking_bound() const { return (1UL << masking_bits) - 1; }
    
    // Additional helper functions
    size_t get_commitment_group_size() const;
    size_t get_decomposition_group_size() const;
    double get_soundness_error() const;
    size_t get_proof_size_estimate() const;
};

// Public parameters for SharpGS
struct SharpGSPublicParams {
    CommitmentKey ck_com;       // Commitment key for Gcom
    CommitmentKey ck_3sq;       // Commitment key for G3sq (3-square)
    SharpGSParams params;
    
    SharpGSPublicParams() = default;
    SharpGSPublicParams(const SharpGSParams& p);
};

// Witness for range proof
struct SharpGSWitness {
    vector<Fr> values;          // x1, ..., xN (values in range)
    Fr randomness;              // rx (commitment randomness)
    
    SharpGSWitness() = default;
    SharpGSWitness(const vector<Fr>& vals, const Fr& rand) 
        : values(vals), randomness(rand) {}
};

// Statement for range proof
struct SharpGSStatement {
    Commitment value_commit;    // Commitment to values
    Fr range_bound;            // B (upper bound of range [0,B])
    
    SharpGSStatement() = default;
    SharpGSStatement(const Commitment& comm, const Fr& bound)
        : value_commit(comm), range_bound(bound) {}
};

// First message of SharpGS protocol
struct SharpGSFirstMessage {
    Commitment y_commit;                    // Cy (commitment to decomposition)
    vector<vector<Commitment>> d_commits;   // Dk,x, Dk,y, Dk,* for each repetition
    
    SharpGSFirstMessage() = default;
};

// Challenge for SharpGS protocol  
struct SharpGSChallenge {
    vector<Fr> challenges;      // γk for k ∈ [1,R]
    
    SharpGSChallenge() = default;
    SharpGSChallenge(const vector<Fr>& chals) : challenges(chals) {}
};

// Response for SharpGS protocol
struct SharpGSResponse {
    vector<vector<Fr>> z_values;    // zk,i,j values
    vector<Fr> t_values;            // tk,x, tk,y, t*k values
    
    SharpGSResponse() = default;
};

// Complete SharpGS proof
struct SharpGSProof {
    SharpGSFirstMessage first_msg;
    SharpGSChallenge challenge;
    SharpGSResponse response;
    
    SharpGSProof() = default;
};

// Main SharpGS protocol class
class SharpGS {
public:
    // Setup protocol parameters
    static SharpGSPublicParams setup(const SharpGSParams& params);
    
    // Generate range proof (interactive version)
    static SharpGSFirstMessage prove_first(const SharpGSPublicParams& pp,
                                          const SharpGSStatement& stmt,
                                          const SharpGSWitness& witness);
    
    static SharpGSResponse prove_second(const SharpGSPublicParams& pp,
                                       const SharpGSStatement& stmt,
                                       const SharpGSWitness& witness,
                                       const SharpGSFirstMessage& first_msg,
                                       const SharpGSChallenge& challenge);
    
    // Verify range proof
    static bool verify(const SharpGSPublicParams& pp,
                      const SharpGSStatement& stmt,
                      const SharpGSProof& proof);
    
    // Non-interactive version using Fiat-Shamir
    static SharpGSProof prove(const SharpGSPublicParams& pp,
                             const SharpGSStatement& stmt,
                             const SharpGSWitness& witness);
    
    // Generate challenge (for interactive version)
    static SharpGSChallenge generate_challenge(const SharpGSParams& params);
    
    // Fiat-Shamir challenge generation
    static SharpGSChallenge fiat_shamir_challenge(const SharpGSPublicParams& pp,
                                                 const SharpGSStatement& stmt,
                                                 const SharpGSFirstMessage& first_msg);

private:
    // Compute 3-square decomposition: 4x(B-x) + 1 = Σ y²ᵢ
    static vector<Fr> compute_square_decomposition(const Fr& x, const Fr& B);
    
    // Verify square decomposition
    static bool verify_square_decomposition(const Fr& x, const Fr& B, const vector<Fr>& y_values);
    
    // Masking operations for zero-knowledge
    static Fr apply_masking(const Fr& value, const Fr& mask, size_t masking_bits);
    static bool check_masking_bounds(const Fr& masked_value, size_t range_bits, 
                                   size_t challenge_bits, size_t masking_bits);
    
    // Compute decomposition polynomial coefficients
    static vector<Fr> compute_decomposition_coeffs(const vector<Fr>& x_values,
                                                   const vector<vector<Fr>>& y_values,
                                                   const vector<Fr>& x_masks,
                                                   const vector<Fr>& y_masks,
                                                   const Fr& B);
    
    // Random Affine Shortness Test (RAST) implementation
    static bool random_affine_shortness_test(const vector<Fr>& values, 
                                             const vector<Fr>& challenges,
                                             const Fr& bound);
};
#pragma once

#include <mcl/bls12_381.hpp>
#include <vector>
#include <random>

using namespace mcl;
using namespace std;

/**
 * Pedersen Multi-Commitment (MPed) Implementation
 * 
 * Based on SharpGS paper section 2.3.3:
 * MPed allows committing to multiple values {x_i} in a single commitment
 * C = r*G_0 + sum(x_i * G_i) for i in [1,N]
 * 
 * Provides computational hiding under SI/SEI assumptions
 * and computational binding under DLOG assumption
 */
class MPed {
public:
    struct CommitmentKey {
        vector<G1> generators; // G_0, G_1, ..., G_N (cryptographically independent)
        size_t max_values;     // Maximum number of values (N)
        Fr hiding_bound;       // Hiding parameter S (2^256-1 for security)
    };
    
    struct Commitment {
        G1 commit;             // The commitment C
        Fr randomness;         // Opening randomness r
        vector<Fr> values;     // Committed values {x_i}
        
        // Default constructor
        Commitment() = default;
        
        // Constructor with values
        Commitment(const G1& c, const Fr& r, const vector<Fr>& vals)
            : commit(c), randomness(r), values(vals) {}
    };
    
    struct Opening {
        Fr randomness;         // Opening randomness r
        vector<Fr> values;     // Opened values {x_i}
    };

private:
    static mt19937 rng;
    
public:
    /**
     * Setup: Generate commitment key with N+1 cryptographically independent generators
     * @param max_values Maximum number of values to commit (N)
     * @param hiding_parameter Hiding bound S (default: 2^256-1 for SharpGS security)
     * @return CommitmentKey with generators G_0, ..., G_N
     */
    static CommitmentKey Setup(size_t max_values, const Fr& hiding_parameter = Fr(0));
    
    /**
     * Commit: Create commitment to vector of values
     * C = r*G_0 + sum(x_i * G_i) for i in [1,N]
     * @param values Vector of values to commit {x_1, ..., x_k} where k <= N
     * @param ck Commitment key
     * @param randomness Optional randomness (if not provided, chosen uniformly from [0,S])
     * @return Commitment containing C and opening information
     */
    static Commitment Commit(const vector<Fr>& values, 
                           const CommitmentKey& ck,
                           const Fr* randomness = nullptr);
    
    /**
     * VerifyOpen: Verify that commitment opens to given values
     * @param commitment The commitment C
     * @param opening Opening information (r, {x_i})
     * @param ck Commitment key
     * @return true if C = r*G_0 + sum(x_i * G_i), false otherwise
     */
    static bool VerifyOpen(const G1& commitment,
                          const Opening& opening,
                          const CommitmentKey& ck);
    
    /**
     * VerifyOpen: Verify that commitment opens to given values (convenience method)
     */
    static bool VerifyOpen(const Commitment& commit_obj,
                          const CommitmentKey& ck);
    
    /**
     * AddCommitments: Homomorphic addition of commitments
     * Com(x1, r1) + Com(x2, r2) = Com(x1+x2, r1+r2)
     * @param c1 First commitment
     * @param c2 Second commitment  
     * @param ck Commitment key
     * @return Combined commitment
     */
    static Commitment AddCommitments(const Commitment& c1,
                                   const Commitment& c2,
                                   const CommitmentKey& ck);
    
    /**
     * ScalarMultCommitment: Scalar multiplication of commitment
     * s * Com(x, r) = Com(s*x, s*r)
     * @param commit Input commitment
     * @param scalar Scalar multiplier
     * @param ck Commitment key
     * @return Scaled commitment
     */
    static Commitment ScalarMultCommitment(const Commitment& commit,
                                         const Fr& scalar,
                                         const CommitmentKey& ck);
    
    /**
     * RecommitSingle: Commit to single value at specific position
     * @param value Value to commit
     * @param index Position (1-indexed, must be <= max_values)
     * @param ck Commitment key
     * @param randomness Optional randomness
     * @return Commitment with value at specified position
     */
    static Commitment RecommitSingle(const Fr& value,
                                   size_t index,
                                   const CommitmentKey& ck,
                                   const Fr* randomness = nullptr);
    
    /**
     * BatchCommit: Create multiple commitments efficiently
     * @param value_vectors Vector of value vectors to commit
     * @param ck Commitment key
     * @return Vector of commitments
     */
    static vector<Commitment> BatchCommit(const vector<vector<Fr>>& value_vectors,
                                        const CommitmentKey& ck);
    
    /**
     * ValidateParameters: Verify commitment key meets SharpGS security requirements
     * @param ck Commitment key to validate
     * @param max_committed_value Maximum value that will be committed
     * @return true if parameters are secure for SharpGS
     */
    static bool ValidateParameters(const CommitmentKey& ck, 
                                 const Fr& max_committed_value = Fr(0));
    
    // Utility functions
    static void SeedRNG(uint32_t seed);
    static Fr GenerateRandomness(const Fr& bound);
    static bool IsValidCommitmentKey(const CommitmentKey& ck);
    
    // Debug functions
    static void PrintCommitmentKey(const CommitmentKey& ck);
    static void PrintCommitment(const Commitment& commit);
    static string CommitmentToString(const Commitment& commit);
};
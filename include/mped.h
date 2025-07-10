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
     * C = r*G_0 + sum(x_i * G_i)
     * @param values Vector of field elements to commit
     * @param ck Commitment key with sufficient generators
     * @return Commitment object with opening information
     */
    static Commitment Commit(const vector<Fr>& values, const CommitmentKey& ck);
    
    /**
     * Commit with custom randomness (for deterministic testing)
     * @param values Vector of field elements to commit
     * @param randomness Custom randomness value
     * @param ck Commitment key
     * @return Commitment object
     */
    static Commitment Commit(const vector<Fr>& values, const Fr& randomness, const CommitmentKey& ck);
    
    /**
     * CommitInRange: Create commitment with range validation for SharpGS
     * @param values Vector of values, each must be in [0, range_bound)
     * @param range_bound Upper bound for range proof
     * @param ck Commitment key
     * @return Commitment object
     */
    static Commitment CommitInRange(const vector<Fr>& values, const Fr& range_bound, const CommitmentKey& ck);
    
    /**
     * VerifyOpen: Verify commitment opening
     * @param commitment Commitment element C
     * @param opening Opening data (randomness and values)
     * @param ck Commitment key
     * @return true if opening is valid
     */
    static bool VerifyOpen(const G1& commitment, const Opening& opening, const CommitmentKey& ck);
    
    /**
     * VerifyOpen: Verify commitment opening (convenience method)
     * @param commit_obj Complete commitment object
     * @param ck Commitment key
     * @return true if opening is valid
     */
    static bool VerifyOpen(const Commitment& commit_obj, const CommitmentKey& ck);
    
    /**
     * AddCommitments: Homomorphic addition of commitments
     * @param c1 First commitment
     * @param c2 Second commitment
     * @param ck Commitment key
     * @return Sum commitment
     */
    static Commitment AddCommitments(const Commitment& c1, const Commitment& c2, const CommitmentKey& ck);
    
    /**
     * ScalarMultCommitment: Homomorphic scalar multiplication
     * @param commit Input commitment
     * @param scalar Scalar multiplier
     * @param ck Commitment key
     * @return Scaled commitment
     */
    static Commitment ScalarMultCommitment(const Commitment& commit, const Fr& scalar, const CommitmentKey& ck);
    
    /**
     * BatchCommit: Create multiple commitments efficiently
     * @param value_vectors Vector of value vectors to commit
     * @param ck Commitment key
     * @return Vector of commitments
     */
    static vector<Commitment> BatchCommit(const vector<vector<Fr>>& value_vectors, const CommitmentKey& ck);
    
    /**
     * BatchCommitSharpGS: Batch commit with SharpGS parameter validation
     * @param value_batches Vector of value vectors
     * @param range_bound Range bound for each value
     * @param ck Commitment key
     * @return Vector of commitments
     */
    static vector<Commitment> BatchCommitSharpGS(const vector<vector<Fr>>& value_batches,
                                                  const Fr& range_bound,
                                                  const CommitmentKey& ck);
    
    /**
     * RecommitSingle: Commit to single value at specific generator index
     * @param value Single value to commit
     * @param index Generator index (0 for G_0, 1 for G_1, etc.)
     * @param ck Commitment key
     * @return Commitment to single value
     */
    static Commitment RecommitSingle(const Fr& value, size_t index, const CommitmentKey& ck);
    
    /**
     * ValidateSharpGSParameters: Validate parameters for SharpGS compliance
     * @param ck Commitment key to validate
     * @param batch_size Expected batch size
     * @param range_bound Range bound for values
     * @return true if parameters meet SharpGS security requirements
     */
    static bool ValidateSharpGSParameters(const CommitmentKey& ck, size_t batch_size, const Fr& range_bound);
    
    /**
     * GenerateRandomness: Generate cryptographically secure randomness
     * @param bound Upper bound (exclusive), or Fr(0) for full range
     * @return Uniformly random value in [0, bound) or full range
     */
    static Fr GenerateRandomness(const Fr& bound = Fr(0));
    
    /**
     * SetRandomSeed: Set deterministic seed for testing
     * @param seed Random seed value
     */
    static void SetRandomSeed(uint32_t seed);
    
    // Utility functions
    static bool IsValidCommitmentKey(const CommitmentKey& ck);
    static void PrintCommitmentKey(const CommitmentKey& ck);
    static void PrintCommitment(const Commitment& commit);
    static string CommitmentToString(const Commitment& commit);
};
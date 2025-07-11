#pragma once

#include <mcl/bls12_381.hpp>
#include <vector>
#include <random>

using namespace mcl;
using namespace std;

/**
 * FIXED Pedersen Multi-Commitment (MPed) - Checkpoint 1
 * Uses BLS12-381 scalar field maximum value as hiding parameter
 * for proper MCL compatibility and cryptographic security
 */
class MPed {
public:
    struct CommitmentKey {
        vector<G1> generators;
        size_t max_values;
        Fr hiding_bound;
    };
    
    struct Commitment {
        G1 commit;
        Fr randomness;
        vector<Fr> values;
    };
    
    struct Opening {
        Fr randomness;
        vector<Fr> values;
    };

private:
    static mt19937_64 secure_rng;
    static bool rng_initialized;
    
public:
    static CommitmentKey Setup(size_t max_values);
    static Fr GenerateSecureRandomness(const Fr& bound);
    static Commitment Commit(const vector<Fr>& values, const CommitmentKey& ck);
    static bool VerifyOpen(const Commitment& commit_obj, const CommitmentKey& ck);
    static Commitment AddCommitments(const Commitment& c1, const Commitment& c2, const CommitmentKey& ck);
    static bool IsValidCommitmentKey(const CommitmentKey& ck);
    static bool ValidateSharpGSCompliance(const CommitmentKey& ck, size_t B, size_t Gamma, size_t L);
};
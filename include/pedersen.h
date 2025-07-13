#pragma once

#include <mcl/bn.hpp>
#include <vector>

using namespace mcl;
using namespace std;

class PedersenMultiCommitment {
public:
    struct CommitmentKey {
        vector<G1> generators;
        size_t max_values;
    };
    
    struct Commitment {
        G1 value;
        Fr randomness;
    };
    
    // Standard commitment key for N values
    static CommitmentKey setup(size_t N);
    
    // Combined commitment key: G0, G1...GN, G1,1...GN,3
    static CommitmentKey setup_combined(size_t N);
    
    // Independent commitment key with different generators
    static CommitmentKey setup_independent(size_t N, const string& seed_prefix = "Independent");
    
    // Commitment operations
    static Commitment commit(const CommitmentKey& ck, const vector<Fr>& values, const Fr& randomness);
    static Commitment commit_with_offset(const CommitmentKey& ck, const vector<Fr>& values, const Fr& randomness, size_t generator_offset);
    static Commitment commit(const CommitmentKey& ck, const vector<Fr>& values);
    
    // Verification and operations
    static bool verify(const CommitmentKey& ck, const Commitment& comm, const vector<Fr>& values, const Fr& randomness);
    static Commitment add(const Commitment& c1, const Commitment& c2);
    static Commitment multiply(const Commitment& c, const Fr& scalar);
};
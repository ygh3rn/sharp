#pragma once

#include <mcl/bn.hpp>
#include <vector>

using namespace mcl;
using namespace std;

class PedersenMultiCommitment {
public:
    struct CommitmentKey {
        vector<G1> generators;  // G0, G1, ..., GN or G0, G1,1, G1,2, G1,3, ... for three squares
        size_t max_values;
    };
    
    struct Commitment {
        G1 value;
        Fr randomness;
    };
    
    // Generate commitment key for N values plus randomness generator
    static CommitmentKey setup(size_t N);
    
    // Generate commitment key for three squares decomposition (N values, 3 squares each)
    // Creates 1 + N*3 generators: G0, G1,1, G1,2, G1,3, G2,1, G2,2, G2,3, ...
    static CommitmentKey setup_three_squares(size_t N);
    
    // Generate independent commitment key with different generators (for G3sq group)
    // Creates independent H0, H1, ..., HN generators 
    static CommitmentKey setup_independent(size_t N, const string& seed_prefix = "Independent");
    
    // Commit to vector of values with given randomness
    static Commitment commit(const CommitmentKey& ck, 
                           const vector<Fr>& values, 
                           const Fr& randomness);
    
    // Commit to vector of values with random randomness
    static Commitment commit(const CommitmentKey& ck, 
                           const vector<Fr>& values);
    
    // Verify opening of commitment
    static bool verify(const CommitmentKey& ck,
                      const Commitment& comm,
                      const vector<Fr>& values,
                      const Fr& randomness);
    
    // Add two commitments (homomorphic property)
    static Commitment add(const Commitment& c1, const Commitment& c2);
    
    // Multiply commitment by scalar
    static Commitment multiply(const Commitment& c, const Fr& scalar);
};
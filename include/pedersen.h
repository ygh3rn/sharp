#pragma once

#include <mcl/bn.hpp>
#include <vector>

using namespace mcl;
using namespace std;

class PedersenMultiCommitment {
public:
    struct CommitmentKey {
        vector<G1> generators;  // G0, G1, ..., GN
        size_t max_values;
    };
    
    struct Commitment {
        G1 value;
        Fr randomness;
    };
    
    // Generate commitment key for N values plus randomness generator
    static CommitmentKey setup(size_t N);
    
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
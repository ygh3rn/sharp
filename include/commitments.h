#pragma once

#include <mcl/bn.hpp>
#include <vector>

using namespace mcl;
using namespace std;

// Pedersen commitment key
struct CommitmentKey {
    vector<G1> generators;  // G0, G1, ..., GN
    
    CommitmentKey() = default;
    CommitmentKey(size_t num_generators);
};

// Pedersen commitment
struct Commitment {
    G1 value;
    
    Commitment() : value() {}
    Commitment(const G1& v) : value(v) {}
    
    // Arithmetic operations
    Commitment operator+(const Commitment& other) const;
    Commitment operator*(const Fr& scalar) const;
};

// Pedersen multi-commitment scheme
class PedersenCommitment {
public:
    // Setup commitment key with num_generators generators
    static CommitmentKey setup(size_t num_generators);
    
    // Commit to a single value
    static pair<Commitment, Fr> commit(const CommitmentKey& ck, const Fr& value);
    
    // Commit to multiple values
    static pair<Commitment, Fr> commit(const CommitmentKey& ck, const vector<Fr>& values);
    
    // Commit with given randomness
    static Commitment commit(const CommitmentKey& ck, const vector<Fr>& values, const Fr& randomness);
    
    // Verify opening
    static bool verify(const CommitmentKey& ck, const Commitment& comm, 
                      const vector<Fr>& values, const Fr& randomness);
    
    // Verify single value opening
    static bool verify(const CommitmentKey& ck, const Commitment& comm, 
                      const Fr& value, const Fr& randomness);
};
#include "commitments.h"
#include "utils.h"
#include <stdexcept>

CommitmentKey::CommitmentKey(size_t num_generators) {
    generators.resize(num_generators);
    for (size_t i = 0; i < num_generators; i++) {
        generators[i] = Utils::random_g1();
    }
}

Commitment Commitment::operator+(const Commitment& other) const {
    G1 result;
    G1::add(result, value, other.value);
    return Commitment(result);
}

Commitment Commitment::operator*(const Fr& scalar) const {
    G1 result;
    G1::mul(result, value, scalar);
    return Commitment(result);
}

CommitmentKey PedersenCommitment::setup(size_t num_generators) {
    return CommitmentKey(num_generators);
}

pair<Commitment, Fr> PedersenCommitment::commit(const CommitmentKey& ck, const Fr& value) {
    if (ck.generators.size() < 2) {
        throw invalid_argument("Need at least 2 generators for commitment");
    }
    
    Fr randomness = Utils::random_fr();
    
    G1 result;
    G1::mul(result, ck.generators[0], randomness);  // r * G0
    
    G1 value_term;
    G1::mul(value_term, ck.generators[1], value);   // x * G1
    G1::add(result, result, value_term);
    
    return make_pair(Commitment(result), randomness);
}

pair<Commitment, Fr> PedersenCommitment::commit(const CommitmentKey& ck, const vector<Fr>& values) {
    if (ck.generators.size() < values.size() + 1) {
        throw invalid_argument("Not enough generators for commitment");
    }
    
    Fr randomness = Utils::random_fr();
    
    G1 result;
    G1::mul(result, ck.generators[0], randomness);  // r * G0
    
    for (size_t i = 0; i < values.size(); i++) {
        G1 value_term;
        G1::mul(value_term, ck.generators[i + 1], values[i]);
        G1::add(result, result, value_term);
    }
    
    return make_pair(Commitment(result), randomness);
}

Commitment PedersenCommitment::commit(const CommitmentKey& ck, const vector<Fr>& values, const Fr& randomness) {
    if (ck.generators.size() < values.size() + 1) {
        throw invalid_argument("Not enough generators for commitment");
    }
    
    G1 result;
    G1::mul(result, ck.generators[0], randomness);  // r * G0
    
    for (size_t i = 0; i < values.size(); i++) {
        G1 value_term;
        G1::mul(value_term, ck.generators[i + 1], values[i]);
        G1::add(result, result, value_term);
    }
    
    return Commitment(result);
}

bool PedersenCommitment::verify(const CommitmentKey& ck, const Commitment& comm, 
                               const vector<Fr>& values, const Fr& randomness) {
    if (ck.generators.size() < values.size() + 1) {
        return false;
    }
    
    G1 expected;
    G1::mul(expected, ck.generators[0], randomness);
    
    for (size_t i = 0; i < values.size(); i++) {
        G1 value_term;
        G1::mul(value_term, ck.generators[i + 1], values[i]);
        G1::add(expected, expected, value_term);
    }
    
    return comm.value == expected;
}

bool PedersenCommitment::verify(const CommitmentKey& ck, const Commitment& comm, 
                               const Fr& value, const Fr& randomness) {
    return verify(ck, comm, vector<Fr>{value}, randomness);
}
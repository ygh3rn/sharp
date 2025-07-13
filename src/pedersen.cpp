// src/pedersen.cpp - FIXED for MCL API compatibility
#include "pedersen.h"
#include <random>
#include <stdexcept>
#include <string>

PedersenMultiCommitment::CommitmentKey PedersenMultiCommitment::setup(size_t N) {
    CommitmentKey ck;
    ck.max_values = N;
    ck.generators.resize(N + 1);
    
    for (size_t i = 0; i <= N; i++) {
        // Create deterministic but cryptographically independent generators
        std::string seed = "SharpGS_generator_" + std::to_string(i);
        
        // Use MCL's hash-to-curve function (available in your version)
        hashAndMapToG1(ck.generators[i], seed.c_str(), seed.length());
        
        // Verify the generator is valid
        if (ck.generators[i].isZero() || !ck.generators[i].isValid()) {
            throw std::runtime_error("Failed to generate valid generator " + std::to_string(i));
        }
    }
    
    return ck;
}

PedersenMultiCommitment::Commitment PedersenMultiCommitment::commit(
    const CommitmentKey& ck, 
    const std::vector<Fr>& values, 
    const Fr& randomness) {
    
    if (values.size() > ck.max_values) {
        throw std::invalid_argument("Too many values for commitment key");
    }
    
    Commitment comm;
    comm.randomness = randomness;
    
    // Compute commitment: r*G0 + Σ x_i*G_i
    G1::mul(comm.value, ck.generators[0], randomness);
    
    for (size_t i = 0; i < values.size(); i++) {
        G1 term;
        G1::mul(term, ck.generators[i + 1], values[i]);
        G1::add(comm.value, comm.value, term);
    }
    
    return comm;
}

PedersenMultiCommitment::Commitment PedersenMultiCommitment::commit(
    const CommitmentKey& ck, 
    const std::vector<Fr>& values) {
    
    Fr randomness;
    randomness.setByCSPRNG();
    return commit(ck, values, randomness);
}

bool PedersenMultiCommitment::verify(
    const CommitmentKey& ck,
    const Commitment& comm,
    const std::vector<Fr>& values,
    const Fr& randomness) {
    
    Commitment expected = commit(ck, values, randomness);
    return comm.value == expected.value;
}

PedersenMultiCommitment::Commitment PedersenMultiCommitment::add(
    const Commitment& c1, 
    const Commitment& c2) {
    
    Commitment result;
    G1::add(result.value, c1.value, c2.value);
    Fr::add(result.randomness, c1.randomness, c2.randomness);
    return result;
}

PedersenMultiCommitment::Commitment PedersenMultiCommitment::multiply(
    const Commitment& c, 
    const Fr& scalar) {
    
    Commitment result;
    G1::mul(result.value, c.value, scalar);
    Fr::mul(result.randomness, c.randomness, scalar);
    return result;
}
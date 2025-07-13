#include "pedersen.h"
#include <random>
#include <stdexcept>
#include <string>

PedersenMultiCommitment::CommitmentKey PedersenMultiCommitment::setup(size_t N) {
    CommitmentKey ck;
    ck.max_values = N;
    ck.generators.resize(N + 1);
    
    for (size_t i = 0; i <= N; i++) {
        std::string seed = "SharpGS_generator_" + std::to_string(i);
        hashAndMapToG1(ck.generators[i], seed.c_str(), seed.length());
        
        if (ck.generators[i].isZero() || !ck.generators[i].isValid()) {
            throw std::runtime_error("Failed to generate valid generator " + std::to_string(i));
        }
    }
    
    return ck;
}

PedersenMultiCommitment::CommitmentKey PedersenMultiCommitment::setup_combined(size_t N) {
    CommitmentKey ck;
    ck.max_values = N + N*3;
    ck.generators.resize(1 + N + N*3);
    
    // G0 generator
    std::string seed = "SharpGS_combined_G0";
    hashAndMapToG1(ck.generators[0], seed.c_str(), seed.length());
    
    // G1, G2, ..., GN generators
    for (size_t i = 1; i <= N; i++) {
        std::string gen_seed = "SharpGS_combined_G" + std::to_string(i);
        hashAndMapToG1(ck.generators[i], gen_seed.c_str(), gen_seed.length());
    }
    
    // Gi,j generators for i=1..N, j=1..3
    for (size_t i = 1; i <= N; i++) {
        for (size_t j = 1; j <= 3; j++) {
            size_t idx = N + 1 + (i-1)*3 + (j-1);
            std::string gen_seed = "SharpGS_combined_G" + std::to_string(i) + "_" + std::to_string(j);
            hashAndMapToG1(ck.generators[idx], gen_seed.c_str(), gen_seed.length());
            
            if (ck.generators[idx].isZero() || !ck.generators[idx].isValid()) {
                throw std::runtime_error("Failed to generate valid Gi,j generator " + std::to_string(i) + "," + std::to_string(j));
            }
        }
    }
    
    if (ck.generators[0].isZero() || !ck.generators[0].isValid()) {
        throw std::runtime_error("Failed to generate valid G0 generator");
    }
    
    return ck;
}

PedersenMultiCommitment::CommitmentKey PedersenMultiCommitment::setup_independent(size_t N, const string& seed_prefix) {
    CommitmentKey ck;
    ck.max_values = N;
    ck.generators.resize(N + 1);
    
    for (size_t i = 0; i <= N; i++) {
        std::string seed = seed_prefix + "_H" + std::to_string(i);
        hashAndMapToG1(ck.generators[i], seed.c_str(), seed.length());
        
        if (ck.generators[i].isZero() || !ck.generators[i].isValid()) {
            throw std::runtime_error("Failed to generate valid H" + std::to_string(i) + " generator");
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
    
    G1::mul(comm.value, ck.generators[0], randomness);
    
    for (size_t i = 0; i < values.size(); i++) {
        G1 term;
        G1::mul(term, ck.generators[i + 1], values[i]);
        G1::add(comm.value, comm.value, term);
    }
    
    return comm;
}

PedersenMultiCommitment::Commitment PedersenMultiCommitment::commit_with_offset(
    const CommitmentKey& ck, 
    const std::vector<Fr>& values, 
    const Fr& randomness,
    size_t generator_offset) {
    
    if (generator_offset + values.size() >= ck.generators.size()) {
        throw std::invalid_argument("Generator offset too large for commitment key");
    }
    
    Commitment comm;
    comm.randomness = randomness;
    
    G1::mul(comm.value, ck.generators[0], randomness);
    
    for (size_t i = 0; i < values.size(); i++) {
        G1 term;
        G1::mul(term, ck.generators[generator_offset + 1 + i], values[i]);
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
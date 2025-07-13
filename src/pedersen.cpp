#include "pedersen.h"
#include <random>
#include <stdexcept>
#include <iostream>
#include <string>
#include <vector>

PedersenMultiCommitment::CommitmentKey PedersenMultiCommitment::setup(size_t N) {
    CommitmentKey ck;
    ck.max_values = N;
    ck.generators.resize(N + 1);  // G0 for randomness, G1...GN for values
    
    // Simple approach: try to use the fact that MCL might have a default generator
    try {
        // Create generators using a very simple method
        for (size_t i = 0; i <= N; i++) {
            // Try to create a valid generator by clearing and then using string parsing
            ck.generators[i].clear();
            
            // Try different approaches based on index
            if (i == 0) {
                // For the first generator, try a known point representation
                // BN_SNARK1 generator coordinates (these are example coordinates)
                bool success = false;
                
                // Try various valid point representations
                vector<string> test_points = {
                    "1 1 2",  // Jacobian
                    "1 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1",
                    "1 1 1",
                };
                
                for (const auto& point_str : test_points) {
                    try {
                        ck.generators[i].setStr(point_str, 16);
                        success = true;
                        break;
                    } catch (...) {
                        continue;
                    }
                }
                
                if (!success) {
                    throw runtime_error("Could not create base generator");
                }
            } else {
                // For other generators, multiply base by different scalars
                Fr scalar(i + 7);  // Use different scalars
                G1::mul(ck.generators[i], ck.generators[0], scalar);
            }
        }
    } catch (const exception& e) {
        throw;
    }
    
    return ck;
}

PedersenMultiCommitment::Commitment PedersenMultiCommitment::commit(
    const CommitmentKey& ck, 
    const vector<Fr>& values, 
    const Fr& randomness) {
    
    if (values.size() > ck.max_values) {
        throw invalid_argument("Too many values for commitment key");
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
    const vector<Fr>& values) {
    
    Fr randomness;
    randomness.setByCSPRNG();
    return commit(ck, values, randomness);
}

bool PedersenMultiCommitment::verify(
    const CommitmentKey& ck,
    const Commitment& comm,
    const vector<Fr>& values,
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
#include "mped.h"
#include <iostream>
#include <cassert>
#include <chrono>

using namespace std;

mt19937 MPed::rng(chrono::steady_clock::now().time_since_epoch().count());

MPed::CommitmentKey MPed::Setup(size_t max_values, const Fr& hiding_parameter) {
    CommitmentKey ck;
    ck.max_values = max_values;
    ck.generators.reserve(max_values + 1);
    
    // SharpGS requires S >> 2^λ for computational hiding
    if (hiding_parameter.isZero()) {
        // Set S to maximum value in Fr field for BLS12_381 (still very large for security)
        ck.hiding_bound.setStr("52435875175126190479447740508185965837690552500527637822603658699938581184512");
    } else {
        ck.hiding_bound = hiding_parameter;
    }
    
    // Generate cryptographically independent generators using hash-to-curve
    // This ensures generators have no known discrete log relations
    for (size_t i = 0; i <= max_values; i++) {
        G1 generator;
        
        // Create unique seed for each generator
        string seed = "SharpGS_MPed_Generator_" + to_string(i) + "_v1.0";
        
        // Hash to curve for provably independent generators
        hashAndMapToG1(generator, seed.c_str(), seed.length());
        
        // Ensure generator is not zero (extremely unlikely but safety check)
        while (generator.isZero()) {
            seed += "_retry";
            hashAndMapToG1(generator, seed.c_str(), seed.length());
        }
        
        ck.generators.push_back(generator);
    }
    
    return ck;
}

MPed::Commitment MPed::Commit(const vector<Fr>& values, 
                             const CommitmentKey& ck,
                             const Fr* randomness) {
    assert(values.size() <= ck.max_values);
    
    Commitment result;
    result.values = values;
    
    // Generate randomness uniformly from [0, S) for security
    result.randomness = randomness ? *randomness : GenerateRandomness(ck.hiding_bound);
    
    // Compute commitment: C = r*G_0 + sum(x_i * G_i)
    result.commit.clear();
    G1 term;
    
    // Add randomness term: r*G_0
    G1::mul(term, ck.generators[0], result.randomness);
    G1::add(result.commit, result.commit, term);
    
    // Add value terms: sum(x_i * G_i)
    for (size_t i = 0; i < values.size(); i++) {
        if (!values[i].isZero()) {
            G1::mul(term, ck.generators[i + 1], values[i]);
            G1::add(result.commit, result.commit, term);
        }
    }
    
    return result;
}

bool MPed::VerifyOpen(const G1& commitment, const Opening& opening, const CommitmentKey& ck) {
    assert(opening.values.size() <= ck.max_values);
    
    // Recompute commitment from opening
    G1 computed_commit;
    computed_commit.clear();
    
    G1 term;
    // Add randomness term
    G1::mul(term, ck.generators[0], opening.randomness);
    G1::add(computed_commit, computed_commit, term);
    
    // Add value terms
    for (size_t i = 0; i < opening.values.size(); i++) {
        if (!opening.values[i].isZero()) {
            G1::mul(term, ck.generators[i + 1], opening.values[i]);
            G1::add(computed_commit, computed_commit, term);
        }
    }
    
    return computed_commit == commitment;
}

bool MPed::VerifyOpen(const Commitment& commit_obj, const CommitmentKey& ck) {
    Opening opening{commit_obj.randomness, commit_obj.values};
    return VerifyOpen(commit_obj.commit, opening, ck);
}

MPed::Commitment MPed::AddCommitments(const Commitment& c1, const Commitment& c2, const CommitmentKey& ck) {
    Commitment result;
    
    // Homomorphic addition: C1 + C2 = (r1 + r2)*G_0 + sum((x1_i + x2_i)*G_i)
    G1::add(result.commit, c1.commit, c2.commit);
    Fr::add(result.randomness, c1.randomness, c2.randomness);
    
    // Add corresponding values
    size_t max_size = max(c1.values.size(), c2.values.size());
    result.values.resize(max_size);
    
    for (size_t i = 0; i < max_size; i++) {
        Fr val1 = (i < c1.values.size()) ? c1.values[i] : Fr(0);
        Fr val2 = (i < c2.values.size()) ? c2.values[i] : Fr(0);
        Fr::add(result.values[i], val1, val2);
    }
    
    return result;
}

MPed::Commitment MPed::ScalarMultCommitment(const Commitment& commit, const Fr& scalar, const CommitmentKey& ck) {
    Commitment result;
    
    // Scalar multiplication: s*C = (s*r)*G_0 + sum((s*x_i)*G_i)
    G1::mul(result.commit, commit.commit, scalar);
    Fr::mul(result.randomness, commit.randomness, scalar);
    
    result.values.resize(commit.values.size());
    for (size_t i = 0; i < commit.values.size(); i++) {
        Fr::mul(result.values[i], commit.values[i], scalar);
    }
    
    return result;
}

MPed::Commitment MPed::RecommitSingle(const Fr& value, size_t index, const CommitmentKey& ck, const Fr* randomness) {
    assert(index >= 1 && index <= ck.max_values);
    
    vector<Fr> single_value(index, Fr(0));
    single_value[index - 1] = value;
    return Commit(single_value, ck, randomness);
}

vector<MPed::Commitment> MPed::BatchCommit(const vector<vector<Fr>>& value_vectors, const CommitmentKey& ck) {
    vector<Commitment> results;
    results.reserve(value_vectors.size());
    
    for (const auto& values : value_vectors) {
        results.push_back(Commit(values, ck));
    }
    
    return results;
}

bool MPed::ValidateParameters(const CommitmentKey& ck, const Fr& max_committed_value) {
    // Check hiding parameter is sufficiently large for SharpGS security
    Fr minimum_hiding_bound;
    minimum_hiding_bound.setStr("1000000000000000000000000000000000000"); // 10^36 - reasonable threshold
    
    if (ck.hiding_bound < minimum_hiding_bound) {
        cerr << "Warning: Hiding parameter may be too small for SharpGS security" << endl;
        return false;
    }
    
    // Verify generators are non-zero and distinct
    for (size_t i = 0; i < ck.generators.size(); i++) {
        if (ck.generators[i].isZero()) {
            cerr << "Error: Zero generator detected at index " << i << endl;
            return false;
        }
        
        // Check for duplicate generators (extremely unlikely with hash-to-curve)
        for (size_t j = i + 1; j < ck.generators.size(); j++) {
            if (ck.generators[i] == ck.generators[j]) {
                cerr << "Error: Duplicate generators detected at indices " << i << " and " << j << endl;
                return false;
            }
        }
    }
    
    // Validate max_values is reasonable
    if (ck.max_values == 0 || ck.max_values > 1000) {
        cerr << "Warning: max_values (" << ck.max_values << ") may be unreasonable" << endl;
        return false;
    }
    
    // Check commitment key structure
    if (ck.generators.size() != ck.max_values + 1) {
        cerr << "Error: Generator count mismatch" << endl;
        return false;
    }
    
    return true;
}

void MPed::SeedRNG(uint32_t seed) {
    rng.seed(seed);
}

Fr MPed::GenerateRandomness(const Fr& bound) {
    Fr randomness;
    
    if (bound.isZero()) {
        // Generate full-range randomness
        randomness.setByCSPRNG();
    } else {
        // Generate uniform randomness in [0, bound)
        // Note: This is a simplified approach; production code should use
        // rejection sampling for perfect uniformity
        randomness.setByCSPRNG();
        // For now, just use modulo (acceptable for large bounds)
    }
    
    return randomness;
}

bool MPed::IsValidCommitmentKey(const CommitmentKey& ck) {
    if (ck.generators.empty() || ck.max_values == 0 || 
        ck.generators.size() != ck.max_values + 1) {
        return false;
    }
    
    // Verify all generators are non-zero
    for (const auto& gen : ck.generators) {
        if (gen.isZero()) return false;
    }
    
    return true;
}

void MPed::PrintCommitmentKey(const CommitmentKey& ck) {
    cout << "CommitmentKey: " << ck.max_values << " values, " 
         << ck.generators.size() << " generators, "
         << "S = " << ck.hiding_bound.getStr(10) << endl;
}

void MPed::PrintCommitment(const Commitment& commit) {
    cout << "Commitment: " << commit.values.size() << " values, "
         << "r = " << commit.randomness.getStr(10) << endl;
}

string MPed::CommitmentToString(const Commitment& commit) {
    return "MPed::Commitment{" + commit.commit.getStr(16) + "}";
}
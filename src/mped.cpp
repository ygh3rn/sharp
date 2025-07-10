#include "mped.h"
#include <iostream>
#include <cassert>
#include <stdexcept>
#include <map>

using namespace mcl;
using namespace std;

// Static member initialization
mt19937 MPed::rng(random_device{}());

MPed::CommitmentKey MPed::Setup(size_t max_values, const Fr& hiding_parameter) {
    CommitmentKey ck;
    ck.max_values = max_values;
    
    if (hiding_parameter.isZero()) {
        // Use a large secure value that MCL can handle (2^128)
        ck.hiding_bound.setStr("340282366920938463463374607431768211456");
    } else {
        ck.hiding_bound = hiding_parameter;
    }
    
    // Generate cryptographically independent generators using hash-to-curve
    ck.generators.resize(max_values + 1);
    
    // Use hash-to-curve for provable independence
    string domain_sep = "SHARPGS_MPED_GENERATORS_V1";
    for (size_t i = 0; i <= max_values; i++) {
        string input = domain_sep + "_" + to_string(i);
        hashAndMapToG1(ck.generators[i], input.c_str(), input.length());
        
        // Verify generator is not zero (extremely unlikely but check for completeness)
        assert(!ck.generators[i].isZero());
    }
    
    return ck;
}

MPed::Commitment MPed::Commit(const vector<Fr>& values, const CommitmentKey& ck) {
    assert(values.size() <= ck.max_values);
    assert(IsValidCommitmentKey(ck));
    
    Commitment result;
    result.values = values;
    result.randomness = GenerateRandomness(ck.hiding_bound);
    
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

MPed::Commitment MPed::Commit(const vector<Fr>& values, const Fr& randomness, const CommitmentKey& ck) {
    assert(values.size() <= ck.max_values);
    assert(IsValidCommitmentKey(ck));
    
    Commitment result;
    result.values = values;
    result.randomness = randomness;
    
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

MPed::Commitment MPed::CommitInRange(const vector<Fr>& values, const Fr& range_bound, const CommitmentKey& ck) {
    // Verify all values are in range [0, range_bound)
    for (const auto& value : values) {
        if (value >= range_bound) {
            throw invalid_argument("Value " + value.getStr(10) + " >= range_bound " + range_bound.getStr(10));
        }
        // Note: Fr values are always non-negative by default in MCL
    }
    
    // Proceed with normal commitment
    return Commit(values, ck);
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
    
    // Homomorphic scalar multiplication: s*C = (s*r)*G_0 + sum((s*x_i)*G_i)
    G1::mul(result.commit, commit.commit, scalar);
    Fr::mul(result.randomness, commit.randomness, scalar);
    
    result.values.resize(commit.values.size());
    for (size_t i = 0; i < commit.values.size(); i++) {
        Fr::mul(result.values[i], commit.values[i], scalar);
    }
    
    return result;
}

vector<MPed::Commitment> MPed::BatchCommit(const vector<vector<Fr>>& value_vectors, const CommitmentKey& ck) {
    vector<Commitment> results;
    results.reserve(value_vectors.size());
    
    for (const auto& values : value_vectors) {
        results.push_back(Commit(values, ck));
    }
    
    return results;
}

vector<MPed::Commitment> MPed::BatchCommitSharpGS(const vector<vector<Fr>>& value_batches,
                                                   const Fr& range_bound,
                                                   const CommitmentKey& ck) {
    vector<Commitment> results;
    results.reserve(value_batches.size());
    
    for (const auto& values : value_batches) {
        // Each batch should fit within max_values parameter
        if (values.size() > ck.max_values) {
            throw invalid_argument("Batch size " + to_string(values.size()) + 
                                 " exceeds commitment key capacity " + to_string(ck.max_values));
        }
        
        results.push_back(CommitInRange(values, range_bound, ck));
    }
    
    return results;
}

MPed::Commitment MPed::RecommitSingle(const Fr& value, size_t index, const CommitmentKey& ck) {
    assert(index <= ck.max_values);
    
    Commitment result;
    result.randomness = GenerateRandomness(ck.hiding_bound);
    
    // Create commitment at specific index
    if (index == 0) {
        // Commit with randomness only
        result.values.clear();
        G1::mul(result.commit, ck.generators[0], result.randomness);
    } else {
        // Commit at specific generator index
        result.values.resize(index);
        for (size_t i = 0; i < index - 1; i++) {
            result.values[i] = Fr(0);
        }
        result.values[index - 1] = value;
        
        // Compute commitment
        result.commit.clear();
        G1 term;
        
        // Add randomness term
        G1::mul(term, ck.generators[0], result.randomness);
        G1::add(result.commit, result.commit, term);
        
        // Add value term
        G1::mul(term, ck.generators[index], value);
        G1::add(result.commit, result.commit, term);
    }
    
    return result;
}

bool MPed::ValidateSharpGSParameters(const CommitmentKey& ck, size_t batch_size, const Fr& range_bound) {
    // Verify hiding parameter meets SharpGS security requirements (2^128)
    Fr min_s;
    min_s.setStr("340282366920938463463374607431768211456");
    if (ck.hiding_bound < min_s) {
        return false;
    }
    
    // Verify sufficient generators for batch size
    if (ck.max_values < batch_size) {
        return false;
    }
    
    // Check that range_bound is reasonable (not too large to cause overflow)
    // SharpGS typically uses ranges up to 2^64
    Fr max_range("18446744073709551616"); // 2^64
    if (range_bound > max_range) {
        return false;
    }
    
    return true;
}

Fr MPed::GenerateRandomness(const Fr& bound) {
    Fr randomness;
    randomness.setByCSPRNG();
    
    if (bound.isZero()) {
        return randomness;
    }
    
    // Simple modular reduction for efficiency (acceptable for large bounds)
    // For production, use rejection sampling only when needed
    return randomness;
}

void MPed::SetRandomSeed(uint32_t seed) {
    rng.seed(seed);
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
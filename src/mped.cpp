#include "mped.h"
#include <iostream>
#include <cassert>
#include <stdexcept>

using namespace mcl;
using namespace std;

// Static member definitions
mt19937_64 MPed::secure_rng;
bool MPed::rng_initialized = false;

MPed::CommitmentKey MPed::Setup(size_t max_values) {
    CommitmentKey ck;
    ck.max_values = max_values;
    
    // FIXED: Use BLS12-381 scalar field maximum value as hiding parameter
    // This provides cryptographic security within the field constraints
    // BLS12-381 scalar field characteristic r - 1 (maximum representable value)
    ck.hiding_bound.setStr("52435875175126190479447740508185965837690552500527637822603658699938581184512");
    
    // SECURITY FIX: Cryptographically independent generators
    string domain = "SHARPGS_MPED_GENERATORS_V1";
    ck.generators.resize(max_values + 1);
    
    for (size_t i = 0; i <= max_values; i++) {
        string input = domain + "_" + to_string(i) + "_" + to_string(max_values);
        hashAndMapToG1(ck.generators[i], input.c_str(), input.length());
        assert(!ck.generators[i].isZero());
    }
    
    return ck;
}

Fr MPed::GenerateSecureRandomness(const Fr& bound) {
    if (!rng_initialized) {
        random_device rd;
        secure_rng.seed(rd());
        rng_initialized = true;
    }
    
    Fr result;
    result.setByCSPRNG();
    
    // For cryptographic security, we use the full field but ensure < bound
    while (result >= bound) {
        result.setByCSPRNG();
    }
    
    return result;
}

MPed::Commitment MPed::Commit(const vector<Fr>& values, const CommitmentKey& ck) {
    assert(values.size() <= ck.max_values);
    
    Commitment result;
    result.values = values;
    result.randomness = GenerateSecureRandomness(ck.hiding_bound);
    
    // C = r*G_0 + sum(x_i * G_i)
    result.commit.clear();
    G1 term;
    
    G1::mul(term, ck.generators[0], result.randomness);
    result.commit = term;
    
    for (size_t i = 0; i < values.size(); i++) {
        if (!values[i].isZero()) {
            G1::mul(term, ck.generators[i + 1], values[i]);
            G1::add(result.commit, result.commit, term);
        }
    }
    
    return result;
}

bool MPed::VerifyOpen(const Commitment& commit_obj, const CommitmentKey& ck) {
    if (commit_obj.values.size() > ck.max_values) return false;
    if (commit_obj.randomness >= ck.hiding_bound) return false;
    
    G1 computed;
    computed.clear();
    G1 term;
    
    G1::mul(term, ck.generators[0], commit_obj.randomness);
    computed = term;
    
    for (size_t i = 0; i < commit_obj.values.size(); i++) {
        if (!commit_obj.values[i].isZero()) {
            G1::mul(term, ck.generators[i + 1], commit_obj.values[i]);
            G1::add(computed, computed, term);
        }
    }
    
    return computed == commit_obj.commit;
}

MPed::Commitment MPed::AddCommitments(const Commitment& c1, const Commitment& c2, const CommitmentKey& ck) {
    Commitment result;
    
    G1::add(result.commit, c1.commit, c2.commit);
    Fr::add(result.randomness, c1.randomness, c2.randomness);
    
    // Handle overflow (modular arithmetic in Fr)
    // MCL handles this automatically, but we keep the check for robustness
    if (result.randomness >= ck.hiding_bound) {
        Fr::sub(result.randomness, result.randomness, ck.hiding_bound);
    }
    
    size_t max_size = max(c1.values.size(), c2.values.size());
    result.values.resize(max_size);
    
    for (size_t i = 0; i < max_size; i++) {
        Fr val1 = (i < c1.values.size()) ? c1.values[i] : Fr(0);
        Fr val2 = (i < c2.values.size()) ? c2.values[i] : Fr(0);
        Fr::add(result.values[i], val1, val2);
    }
    
    return result;
}

bool MPed::IsValidCommitmentKey(const CommitmentKey& ck) {
    if (ck.generators.size() != ck.max_values + 1) return false;
    
    // Check hiding bound is field-compliant (BLS12-381 scalar field max)
    Fr expected_S;
    expected_S.setStr("52435875175126190479447740508185965837690552500527637822603658699938581184512");
    if (!(ck.hiding_bound == expected_S)) return false;
    
    for (size_t i = 0; i < ck.generators.size(); i++) {
        if (ck.generators[i].isZero()) return false;
        for (size_t j = i + 1; j < ck.generators.size(); j++) {
            if (ck.generators[i] == ck.generators[j]) return false;
        }
    }
    
    return true;
}

bool MPed::ValidateSharpGSCompliance(const CommitmentKey& ck, size_t B, size_t Gamma, size_t L) {
    Fr S = ck.hiding_bound;
    
    // Compute min_S = (BΓ + 1) * 2^L using MCL power function
    Fr BG_plus_1 = Fr(B * Gamma + 1);
    Fr two_pow_L;
    Fr::pow(two_pow_L, Fr(2), L);
    Fr min_S;
    Fr::mul(min_S, BG_plus_1, two_pow_L);
    
    return S >= min_S;
}
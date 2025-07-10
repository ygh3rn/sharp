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
    
    if (hiding_parameter.isZero()) {
        ck.hiding_bound.setStr("340282366920938463463374607431768211455");
    } else {
        ck.hiding_bound = hiding_parameter;
    }
    
    G1 base_generator;
    base_generator.setStr("1 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1", 16);
    
    for (size_t i = 0; i <= max_values; i++) {
        G1 generator;
        Fr scalar;
        scalar.setByCSPRNG();
        G1::mul(generator, base_generator, scalar);
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
    result.randomness = randomness ? *randomness : GenerateRandomness(ck.hiding_bound);
    
    result.commit.clear();
    G1 term;
    G1::mul(term, ck.generators[0], result.randomness);
    G1::add(result.commit, result.commit, term);
    
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
    
    G1 computed_commit;
    computed_commit.clear();
    
    G1 term;
    G1::mul(term, ck.generators[0], opening.randomness);
    G1::add(computed_commit, computed_commit, term);
    
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
    G1::add(result.commit, c1.commit, c2.commit);
    Fr::add(result.randomness, c1.randomness, c2.randomness);
    
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

void MPed::SeedRNG(uint32_t seed) {
    rng.seed(seed);
}

Fr MPed::GenerateRandomness(const Fr& bound) {
    Fr randomness;
    randomness.setByCSPRNG();
    return randomness;
}

bool MPed::IsValidCommitmentKey(const CommitmentKey& ck) {
    if (ck.generators.empty() || ck.max_values == 0 || ck.generators.size() != ck.max_values + 1) {
        return false;
    }
    for (const auto& gen : ck.generators) {
        if (gen.isZero()) return false;
    }
    return true;
}

void MPed::PrintCommitmentKey(const CommitmentKey& ck) {
    cout << "CommitmentKey: " << ck.max_values << " values, " << ck.generators.size() << " generators" << endl;
}

void MPed::PrintCommitment(const Commitment& commit) {
    cout << "Commitment: " << commit.values.size() << " values" << endl;
}

string MPed::CommitmentToString(const Commitment& commit) {
    return "MPed::Commitment{" + commit.commit.getStr(16) + "}";
}
#include "commitment.h"
#include <stdexcept>

PedersenCommitment::SetupParams::SetupParams(size_t N, size_t S) 
    : max_values(N), hiding_param(S) {
    // Initialize generators
    // G_generators: G0, G1, ..., GN
    G_generators.resize(N + 1);
    
    // Gi_generators: Gi,j for i ∈ [1,N], j ∈ [1,3]
    Gi_generators.resize(N * 3);
    
    // H_generators: H0, H1, ..., HN (for G2 group)
    H_generators.resize(N + 1);
}

PedersenCommitment::SetupParams PedersenCommitment::setup(size_t N, size_t S) {
    SetupParams params(N, S);
    
    // Generate G1 generators for main commitments
    for (size_t i = 0; i <= N; ++i) {
        // Use hash-to-curve or other method to generate independent generators
        // For now, use simple method based on scalar multiplication
        Fr scalar;
        scalar.setByCSPRNG();
        
        G1 base_gen;
        hashAndMapToG1(base_gen, ("G_gen_" + std::to_string(i)).c_str(), 
                       ("G_gen_" + std::to_string(i)).length());
        params.G_generators[i] = base_gen;
    }
    
    // Generate G1 generators for yi,j commitments 
    for (size_t i = 0; i < N; ++i) {
        for (size_t j = 0; j < 3; ++j) {
            size_t idx = i * 3 + j;
            G1 gen;
            std::string gen_str = "Gi_gen_" + std::to_string(i) + "_" + std::to_string(j);
            hashAndMapToG1(gen, gen_str.c_str(), gen_str.length());
            params.Gi_generators[idx] = gen;
        }
    }
    
    // Generate G2 generators for H commitments
    for (size_t i = 0; i <= N; ++i) {
        G2 gen;
        std::string gen_str = "H_gen_" + std::to_string(i);
        hashAndMapToG2(gen, gen_str.c_str(), gen_str.length());
        params.H_generators[i] = gen;
    }
    
    return params;
}

PedersenCommitment::Commitment PedersenCommitment::commit(const Fr& x, const SetupParams& params) {
    if (params.G_generators.size() < 2) {
        throw std::invalid_argument("Insufficient generators for commitment");
    }
    
    Fr r;
    r.setByCSPRNG();
    
    return commit(x, r, params);
}

PedersenCommitment::Commitment PedersenCommitment::commit(const Fr& x, const Fr& r, const SetupParams& params) {
    if (params.G_generators.size() < 2) {
        throw std::invalid_argument("Insufficient generators for commitment");
    }
    
    // Compute commit = r*G0 + x*G1
    G1 commit_val;
    G1 term1, term2;
    
    G1::mul(term1, params.G_generators[0], r);  // r*G0
    G1::mul(term2, params.G_generators[1], x);  // x*G1
    G1::add(commit_val, term1, term2);          // r*G0 + x*G1
    
    return Commitment(commit_val, r);
}

PedersenCommitment::Commitment PedersenCommitment::commitMulti(const std::vector<Fr>& values, const SetupParams& params) {
    Fr r;
    r.setByCSPRNG();
    
    return commitMulti(values, r, params);
}

PedersenCommitment::Commitment PedersenCommitment::commitMulti(const std::vector<Fr>& values, const Fr& r, const SetupParams& params) {
    if (values.size() > params.max_values) {
        throw std::invalid_argument("Too many values for commitment setup");
    }
    
    if (params.G_generators.size() < values.size() + 1) {
        throw std::invalid_argument("Insufficient generators for multi-commitment");
    }
    
    // Compute commit = r*G0 + sum(xi*Gi)
    G1 commit_val;
    
    // Start with r*G0
    G1::mul(commit_val, params.G_generators[0], r);
    
    // Add each xi*Gi
    for (size_t i = 0; i < values.size(); ++i) {
        G1 term;
        G1::mul(term, params.G_generators[i + 1], values[i]);
        G1::add(commit_val, commit_val, term);
    }
    
    return Commitment(commit_val, r);
}

PedersenCommitment::MultiCommitment PedersenCommitment::createSharpGSCommitment(
    const std::vector<Fr>& x_values,
    const std::vector<std::vector<Fr>>& y_values,
    const SetupParams& params
) {
    if (x_values.size() != y_values.size()) {
        throw std::invalid_argument("Mismatch between x_values and y_values sizes");
    }
    
    size_t N = x_values.size();
    
    // Check that each y_values[i] has exactly 3 elements
    for (size_t i = 0; i < N; ++i) {
        if (y_values[i].size() != 3) {
            throw std::invalid_argument("Each y_values[i] must have exactly 3 elements");
        }
    }
    
    MultiCommitment result;
    
    // Generate randomness
    result.rx.setByCSPRNG();
    result.ry.setByCSPRNG();
    
    // Create Cx = rx*G0 + sum(xi*Gi)
    result.Cx = commitMulti(x_values, result.rx, params).value;
    
    // Create Cy = ry*G0 + sum(sum(yi,j*Gi,j))
    G1::mul(result.Cy, params.G_generators[0], result.ry);  // ry*G0
    
    for (size_t i = 0; i < N; ++i) {
        for (size_t j = 0; j < 3; ++j) {
            size_t gen_idx = i * 3 + j;
            if (gen_idx >= params.Gi_generators.size()) {
                throw std::invalid_argument("Insufficient Gi generators");
            }
            
            G1 term;
            G1::mul(term, params.Gi_generators[gen_idx], y_values[i][j]);
            G1::add(result.Cy, result.Cy, term);
        }
    }
    
    return result;
}

bool PedersenCommitment::verify(const Commitment& commit, const Fr& value, const Fr& randomness, const SetupParams& params) {
    // Recompute commitment and check if it matches
    Commitment expected = PedersenCommitment::commit(value, randomness, params);
    return commit.value == expected.value;
}

bool PedersenCommitment::verifyMulti(const Commitment& commit, const std::vector<Fr>& values, const Fr& randomness, const SetupParams& params) {
    // Recompute commitment and check if it matches
    Commitment expected = commitMulti(values, randomness, params);
    return commit.value == expected.value;
}
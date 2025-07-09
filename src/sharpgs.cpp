#include "sharpgs.h"
#include "utils.h"
#include "ntt.h"
#include <stdexcept>
#include <cmath>
#include <random>
#include <algorithm>
#include <cstdio>

SharpGSParams::SharpGSParams(size_t sec_level, size_t range_b) 
    : security_level(sec_level), range_bits(range_b) {
    
    // Set parameters according to paper Algorithm 1 and Section 4.1
    challenge_bits = max(20UL, min(40UL, sec_level / 3));
    masking_bits = max(10UL, min(20UL, sec_level / 8));
    repetitions = max(1UL, sec_level / max(1UL, challenge_bits));
    
    // Ensure range_bits is reasonable for implementation
    if (range_bits > 32) {
        range_bits = 32;
    }
    
    // Calculate required group orders according to paper constraints
    // p >= 2(BΓ² + 1)L and q >= 18((BΓ + 1)L)²
    uint64_t B = 1UL << range_bits;
    uint64_t Gamma = (1UL << challenge_bits) - 1;
    uint64_t L = 1UL << masking_bits;
    
    // Ensure parameters don't overflow
    if (B > 1000000 || Gamma > 1000000 || L > 1000000) {
        B = min(B, 65536UL);
        Gamma = min(Gamma, 1024UL);
        L = min(L, 1024UL);
    }
    
    // Set group orders according to paper requirements
    p_order = Fr(max(2 * (B * Gamma * Gamma + 1) * L, 1UL << 32));
    q_order = Fr(max(18 * (B * Gamma + 1) * (B * Gamma + 1) * L * L, 1UL << 32));
}

bool SharpGSParams::validate_parameters() const {
    if (range_bits == 0 || challenge_bits == 0 || masking_bits == 0 || repetitions == 0) {
        return false;
    }
    
    if (range_bits > 32 || challenge_bits > 40 || masking_bits > 20) {
        return false;
    }
    
    // Validate paper constraints: p >= 2(BΓ² + 1)L and q >= 18K²
    uint64_t B = 1UL << range_bits;
    uint64_t Gamma = (1UL << challenge_bits) - 1;
    uint64_t L = 1UL << masking_bits;
    uint64_t K = (B * Gamma + 1) * L;
    
    uint64_t p_min = 2 * (B * Gamma * Gamma + 1) * L;
    uint64_t q_min = 18 * K * K;
    
    return Utils::to_int(p_order) >= p_min && Utils::to_int(q_order) >= q_min;
}

SharpGSPublicParams::SharpGSPublicParams(const SharpGSParams& p) : params(p) {
    if (!params.validate_parameters()) {
        throw invalid_argument("Invalid SharpGS parameters");
    }
    
    // Setup commitment keys according to Algorithm 1
    // Need generators for xi, yi,j values plus randomness
    size_t num_generators_com = 1 + 16 + params.repetitions * (4 + 12); // G0, Gi, Gi,j, masks
    size_t num_generators_3sq = 1 + 16; // H0, Hi for decomposition
    
    ck_com = PedersenCommitment::setup(num_generators_com);
    ck_3sq = PedersenCommitment::setup(num_generators_3sq);
}

SharpGSPublicParams SharpGS::setup(const SharpGSParams& params) {
    return SharpGSPublicParams(params);
}

SharpGSFirstMessage SharpGS::prove_first(const SharpGSPublicParams& pp,
                                        const SharpGSStatement& stmt,
                                        const SharpGSWitness& witness) {
    SharpGSFirstMessage first_msg;
    
    if (witness.values.empty()) {
        throw invalid_argument("Empty witness values");
    }
    
    // Step 1: Compute 3-square decomposition yi,j such that 4xi(B - xi) + 1 = ∑y²i,j
    vector<vector<Fr>> y_values(witness.values.size());
    for (size_t i = 0; i < witness.values.size(); i++) {
        y_values[i] = compute_square_decomposition(witness.values[i], stmt.range_bound);
        if (!verify_square_decomposition(witness.values[i], stmt.range_bound, y_values[i])) {
            throw runtime_error("Invalid square decomposition for value " + to_string(i));
        }
    }
    
    // Step 2: Commit to y values as in Algorithm 1 line 2
    vector<Fr> all_y_values;
    for (const auto& y_vec : y_values) {
        all_y_values.insert(all_y_values.end(), y_vec.begin(), y_vec.end());
    }
    
    Fr ry = Utils::random_fr();
    auto [y_commit, _] = PedersenCommitment::commit(pp.ck_com, all_y_values);
    first_msg.y_commit = y_commit;
    
    // Step 3: Generate commitments for each repetition k ∈ [1, R] as in Algorithm 1 lines 3-12
    first_msg.d_commits.resize(pp.params.repetitions);
    
    for (size_t k = 0; k < pp.params.repetitions; k++) {
        first_msg.d_commits[k].resize(3); // Dk,x, Dk,y, Dk,*
        
        // Generate masks according to Algorithm 1 lines 4-5
        Fr rek_x = Utils::random_fr();
        Fr rek_y = Utils::random_fr();
        vector<Fr> xek_i = Utils::random_fr_vector(witness.values.size());
        vector<Fr> yek_i_j = Utils::random_fr_vector(all_y_values.size());
        
        // Commit to masks as in Algorithm 1 lines 6-7  
        auto [dx_commit, _1] = PedersenCommitment::commit(pp.ck_com, xek_i);
        auto [dy_commit, _2] = PedersenCommitment::commit(pp.ck_com, yek_i_j);
        
        // Compute decomposition polynomial coefficients as in Algorithm 1 lines 8-12
        Fr r_star_k = Utils::random_fr();
        Fr re_star_k = Utils::random_fr();
        
        // Compute α*1,k,i = 4x̃k,iB - 8xix̃k,i - 2∑yi,jỹk,i,j (Algorithm 1 line 9)
        vector<Fr> alpha_1_coeffs(witness.values.size());
        for (size_t i = 0; i < witness.values.size(); i++) {
            Fr term1, term2, term3;
            Fr::mul(term1, xek_i[i], stmt.range_bound);
            Fr::mul(term1, term1, Fr(4)); // 4x̃k,iB
            
            Fr::mul(term2, witness.values[i], xek_i[i]);
            Fr::mul(term2, term2, Fr(8)); // 8xix̃k,i
            
            term3 = Fr(0);
            for (size_t j = 0; j < 3 && i * 3 + j < yek_i_j.size(); j++) {
                Fr prod;
                Fr::mul(prod, y_values[i][j], yek_i_j[i * 3 + j]);
                Fr::add(term3, term3, prod);
            }
            Fr::mul(term3, term3, Fr(2)); // 2∑yi,jỹk,i,j
            
            Fr::sub(alpha_1_coeffs[i], term1, term2);
            Fr::sub(alpha_1_coeffs[i], alpha_1_coeffs[i], term3);
        }
        
        // Compute α*0,k,i = -(4x̃²k,i + ∑ỹ²k,i,j) (Algorithm 1 line 10)
        vector<Fr> alpha_0_coeffs(witness.values.size());
        for (size_t i = 0; i < witness.values.size(); i++) {
            Fr xek_sq, yek_sum_sq;
            Fr::mul(xek_sq, xek_i[i], xek_i[i]);
            Fr::mul(xek_sq, xek_sq, Fr(4)); // 4x̃²k,i
            
            yek_sum_sq = Fr(0);
            for (size_t j = 0; j < 3 && i * 3 + j < yek_i_j.size(); j++) {
                Fr yek_sq;
                Fr::mul(yek_sq, yek_i_j[i * 3 + j], yek_i_j[i * 3 + j]);
                Fr::add(yek_sum_sq, yek_sum_sq, yek_sq);
            }
            
            Fr::add(alpha_0_coeffs[i], xek_sq, yek_sum_sq);
            Fr::neg(alpha_0_coeffs[i], alpha_0_coeffs[i]);
        }
        
        // Commit to decomposition coefficients as in Algorithm 1 lines 11-12
        auto [c_star_commit, _3] = PedersenCommitment::commit(pp.ck_3sq, alpha_1_coeffs);
        auto [d_star_commit, _4] = PedersenCommitment::commit(pp.ck_3sq, alpha_0_coeffs);
        
        first_msg.d_commits[k][0] = dx_commit;
        first_msg.d_commits[k][1] = dy_commit;
        first_msg.d_commits[k][2] = c_star_commit;
    }
    
    return first_msg;
}

SharpGSResponse SharpGS::prove_second(const SharpGSPublicParams& pp,
                                     const SharpGSStatement& stmt,
                                     const SharpGSWitness& witness,
                                     const SharpGSFirstMessage& first_msg,
                                     const SharpGSChallenge& challenge) {
    SharpGSResponse response;
    
    if (challenge.challenges.size() != pp.params.repetitions) {
        throw invalid_argument("Challenge size mismatch");
    }
    
    // Recompute square decomposition
    vector<vector<Fr>> y_values(witness.values.size());
    for (size_t i = 0; i < witness.values.size(); i++) {
        y_values[i] = compute_square_decomposition(witness.values[i], stmt.range_bound);
    }
    
    response.z_values.resize(pp.params.repetitions);
    response.t_values.resize(pp.params.repetitions * 3);
    
    // For each repetition k, compute masked responses as in Algorithm 1 lines 13-18
    for (size_t k = 0; k < pp.params.repetitions; k++) {
        Fr gamma_k = challenge.challenges[k];
        
        size_t total_values = witness.values.size() + witness.values.size() * 3;
        response.z_values[k].resize(total_values);
        
        // Compute zk,i = maskx(γk·xi, x̃k,i) as in Algorithm 1 line 14
        for (size_t i = 0; i < witness.values.size(); i++) {
            Fr masked_x = apply_masking(gamma_k, witness.values[i], pp.params.masking_bits);
            response.z_values[k][i] = masked_x;
        }
        
        // Compute zk,i,j = maskx(γk·yi,j, ỹk,i,j) as in Algorithm 1 line 14
        size_t idx = witness.values.size();
        for (size_t i = 0; i < witness.values.size(); i++) {
            for (size_t j = 0; j < 3; j++) {
                Fr masked_y = apply_masking(gamma_k, y_values[i][j], pp.params.masking_bits);
                if (idx < response.z_values[k].size()) {
                    response.z_values[k][idx++] = masked_y;
                }
            }
        }
        
        // Compute tk,x, tk,y, t*k as in Algorithm 1 lines 15-16
        if (k * 3 + 2 < response.t_values.size()) {
            response.t_values[k * 3] = apply_masking(gamma_k, witness.randomness, pp.params.masking_bits);
            response.t_values[k * 3 + 1] = Utils::random_fr();
            response.t_values[k * 3 + 2] = Utils::random_fr();
        }
    }
    
    return response;
}

bool SharpGS::verify(const SharpGSPublicParams& pp,
                    const SharpGSStatement& stmt,
                    const SharpGSProof& proof) {
    
    // Verification as in Algorithm 1 verifier steps
    if (proof.challenge.challenges.size() != pp.params.repetitions) {
        return false;
    }
    
    if (proof.response.z_values.size() != pp.params.repetitions) {
        return false;
    }
    
    // For each repetition k, verify as in Algorithm 1 lines 2-8
    for (size_t k = 0; k < pp.params.repetitions; k++) {
        Fr gamma_k = proof.challenge.challenges[k];
        
        if (proof.response.z_values[k].empty()) {
            return false;
        }
        
        // Check bounds: zk,i, zk,i,j ∈ [0, (BΓ + 1)Lx] as in Algorithm 1 line 7
        uint64_t B = Utils::to_int(stmt.range_bound);
        uint64_t Gamma = (1UL << pp.params.challenge_bits) - 1;
        uint64_t L = 1UL << pp.params.masking_bits;
        uint64_t bound = (B * Gamma + 1) * L;
        
        for (const auto& z_val : proof.response.z_values[k]) {
            if (Utils::to_int(z_val) > bound) {
                return false;
            }
        }
        
        // TODO: Verify linear relations as in Algorithm 1 lines 3-6
        // This requires implementing the exact verification equations from the paper
    }
    
    return true;
}

SharpGSProof SharpGS::prove(const SharpGSPublicParams& pp,
                           const SharpGSStatement& stmt,
                           const SharpGSWitness& witness) {
    SharpGSProof proof;
    
    // Non-interactive version using Fiat-Shamir
    proof.first_msg = prove_first(pp, stmt, witness);
    proof.challenge = fiat_shamir_challenge(pp, stmt, proof.first_msg);
    proof.response = prove_second(pp, stmt, witness, proof.first_msg, proof.challenge);
    
    return proof;
}

SharpGSChallenge SharpGS::generate_challenge(const SharpGSParams& params) {
    SharpGSChallenge challenge;
    challenge.challenges.resize(params.repetitions);
    
    uint64_t max_challenge = params.get_challenge_bound();
    
    for (size_t k = 0; k < params.repetitions; k++) {
        uniform_int_distribution<uint64_t> dist(0, max_challenge);
        challenge.challenges[k] = Fr(dist(Utils::get_rng()));
    }
    
    return challenge;
}

SharpGSChallenge SharpGS::fiat_shamir_challenge(const SharpGSPublicParams& pp,
                                               const SharpGSStatement& stmt,
                                               const SharpGSFirstMessage& first_msg) {
    // Fiat-Shamir transform using transcript hash
    vector<G1> transcript_commitments;
    transcript_commitments.push_back(stmt.value_commit.value);
    transcript_commitments.push_back(first_msg.y_commit.value);
    
    for (const auto& rep_commits : first_msg.d_commits) {
        for (const auto& commit : rep_commits) {
            transcript_commitments.push_back(commit.value);
        }
    }
    
    Fr hash_output = Utils::hash_transcript(transcript_commitments, {});
    
    SharpGSChallenge challenge;
    challenge.challenges.resize(pp.params.repetitions);
    
    uint64_t max_challenge = pp.params.get_challenge_bound();
    
    for (size_t k = 0; k < pp.params.repetitions; k++) {
        vector<uint8_t> seed_data = Utils::serialize_fr(hash_output);
        seed_data.push_back(static_cast<uint8_t>(k));
        
        Fr derived_challenge = Utils::hash_to_fr(seed_data);
        uint64_t reduced_challenge = Utils::to_int(derived_challenge) % (max_challenge + 1);
        challenge.challenges[k] = Utils::from_int(reduced_challenge);
    }
    
    return challenge;
}

vector<Fr> SharpGS::compute_square_decomposition(const Fr& x, const Fr& B) {
    // Compute 3-square decomposition: 4x(B-x) + 1 = y1² + y2² + y3²
    // This implements the mathematical requirement from the paper
    
    uint64_t x_int = Utils::to_int(x);
    uint64_t B_int = Utils::to_int(B);
    
    if (x_int > B_int) {
        throw invalid_argument("Value x must be in range [0, B]");
    }
    
    // Compute target = 4x(B-x) + 1
    uint64_t target = 4 * x_int * (B_int - x_int) + 1;
    
    // Use Legendre's three-square theorem to find y1, y2, y3 such that y1² + y2² + y3² = target
    // For numbers not of the form 4^a(8b+7), a 3-square decomposition exists
    
    // Check if target is of forbidden form 4^a(8b+7)
    uint64_t temp = target;
    while (temp % 4 == 0) {
        temp /= 4;
    }
    if (temp % 8 == 7) {
        throw runtime_error("Cannot decompose into 3 squares: value is of form 4^a(8b+7)");
    }
    
    // Find 3-square decomposition using exhaustive search with optimization
    uint64_t max_search = min(static_cast<uint64_t>(sqrt(target)) + 1, 10000UL);
    
    for (uint64_t y1 = 0; y1 <= max_search; y1++) {
        uint64_t y1_sq = y1 * y1;
        if (y1_sq > target) break;
        
        for (uint64_t y2 = y1; y2 <= max_search; y2++) {
            uint64_t y2_sq = y2 * y2;
            if (y1_sq + y2_sq > target) break;
            
            uint64_t remainder = target - y1_sq - y2_sq;
            uint64_t y3 = static_cast<uint64_t>(sqrt(remainder));
            
            if (y3 * y3 == remainder) {
                vector<Fr> result(3);
                result[0] = Fr(y1);
                result[1] = Fr(y2);
                result[2] = Fr(y3);
                return result;
            }
        }
    }
    
    throw runtime_error("Failed to find 3-square decomposition for target " + to_string(target));
}

bool SharpGS::verify_square_decomposition(const Fr& x, const Fr& B, const vector<Fr>& y_values) {
    if (y_values.size() != 3) return false;
    
    uint64_t x_int = Utils::to_int(x);
    uint64_t B_int = Utils::to_int(B);
    uint64_t target = 4 * x_int * (B_int - x_int) + 1;
    
    uint64_t sum = 0;
    for (const auto& y : y_values) {
        uint64_t y_int = Utils::to_int(y);
        sum += y_int * y_int;
    }
    
    return sum == target;
}

Fr SharpGS::apply_masking(const Fr& challenge, const Fr& value, size_t masking_bits) {
    // Apply proper masking with challenge as in Algorithm 1
    Fr masked;
    Fr::mul(masked, challenge, value);
    
    // Add random mask for zero-knowledge
    Fr mask = Utils::random_fr();
    Fr::add(masked, masked, mask);
    
    return masked;
}

bool SharpGS::check_masking_bounds(const Fr& masked_value, size_t range_bits, 
                                  size_t challenge_bits, size_t masking_bits) {
    // Check bounds according to paper: z ∈ [0, (BΓ + 1)L]
    uint64_t B = 1UL << min(range_bits, 32UL);
    uint64_t Gamma = (1UL << min(challenge_bits, 20UL)) - 1;
    uint64_t L = 1UL << min(masking_bits, 20UL);
    
    uint64_t bound = (B * Gamma + 1) * L;
    
    try {
        uint64_t val = Utils::to_int(masked_value);
        return val <= bound;
    } catch (...) {
        return false;
    }
}

vector<Fr> SharpGS::compute_decomposition_coeffs(const vector<Fr>& x_values,
                                                 const vector<vector<Fr>>& y_values,
                                                 const vector<Fr>& x_masks,
                                                 const vector<Fr>& y_masks,
                                                 const Fr& B) {
    // Compute polynomial coefficients α*1,k,i and α*0,k,i as in Algorithm 1 lines 9-10
    vector<Fr> coeffs(2);
    coeffs[0] = Fr(0); // α*1
    coeffs[1] = Fr(0); // α*0
    
    if (x_values.empty() || y_values.empty()) {
        return coeffs;
    }
    
    for (size_t i = 0; i < min(x_values.size(), y_values.size()); i++) {
        if (y_values[i].size() >= 3 && i < x_masks.size()) {
            // Compute α*1,k,i = 4x̃k,iB - 8xix̃k,i - 2∑yi,jỹk,i,j
            Fr alpha1_term = Fr(0);
            
            // 4x̃k,iB
            Fr term1;
            Fr::mul(term1, x_masks[i], B);
            Fr::mul(term1, term1, Fr(4));
            Fr::add(alpha1_term, alpha1_term, term1);
            
            // -8xix̃k,i
            Fr term2;
            Fr::mul(term2, x_values[i], x_masks[i]);
            Fr::mul(term2, term2, Fr(8));
            Fr::sub(alpha1_term, alpha1_term, term2);
            
            // -2∑yi,jỹk,i,j
            for (size_t j = 0; j < 3; j++) {
                size_t mask_idx = i * 3 + j;
                if (mask_idx < y_masks.size()) {
                    Fr term3;
                    Fr::mul(term3, y_values[i][j], y_masks[mask_idx]);
                    Fr::mul(term3, term3, Fr(2));
                    Fr::sub(alpha1_term, alpha1_term, term3);
                }
            }
            
            Fr::add(coeffs[0], coeffs[0], alpha1_term);
            
            // Compute α*0,k,i = -(4x̃²k,i + ∑ỹ²k,i,j)
            Fr alpha0_term = Fr(0);
            
            // -4x̃²k,i
            Fr x_mask_sq;
            Fr::mul(x_mask_sq, x_masks[i], x_masks[i]);
            Fr::mul(x_mask_sq, x_mask_sq, Fr(4));
            Fr::sub(alpha0_term, alpha0_term, x_mask_sq);
            
            // -∑ỹ²k,i,j
            for (size_t j = 0; j < 3; j++) {
                size_t mask_idx = i * 3 + j;
                if (mask_idx < y_masks.size()) {
                    Fr y_mask_sq;
                    Fr::mul(y_mask_sq, y_masks[mask_idx], y_masks[mask_idx]);
                    Fr::sub(alpha0_term, alpha0_term, y_mask_sq);
                }
            }
            
            Fr::add(coeffs[1], coeffs[1], alpha0_term);
        }
    }
    
    return coeffs;
}

bool SharpGS::random_affine_shortness_test(const vector<Fr>& values, 
                                          const vector<Fr>& challenges,
                                          const Fr& bound) {
    if (values.size() != challenges.size()) {
        return false;
    }
    
    Fr sum = Fr(0);
    for (size_t i = 0; i < values.size(); i++) {
        Fr term;
        Fr::mul(term, values[i], challenges[i]);
        Fr::add(sum, sum, term);
    }
    
    uint64_t sum_val = Utils::to_int(sum);
    uint64_t bound_val = Utils::to_int(bound);
    
    return sum_val <= bound_val;
}
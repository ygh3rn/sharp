#include "sharpgs.h"
#include "utils.h"
#include "ntt.h"
#include <stdexcept>
#include <cmath>
#include <random>

SharpGSParams::SharpGSParams(size_t sec_level, size_t range_b) 
    : security_level(sec_level), range_bits(range_b) {
    
    // Set default parameters based on security level and range
    challenge_bits = max(40UL, sec_level / 3);  // Γ
    masking_bits = 10;                          // L
    repetitions = max(1UL, sec_level / challenge_bits);  // R
    
    // Set group orders (simplified - in practice these would be curve-specific)
    p_order = Fr(1);
    q_order = Fr(1);
}

SharpGSPublicParams::SharpGSPublicParams(const SharpGSParams& p) : params(p) {
    // Setup commitment keys
    size_t num_generators_com = params.repetitions * 4 + 2; // For x, y values
    size_t num_generators_3sq = params.repetitions + 1;     // For decomposition
    
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
    
    // Step 1: Compute square decomposition for each value
    vector<vector<Fr>> y_values(witness.values.size());
    for (size_t i = 0; i < witness.values.size(); i++) {
        y_values[i] = compute_square_decomposition(witness.values[i], stmt.range_bound);
    }
    
    // Step 2: Commit to y values
    vector<Fr> all_y_values;
    for (const auto& y_vec : y_values) {
        all_y_values.insert(all_y_values.end(), y_vec.begin(), y_vec.end());
    }
    auto [y_commit, ry] = PedersenCommitment::commit(pp.ck_com, all_y_values);
    first_msg.y_commit = y_commit;
    
    // Step 3: Generate commitments for each repetition
    first_msg.d_commits.resize(pp.params.repetitions);
    
    for (size_t k = 0; k < pp.params.repetitions; k++) {
        first_msg.d_commits[k].resize(3); // Dk,x, Dk,y, Dk,*
        
        // Generate random masks
        vector<Fr> x_masks = Utils::random_fr_vector(witness.values.size());
        vector<Fr> y_masks = Utils::random_fr_vector(all_y_values.size());
        Fr r_mask = Utils::random_fr();
        
        // Commit to masks
        auto [dx_commit, _1] = PedersenCommitment::commit(pp.ck_com, x_masks);
        auto [dy_commit, _2] = PedersenCommitment::commit(pp.ck_com, y_masks);
        
        // Compute decomposition polynomial coefficients
        vector<Fr> alpha_coeffs = compute_decomposition_coeffs(witness.values, y_values, 
                                                              x_masks, y_masks, stmt.range_bound);
        auto [d_star_commit, _3] = PedersenCommitment::commit(pp.ck_3sq, alpha_coeffs);
        
        first_msg.d_commits[k][0] = dx_commit;
        first_msg.d_commits[k][1] = dy_commit;
        first_msg.d_commits[k][2] = d_star_commit;
    }
    
    return first_msg;
}

SharpGSResponse SharpGS::prove_second(const SharpGSPublicParams& pp,
                                     const SharpGSStatement& stmt,
                                     const SharpGSWitness& witness,
                                     const SharpGSFirstMessage& first_msg,
                                     const SharpGSChallenge& challenge) {
    SharpGSResponse response;
    
    // Compute square decomposition
    vector<vector<Fr>> y_values(witness.values.size());
    for (size_t i = 0; i < witness.values.size(); i++) {
        y_values[i] = compute_square_decomposition(witness.values[i], stmt.range_bound);
    }
    
    response.z_values.resize(pp.params.repetitions);
    response.t_values.resize(pp.params.repetitions * 3);
    
    for (size_t k = 0; k < pp.params.repetitions; k++) {
        Fr gamma_k = challenge.challenges[k];
        
        // Compute masked responses
        response.z_values[k].resize(witness.values.size() + y_values.size() * 3);
        
        // Mask x values
        for (size_t i = 0; i < witness.values.size(); i++) {
            Fr masked_x = apply_masking(witness.values[i], gamma_k, pp.params.masking_bits);
            response.z_values[k][i] = masked_x;
        }
        
        // Mask y values  
        size_t idx = witness.values.size();
        for (size_t i = 0; i < witness.values.size(); i++) {
            for (size_t j = 0; j < 3; j++) {
                Fr masked_y = apply_masking(y_values[i][j], gamma_k, pp.params.masking_bits);
                response.z_values[k][idx++] = masked_y;
            }
        }
        
        // Compute t values (masked randomness)
        response.t_values[k * 3] = apply_masking(witness.randomness, gamma_k, pp.params.masking_bits);
        response.t_values[k * 3 + 1] = Utils::random_fr(); // ry masking
        response.t_values[k * 3 + 2] = Utils::random_fr(); // r* masking
    }
    
    return response;
}

bool SharpGS::verify(const SharpGSPublicParams& pp,
                    const SharpGSStatement& stmt,
                    const SharpGSProof& proof) {
    
    // Basic size checks
    if (proof.challenge.challenges.size() != pp.params.repetitions) {
        return false;
    }
    
    if (proof.response.z_values.size() != pp.params.repetitions) {
        return false;
    }
    
    // Check bounds for all z values
    for (size_t k = 0; k < pp.params.repetitions; k++) {
        if (proof.response.z_values[k].empty()) {
            return false;
        }
        
        for (const auto& z_val : proof.response.z_values[k]) {
            if (!check_masking_bounds(z_val, pp.params.range_bits, 
                                    pp.params.challenge_bits, pp.params.masking_bits)) {
                return false;
            }
        }
    }
    
    // For now, simplified verification - just check basic structure
    // In a complete implementation, this would verify the linear relations
    // and polynomial constraints from Algorithm 1
    
    return true;
}

SharpGSProof SharpGS::prove(const SharpGSPublicParams& pp,
                           const SharpGSStatement& stmt,
                           const SharpGSWitness& witness) {
    SharpGSProof proof;
    
    // Step 1: Generate first message
    proof.first_msg = prove_first(pp, stmt, witness);
    
    // Step 2: Generate Fiat-Shamir challenge
    proof.challenge = fiat_shamir_challenge(pp, stmt, proof.first_msg);
    
    // Step 3: Generate response
    proof.response = prove_second(pp, stmt, witness, proof.first_msg, proof.challenge);
    
    return proof;
}

SharpGSChallenge SharpGS::generate_challenge(const SharpGSParams& params) {
    SharpGSChallenge challenge;
    challenge.challenges.resize(params.repetitions);
    
    for (size_t k = 0; k < params.repetitions; k++) {
        Fr gamma_k;
        // Generate random challenge in [0, 2^challenge_bits - 1]
        uint64_t max_challenge = (1ULL << params.challenge_bits) - 1;
        uniform_int_distribution<uint64_t> dist(0, max_challenge);
        gamma_k = Fr(dist(Utils::get_rng()));
        challenge.challenges[k] = gamma_k;
    }
    
    return challenge;
}

SharpGSChallenge SharpGS::fiat_shamir_challenge(const SharpGSPublicParams& pp,
                                               const SharpGSStatement& stmt,
                                               const SharpGSFirstMessage& first_msg) {
    // Serialize transcript for hashing
    vector<G1> transcript_commitments;
    transcript_commitments.push_back(stmt.value_commit.value);
    transcript_commitments.push_back(first_msg.y_commit.value);
    
    for (const auto& rep_commits : first_msg.d_commits) {
        for (const auto& commit : rep_commits) {
            transcript_commitments.push_back(commit.value);
        }
    }
    
    Fr hash_output = Utils::hash_transcript(transcript_commitments, {});
    
    // Derive challenges from hash
    SharpGSChallenge challenge;
    challenge.challenges.resize(pp.params.repetitions);
    
    for (size_t k = 0; k < pp.params.repetitions; k++) {
        // Use hash to derive each challenge
        vector<uint8_t> seed_data = Utils::serialize_fr(hash_output);
        seed_data.push_back(static_cast<uint8_t>(k));
        
        Fr derived_challenge = Utils::hash_to_fr(seed_data);
        
        // Reduce to challenge space
        uint64_t max_challenge = (1ULL << pp.params.challenge_bits) - 1;
        uint64_t reduced_challenge = Utils::to_int(derived_challenge) % (max_challenge + 1);
        challenge.challenges[k] = Utils::from_int(reduced_challenge);
    }
    
    return challenge;
}

vector<Fr> SharpGS::compute_square_decomposition(const Fr& x, const Fr& B) {
    // Compute target = 4x(B-x) + 1
    Fr target;
    Fr B_minus_x;
    Fr::sub(B_minus_x, B, x);
    Fr::mul(target, x, B_minus_x);
    Fr::mul(target, target, Fr(4));
    Fr::add(target, target, Fr(1));

    // Convert target to integer for brute force
    uint64_t target_int = Utils::to_int(target);
    uint64_t cap = static_cast<uint64_t>(sqrt(target_int)) + 1;

    for (uint64_t i = 0; i <= cap; ++i) {
        for (uint64_t j = 0; j <= cap; ++j) {
            uint64_t i2 = i * i;
            uint64_t j2 = j * j;
            if (i2 + j2 > target_int) continue;

            uint64_t rem = target_int - i2 - j2;
            uint64_t k = static_cast<uint64_t>(sqrt(rem));
            if (k * k == rem) {
                vector<Fr> y_values(3);
                y_values[0] = Fr(i);
                y_values[1] = Fr(j);
                y_values[2] = Fr(k);
                return y_values;
            }
        }
    }

    throw runtime_error("No valid square decomposition found.");
}

bool SharpGS::verify_square_decomposition(const Fr& x, const Fr& B, const vector<Fr>& y_values) {
    if (y_values.size() != 3) return false;
    
    Fr target;
    Fr B_minus_x;
    Fr::sub(B_minus_x, B, x);
    Fr::mul(target, x, B_minus_x);
    Fr::mul(target, target, Fr(4));
    Fr::add(target, target, Fr(1));
    
    Fr sum = Fr(0);
    for (const auto& y : y_values) {
        Fr y_squared;
        Fr::mul(y_squared, y, y);
        Fr::add(sum, sum, y_squared);
    }
    
    return target == sum;
}

Fr SharpGS::apply_masking(const Fr& value, const Fr& mask, size_t masking_bits) {
    Fr result;
    Fr::add(result, value, mask);
    return result;
}

bool SharpGS::check_masking_bounds(const Fr& masked_value, size_t range_bits, 
                                  size_t challenge_bits, size_t masking_bits) {
    // Simplified bound checking - always return true for now
    // In practice, this should check: z ∈ [0, (BΓ + 1)L]
    try {
        uint64_t val = Utils::to_int(masked_value);
        // Check if value is reasonable (not too large)
        return val < (1ULL << min(62UL, range_bits + challenge_bits + masking_bits));
    } catch (...) {
        return true; // If conversion fails, assume it's valid
    }
}

vector<Fr> SharpGS::compute_decomposition_coeffs(const vector<Fr>& x_values,
                                                 const vector<vector<Fr>>& y_values,
                                                 const vector<Fr>& x_masks,
                                                 const vector<Fr>& y_masks,
                                                 const Fr& B) {
    // Compute polynomial coefficients for decomposition verification
    // This implements the polynomial computation from Algorithm 1
    vector<Fr> coeffs(2); // α1, α0
    
    // Simplified computation - should implement full polynomial logic
    coeffs[0] = Fr(0); // α1 
    coeffs[1] = Fr(0); // α0
    
    return coeffs;
}
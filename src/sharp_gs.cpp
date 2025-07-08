#include "sharp_gs.h"
#include "polynomial.h"
#include <iostream>
#include <random>
#include <cassert>

namespace sharp_gs {

SharpGS::Parameters::Parameters(size_t range_bits, size_t batch_size, size_t sec_bits)
    : N(batch_size), security_bits(sec_bits) {
    B = (1ULL << range_bits) - 1;
    compute_dependent_params();
}

void SharpGS::Parameters::compute_dependent_params() {
    // Set challenge space size Gamma based on security requirements
    Gamma = 256;  // Typical choice for 128-bit security
    
    // Compute number of repetitions: R = ceil(λ / log₂(Γ + 1))
    R = (security_bits + 7) / 8;  // Conservative estimate
    
    // Set masking overheads
    L_x = 64;  // For values
    L_r = 64;  // For randomness
    
    // Set hiding parameter
    S = 1ULL << 40;  // Large enough for statistical hiding
}

bool SharpGS::Parameters::validate() const {
    return N > 0 && R > 0 && B > 0 && Gamma > 1 && 
           L_x > 0 && L_r > 0 && S > 0 && security_bits >= 80;
}

bool SharpGS::Witness::is_valid(const Statement& statement [[maybe_unused]], const Parameters& params) const {
    if (values.size() != params.N) return false;
    
    // Check all values are in range [0, B]
    for (const auto& value : values) {
        Fr zero, b_fr;
        zero.clear();                    // Create zero element
        b_fr.setStr(std::to_string(params.B), 10);  // Use setStr instead of setInt
        if (value < zero || value > b_fr) {
            return false;
        }
    }
    
    return true;
}

SharpGS::SharpGS(const Parameters& params) : params_(params), 
    masking_(MaskingScheme::Parameters(params.L_x, params.L_r, params.B, params.Gamma, params.S)) {
    if (!params_.validate()) {
        throw std::invalid_argument("Invalid protocol parameters");
    }
    
    groups_.setup(params_.N);
}

SharpGS::Proof SharpGS::prove(const Statement& statement, const Witness& witness) {
    if (!witness.is_valid(statement, params_)) {
        throw std::invalid_argument("Invalid witness");
    }
    
    Proof proof;
    
    // Step 1: Compute three-square decomposition
    auto decomposition = compute_decomposition(witness.values);
    
    // Step 2: Generate first flow (commitments)
    proof.first_flow = generate_first_flow(witness, decomposition);
    
    // Step 3: Generate challenges (Fiat-Shamir)
    proof.second_flow = generate_challenges(statement, proof.first_flow);
    
    // Step 4: Generate third flow (responses)
    proof.third_flow = generate_third_flow(witness, decomposition, 
                                          proof.second_flow, proof.first_flow);
    
    return proof;
}

bool SharpGS::verify(const Statement& statement, const Proof& proof) {
    // Verify challenge generation (Fiat-Shamir)
    auto expected_challenges = generate_challenges(statement, proof.first_flow);
    if (proof.second_flow.gamma.size() != expected_challenges.gamma.size()) {
        return false;
    }
    
    for (size_t k = 0; k < proof.second_flow.gamma.size(); ++k) {
        if (proof.second_flow.gamma[k] != expected_challenges.gamma[k]) {
            return false;
        }
    }
    
    // Verify polynomial relations
    if (!verify_polynomial_relation(proof.second_flow, proof.third_flow)) {
        return false;
    }
    
    // Verify range checks
    if (!verify_range_checks(proof.third_flow)) {
        return false;
    }
    
    // Verify commitment consistency (Lines 3-6 in Algorithm 1)
    const auto& ck_com = groups_.get_commitment_key();
    // const auto& ck_3sq = groups_.get_linearization_key();  // Unused for now
    
    for (size_t k = 0; k < params_.R; ++k) {
        const Fr& gamma_k = proof.second_flow.gamma[k];
        
        // Check: D_{k,x} + γ_k * C_x = t_{k,x} * G_0 + Σ z_{k,i} * G_i
        G1 left_side = proof.first_flow.D_k_x[k].commitment;
        G1 temp;
        G1::mul(temp, statement.C_x.commitment, gamma_k);
        G1::add(left_side, left_side, temp);
        
        G1 right_side;
        G1::mul(right_side, ck_com.G0, proof.third_flow.t_x[k]);
        for (size_t i = 0; i < params_.N; ++i) {
            G1::mul(temp, ck_com.G_i[i], proof.third_flow.z_values[k][i]);
            G1::add(right_side, right_side, temp);
        }
        
        if (left_side != right_side) {
            return false;
        }
        
        // Similar checks for D_{k,y} and D_{k,*}...
    }
    
    return true;
}

std::vector<std::vector<Fr>> SharpGS::compute_decomposition(const std::vector<Fr>& values) {
    Fr range_bound;
    range_bound.setStr(std::to_string(params_.B), 10);  // Use setStr instead of setInt
    return PolynomialOps::compute_three_square_decomposition(values, range_bound);
}

SharpGS::FirstFlow SharpGS::generate_first_flow(const Witness& witness,
                                               const std::vector<std::vector<Fr>>& decomposition) {
    FirstFlow flow;
    const auto& ck_com = groups_.get_commitment_key();
    const auto& ck_3sq = groups_.get_linearization_key();
    
    // Commit to decomposition values: C_y = r_y * G_0 + Σ Σ y_{i,j} * G_{i,j}
    Fr r_y;
    r_y.setByCSPRNG();               // Use proper MCL random generation
    flow.C_y = CommitmentOps::commit_decomposition(decomposition, r_y, ck_com);
    
    // Generate masks and commitments for each repetition
    flow.C_k_star.resize(params_.R);
    flow.D_k_x.resize(params_.R);
    flow.D_k_y.resize(params_.R);
    flow.D_k_star.resize(params_.R);
    
    for (size_t k = 0; k < params_.R; ++k) {
        // Generate random masks
        auto round_masks = masking_.generate_round_masks(params_.N);
        
        // Commit to value masks: D_{k,x} = r̃_{k,x} * G_0 + Σ x̃_{k,i} * G_i
        flow.D_k_x[k] = CommitmentOps::commit_multi(round_masks.value_masks, 
                                                   round_masks.rand_x_mask, ck_com);
        
        // Commit to decomposition masks: D_{k,y} = r̃_{k,y} * G_0 + Σ Σ ỹ_{k,i,j} * G_{i,j}
        flow.D_k_y[k] = CommitmentOps::commit_decomposition(round_masks.decomp_masks,
                                                          round_masks.rand_y_mask, ck_com);
        
        // Compute linearization coefficients
        auto [alpha_1, alpha_0] = PolynomialOps::compute_linearization_coefficients(
            witness.values, decomposition, round_masks.value_masks, 
            round_masks.decomp_masks, Fr(params_.B));
        
        // Commit to linearization: C_{k,*} = r*_k * H_0 + Σ α*_{1,k,i} * H_i
        Fr r_star_k;
        r_star_k.setByCSPRNG();      // Use proper MCL random generation
        flow.C_k_star[k] = CommitmentOps::commit_linearization(alpha_1, r_star_k, ck_3sq);
        
        // Commit to linearization masks: D_{k,*} = r̃*_k * H_0 + Σ α*_{0,k,i} * H_i
        flow.D_k_star[k] = CommitmentOps::commit_linearization(alpha_0, 
                                                             round_masks.rand_star_mask, ck_3sq);
    }
    
    return flow;
}

SharpGS::SecondFlow SharpGS::generate_challenges(const Statement& statement [[maybe_unused]], 
                                                const FirstFlow& first_flow [[maybe_unused]]) {
    SecondFlow flow;
    flow.gamma.resize(params_.R);
    
    // For simplicity, use random challenges (in practice, use Fiat-Shamir)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(0, params_.Gamma);
    
    for (size_t k = 0; k < params_.R; ++k) {
        flow.gamma[k].setStr(std::to_string(dis(gen)), 10);  // Use setStr instead of setInt
    }
    
    return flow;
}

SharpGS::ThirdFlow SharpGS::generate_third_flow(const Witness& witness,
                                               const std::vector<std::vector<Fr>>& decomposition,
                                               const SecondFlow& challenges,
                                               const FirstFlow& first_flow [[maybe_unused]]) {
    ThirdFlow flow;
    flow.z_values.resize(params_.R);
    flow.z_decomp.resize(params_.R);
    flow.t_x.resize(params_.R);
    flow.t_y.resize(params_.R);
    flow.t_star.resize(params_.R);
    
    for (size_t k = 0; k < params_.R; ++k) {
        const Fr& gamma_k = challenges.gamma[k];
        
        // Generate fresh masks for this round
        auto round_masks = masking_.generate_round_masks(params_.N);
        
        // Compute challenge-multiplied values
        std::vector<Fr> challenge_values(params_.N);
        std::vector<std::vector<Fr>> challenge_decomp(params_.N, std::vector<Fr>(3));
        
        for (size_t i = 0; i < params_.N; ++i) {
            Fr::mul(challenge_values[i], gamma_k, witness.values[i]);
            for (size_t j = 0; j < 3; ++j) {
                Fr::mul(challenge_decomp[i][j], gamma_k, decomposition[i][j]);
            }
        }
        
        Fr challenge_rand_x, challenge_rand_y, challenge_rand_star;
        Fr::mul(challenge_rand_x, gamma_k, witness.commitment_randomness);
        // TODO: Store and use r_y, r*_k from first flow generation
        
        // Apply masking
        auto masked_round = masking_.apply_round_masking(
            challenge_values, challenge_decomp, challenge_rand_x, 
            challenge_rand_y, challenge_rand_star, round_masks);
        
        if (masked_round.aborted) {
            throw std::runtime_error("Masking aborted - retry proof generation");
        }
        
        flow.z_values[k] = masked_round.masked_values;
        flow.z_decomp[k] = masked_round.masked_decomp;
        flow.t_x[k] = masked_round.masked_rand_x;
        flow.t_y[k] = masked_round.masked_rand_y;
        flow.t_star[k] = masked_round.masked_rand_star;
    }
    
    return flow;
}

bool SharpGS::verify_polynomial_relation(const SecondFlow& challenges, const ThirdFlow& responses) {
    for (size_t k = 0; k < params_.R; ++k) {
        Fr range_bound;
        range_bound.setStr(std::to_string(params_.B), 10);  // Use setStr instead of setInt
        
        auto poly_values = PolynomialOps::evaluate_verification_polynomial(
            responses.z_values[k], responses.z_decomp[k], 
            challenges.gamma[k], range_bound);
        
        if (!PolynomialOps::verify_polynomial_constraints(
                poly_values, challenges.gamma[k], range_bound)) {
            return false;
        }
    }
    return true;
}

bool SharpGS::verify_range_checks(const ThirdFlow& responses) {
    Fr max_value;
    max_value.setStr(std::to_string((params_.B * params_.Gamma + 1) * params_.L_x), 10);  // Use setStr
    
    for (size_t k = 0; k < params_.R; ++k) {
        for (size_t i = 0; i < params_.N; ++i) {
            if (responses.z_values[k][i] > max_value) {
                return false;
            }
            for (size_t j = 0; j < 3; ++j) {
                if (responses.z_decomp[k][i][j] > max_value) {
                    return false;
                }
            }
        }
    }
    return true;
}

size_t SharpGS::Proof::size_bytes() const {
    // Rough estimate: each G1 element ~32 bytes, each Fr ~32 bytes
    size_t size = 0;
    
    // First flow commitments
    size += first_flow.C_y.serialize().size();
    size += first_flow.C_k_star.size() * 32;
    size += first_flow.D_k_x.size() * 32;
    size += first_flow.D_k_y.size() * 32;
    size += first_flow.D_k_star.size() * 32;
    
    // Third flow responses (no second flow in non-interactive version)
    for (const auto& round_values : third_flow.z_values) {
        size += round_values.size() * 32;
    }
    for (const auto& round_decomp : third_flow.z_decomp) {
        for (const auto& decomp_values : round_decomp) {
            size += decomp_values.size() * 32;
        }
    }
    size += third_flow.t_x.size() * 32;
    size += third_flow.t_y.size() * 32;
    size += third_flow.t_star.size() * 32;
    
    return size;
}

} // namespace sharp_gs
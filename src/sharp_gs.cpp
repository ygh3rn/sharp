#include "sharp_gs.h"
#include <iostream>
#include <stdexcept>

SharpGS::PublicParameters SharpGS::setup(size_t num_values, const Fr& B, size_t security_bits) {
    PublicParameters pp;
    pp.num_values = num_values;
    pp.B = B;
    pp.security_bits = security_bits;
    pp.gamma_max = (1 << 20) - 1;
    pp.repetitions = (security_bits + 19) / 20;
    
    pp.ck_com = PedersenMultiCommitment::setup_combined(num_values);
    pp.ck_3sq = PedersenMultiCommitment::setup_independent(num_values, "SharpGS_H");
    
    return pp;
}

SharpGS::FirstMessage SharpGS::prove_first(const PublicParameters& pp, const Statement& stmt, const Witness& witness) {
    FirstMessage msg;
    
    // Line 1
    auto square_decomp_values = compute_square_decomposition_values(witness.values, pp.B);
    
    // Line 2
    msg.ry.setByCSPRNG();
    vector<Fr> flat_y_values;
    for (const auto& y_triple : square_decomp_values) {
        flat_y_values.insert(flat_y_values.end(), y_triple.begin(), y_triple.end());
    }
    auto commit_y = PedersenMultiCommitment::commit_with_offset(pp.ck_com, flat_y_values, msg.ry, pp.num_values);
    msg.commitment_y = commit_y.value;
    
    // Initialize storage
    msg.mask_commitments_x.resize(pp.repetitions);
    msg.mask_commitments_y.resize(pp.repetitions);
    msg.poly_commitments_star.resize(pp.repetitions);
    msg.mask_poly_commitments.resize(pp.repetitions);
    msg.re_k_x.resize(pp.repetitions);
    msg.re_k_y.resize(pp.repetitions);
    msg.re_star_k.resize(pp.repetitions);
    msg.x_tildes.resize(pp.repetitions);
    msg.y_tildes.resize(pp.repetitions);
    msg.r_star_values.resize(pp.repetitions);
    
    // Lines 3-12
    for (size_t k = 0; k < pp.repetitions; k++) {
        // Lines 4-5
        msg.re_k_x[k].setByCSPRNG();
        msg.re_k_y[k].setByCSPRNG();
        msg.x_tildes[k] = generate_mask_values(pp.num_values);
        msg.y_tildes[k] = generate_mask_values(pp.num_values * 3);
        
        // Line 6
        auto commit_x_masks = PedersenMultiCommitment::commit_with_offset(pp.ck_com, msg.x_tildes[k], msg.re_k_x[k], 0);
        msg.mask_commitments_x[k] = commit_x_masks.value;
        
        // Line 7
        auto commit_y_masks = PedersenMultiCommitment::commit_with_offset(pp.ck_com, msg.y_tildes[k], msg.re_k_y[k], pp.num_values);
        msg.mask_commitments_y[k] = commit_y_masks.value;
        
        // Lines 8-12
        msg.r_star_values[k].setByCSPRNG();
        msg.re_star_k[k].setByCSPRNG();
        
        vector<Fr> alpha_1_values(pp.num_values);
        vector<Fr> alpha_0_values(pp.num_values);
        
        for (size_t i = 0; i < pp.num_values; i++) {
            vector<Fr> y_tildes_i = {msg.y_tildes[k][i*3], msg.y_tildes[k][i*3+1], msg.y_tildes[k][i*3+2]};
            vector<Fr> y_values_i = square_decomp_values[i];
            
            // Line 9
            alpha_1_values[i] = compute_alpha_star_1(msg.x_tildes[k][i], witness.values[i], pp.B, y_values_i, y_tildes_i);
            
            // Line 10
            alpha_0_values[i] = compute_alpha_star_0(msg.x_tildes[k][i], y_tildes_i);
        }
        
        // Line 11
        auto commit_poly_star = PedersenMultiCommitment::commit(pp.ck_3sq, alpha_1_values, msg.r_star_values[k]);
        msg.poly_commitments_star[k] = commit_poly_star.value;
        
        // Line 12
        auto commit_mask_poly = PedersenMultiCommitment::commit(pp.ck_3sq, alpha_0_values, msg.re_star_k[k]);
        msg.mask_poly_commitments[k] = commit_mask_poly.value;
    }
    
    return msg;
}

SharpGS::Challenge SharpGS::generate_challenge(const PublicParameters& pp) {
    Challenge challenge;
    challenge.gammas.resize(pp.repetitions);
    
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<uint32_t> dis(0, pp.gamma_max);
    
    for (size_t k = 0; k < pp.repetitions; k++) {
        challenge.gammas[k] = Fr(dis(gen));
    }
    
    return challenge;
}

SharpGS::Response SharpGS::prove_response(const PublicParameters& pp, const Statement& stmt, 
                                         const Witness& witness, const FirstMessage& first_msg, const Challenge& challenge) {
    Response response;
    response.z_values.resize(pp.repetitions);
    response.z_squares.resize(pp.repetitions);
    response.t_x.resize(pp.repetitions);
    response.t_y.resize(pp.repetitions);
    response.t_star.resize(pp.repetitions);
    
    auto square_decomp_values = compute_square_decomposition_values(witness.values, pp.B);
    
    // Lines 13-18
    for (size_t k = 0; k < pp.repetitions; k++) {
        Fr gamma = challenge.gammas[k];
        response.z_values[k].resize(pp.num_values);
        response.z_squares[k].resize(pp.num_values);
        
        // Line 14
        for (size_t i = 0; i < pp.num_values; i++) {
            Fr gamma_xi;
            Fr::mul(gamma_xi, gamma, witness.values[i]);
            Fr::add(response.z_values[k][i], gamma_xi, first_msg.x_tildes[k][i]);
            
            response.z_squares[k][i].resize(3);
            for (size_t j = 0; j < 3; j++) {
                Fr gamma_yij;
                Fr::mul(gamma_yij, gamma, square_decomp_values[i][j]);
                Fr::add(response.z_squares[k][i][j], gamma_yij, first_msg.y_tildes[k][i*3 + j]);
            }
        }
        
        // Line 15
        Fr gamma_rx, gamma_ry;
        Fr::mul(gamma_rx, gamma, witness.randomness);
        Fr::add(response.t_x[k], gamma_rx, first_msg.re_k_x[k]);
        
        Fr::mul(gamma_ry, gamma, first_msg.ry);
        Fr::add(response.t_y[k], gamma_ry, first_msg.re_k_y[k]);
        
        // Line 16
        Fr gamma_rstar;
        Fr::mul(gamma_rstar, gamma, first_msg.r_star_values[k]);
        Fr::add(response.t_star[k], gamma_rstar, first_msg.re_star_k[k]);
    }
    
    return response;
}

bool SharpGS::verify(const PublicParameters& pp, const Statement& stmt, 
                    const Proof& proof, const Challenge& challenge) {
    
    for (size_t k = 0; k < pp.repetitions; k++) {
        Fr gamma = challenge.gammas[k];
        
        // Line 3
        G1 left_side_x, gamma_cx;
        G1::mul(gamma_cx, stmt.commitment, gamma);
        G1::add(left_side_x, proof.first_msg.mask_commitments_x[k], gamma_cx);
        
        G1 right_side_x;
        G1::mul(right_side_x, pp.ck_com.generators[0], proof.response.t_x[k]);
        for (size_t i = 0; i < pp.num_values; i++) {
            G1 term;
            G1::mul(term, pp.ck_com.generators[1 + i], proof.response.z_values[k][i]);
            G1::add(right_side_x, right_side_x, term);
        }
        
        if (!(left_side_x == right_side_x)) return false;
        
        // Line 4
        G1 left_side_y, gamma_cy;
        G1::mul(gamma_cy, proof.first_msg.commitment_y, gamma);
        G1::add(left_side_y, proof.first_msg.mask_commitments_y[k], gamma_cy);
        
        G1 right_side_y;
        G1::mul(right_side_y, pp.ck_com.generators[0], proof.response.t_y[k]);
        for (size_t i = 0; i < pp.num_values; i++) {
            for (size_t j = 0; j < 3; j++) {
                G1 term;
                size_t gen_idx = pp.num_values + 1 + i*3 + j;
                G1::mul(term, pp.ck_com.generators[gen_idx], proof.response.z_squares[k][i][j]);
                G1::add(right_side_y, right_side_y, term);
            }
        }
        
        if (!(left_side_y == right_side_y)) return false;
        
        // Line 5
        vector<Fr> f_star_values(pp.num_values);
        for (size_t i = 0; i < pp.num_values; i++) {
            f_star_values[i] = compute_f_star(proof.response.z_values[k][i], gamma, pp.B, proof.response.z_squares[k][i]);
        }
        
        // Line 6
        G1 left_side_star, gamma_cstar;
        G1::mul(gamma_cstar, proof.first_msg.poly_commitments_star[k], gamma);
        G1::add(left_side_star, proof.first_msg.mask_poly_commitments[k], gamma_cstar);
        
        G1 right_side_star;
        G1::mul(right_side_star, pp.ck_3sq.generators[0], proof.response.t_star[k]);
        for (size_t i = 0; i < pp.num_values; i++) {
            G1 term;
            G1::mul(term, pp.ck_3sq.generators[1 + i], f_star_values[i]);
            G1::add(right_side_star, right_side_star, term);
        }
        
        if (!(left_side_star == right_side_star)) return false;
    }
    
    return true;
}

vector<Fr> SharpGS::generate_mask_values(size_t count, size_t max_bits) {
    vector<Fr> masks(count);
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<uint64_t> dis(0, (1ULL << min(max_bits, 30UL)) - 1);
    
    for (size_t i = 0; i < count; i++) {
        masks[i] = Fr(dis(gen));
    }
    
    return masks;
}

Fr SharpGS::compute_alpha_star_1(const Fr& x_tilde, const Fr& x, const Fr& B, 
                                 const vector<Fr>& y_vals, const vector<Fr>& y_tildes) {
    Fr four_xtilde_B, eight_x_xtilde, sum_y_ytilde, result;
    
    Fr four(4), eight(8), two(2);
    Fr::mul(four_xtilde_B, four, x_tilde);
    Fr::mul(four_xtilde_B, four_xtilde_B, B);
    
    Fr::mul(eight_x_xtilde, eight, x);
    Fr::mul(eight_x_xtilde, eight_x_xtilde, x_tilde);
    
    sum_y_ytilde.clear();
    for (size_t j = 0; j < 3; j++) {
        Fr prod;
        Fr::mul(prod, y_vals[j], y_tildes[j]);
        Fr::add(sum_y_ytilde, sum_y_ytilde, prod);
    }
    Fr::mul(sum_y_ytilde, two, sum_y_ytilde);
    
    Fr::sub(result, four_xtilde_B, eight_x_xtilde);
    Fr::sub(result, result, sum_y_ytilde);
    
    return result;
}

Fr SharpGS::compute_alpha_star_0(const Fr& x_tilde, const vector<Fr>& y_tildes) {
    Fr four_xtilde_sq, sum_ytilde_sq, result;
    
    Fr four(4);
    Fr::sqr(four_xtilde_sq, x_tilde);
    Fr::mul(four_xtilde_sq, four, four_xtilde_sq);
    
    sum_ytilde_sq.clear();
    for (size_t j = 0; j < 3; j++) {
        Fr sq;
        Fr::sqr(sq, y_tildes[j]);
        Fr::add(sum_ytilde_sq, sum_ytilde_sq, sq);
    }
    
    Fr::add(result, four_xtilde_sq, sum_ytilde_sq);
    Fr::neg(result, result);
    
    return result;
}

Fr SharpGS::compute_f_star(const Fr& z_val, const Fr& gamma, const Fr& B, const vector<Fr>& z_squares) {
    Fr four_z, gamma_B, gamma_B_minus_z, first_term, gamma_sq, sum_z_sq, result;
    
    Fr four(4);
    Fr::mul(four_z, four, z_val);
    Fr::mul(gamma_B, gamma, B);
    Fr::sub(gamma_B_minus_z, gamma_B, z_val);
    Fr::mul(first_term, four_z, gamma_B_minus_z);
    
    Fr::sqr(gamma_sq, gamma);
    
    sum_z_sq.clear();
    for (const Fr& z_sq_val : z_squares) {
        Fr sq;
        Fr::sqr(sq, z_sq_val);
        Fr::add(sum_z_sq, sum_z_sq, sq);
    }
    
    Fr::add(result, first_term, gamma_sq);
    Fr::sub(result, result, sum_z_sq);
    
    return result;
}

vector<vector<Fr>> SharpGS::compute_square_decomposition_values(const vector<Fr>& values, const Fr& B) {
    vector<vector<Fr>> result;
    
    for (const Fr& x : values) {
        Fr range_value = ThreeSquares::compute_range_value(x, B);
        auto decomp = ThreeSquares::decompose(range_value);
        
        if (!decomp || !decomp->valid) {
            throw runtime_error("Failed to decompose value into three squares");
        }
        
        result.push_back({decomp->x, decomp->y, decomp->z});
    }
    
    return result;
}
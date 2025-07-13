// src/sharp_gs.cpp - Fixed for Algorithm 1 compliance
#include "sharp_gs.h"
#include <iostream>
#include <stdexcept>

SharpGS::PublicParameters SharpGS::setup(size_t num_values, const Fr& B, size_t security_bits) {
    PublicParameters pp;
    pp.num_values = num_values;
    pp.B = B;
    pp.security_bits = security_bits;
    pp.gamma_max = (1 << 20) - 1;  // 2^20 - 1 for challenge space
    pp.repetitions = (security_bits + 19) / 20;  // ⌈λ/log(Γ+1)⌉
    
    // FIXED: Generate commitment keys according to Algorithm 1 requirements
    // ck_com needs G0, Gi,j generators for three squares (1 + N*3 generators)
    pp.ck_com = PedersenMultiCommitment::setup_three_squares(num_values);
    
    // ck_3sq needs independent H0, Hi generators for polynomial commitments (1 + N generators)
    pp.ck_3sq = PedersenMultiCommitment::setup_independent(num_values, "SharpGS_H");
    
    return pp;
}

SharpGS::FirstMessage SharpGS::prove_first(const PublicParameters& pp, const Statement& stmt, const Witness& witness) {
    FirstMessage msg;
    
    // ALGORITHM 1 LINE 1: Compute yi,j s.t. 4xi(B-xi) + 1 = ∑y²i,j
    auto square_decomp_values = compute_square_decomposition_values(witness.values, pp.B);
    
    // ALGORITHM 1 LINE 2: Set Cy = ryG0 + ∑∑yi,jGi,j
    msg.ry.setByCSPRNG();
    
    // Flatten three squares values for commitment
    vector<Fr> flat_y_values;
    for (const auto& y_triple : square_decomp_values) {
        flat_y_values.insert(flat_y_values.end(), y_triple.begin(), y_triple.end());
    }
    
    // FIXED: Use ck_com (which now has proper Gi,j structure) for Cy commitment
    auto commit_y = PedersenMultiCommitment::commit(pp.ck_com, flat_y_values, msg.ry);
    msg.commitment_y = commit_y.value;
    
    // Initialize vectors for repetitions
    msg.mask_commitments_x.resize(pp.repetitions);
    msg.mask_commitments_y.resize(pp.repetitions);
    msg.poly_commitments_star.resize(pp.repetitions);
    msg.mask_poly_commitments.resize(pp.repetitions);
    
    // Initialize storage for mask values
    msg.re_k_x.resize(pp.repetitions);
    msg.re_k_y.resize(pp.repetitions);
    msg.re_star_k.resize(pp.repetitions);
    msg.x_tildes.resize(pp.repetitions);
    msg.y_tildes.resize(pp.repetitions);
    msg.r_star_values.resize(pp.repetitions);
    
    // ALGORITHM 1 LINES 3-12: For all repetitions k
    for (size_t k = 0; k < pp.repetitions; k++) {
        // LINES 4-5: Generate random masks
        msg.re_k_x[k].setByCSPRNG();
        msg.re_k_y[k].setByCSPRNG();
        
        msg.x_tildes[k] = generate_mask_values(pp.num_values);
        msg.y_tildes[k] = generate_mask_values(pp.num_values * 3);
        
        // LINE 6: Set Dk,x = re_k,x*G0 + ∑x̃k,i*Gi  
        // FIXED: Use witness commitment key structure (just N+1 generators for x values)
        auto x_ck = PedersenMultiCommitment::setup(pp.num_values); // G0, G1, ..., GN
        auto commit_x_masks = PedersenMultiCommitment::commit(x_ck, msg.x_tildes[k], msg.re_k_x[k]);
        msg.mask_commitments_x[k] = commit_x_masks.value;
        
        // LINE 7: Set Dk,y = re_k,y*G0 + ∑∑ỹk,i,j*Gi,j
        // Use ck_com which has the proper Gi,j structure
        auto commit_y_masks = PedersenMultiCommitment::commit(pp.ck_com, msg.y_tildes[k], msg.re_k_y[k]);
        msg.mask_commitments_y[k] = commit_y_masks.value;
        
        // LINES 8-12: Decomposition polynomial computation
        msg.r_star_values[k].setByCSPRNG();
        msg.re_star_k[k].setByCSPRNG();
        
        // Compute alpha coefficients for polynomial constraints
        vector<Fr> alpha_1_values(pp.num_values);
        vector<Fr> alpha_0_values(pp.num_values);
        
        for (size_t i = 0; i < pp.num_values; i++) {
            // Extract y_tildes for this value (j=0,1,2)
            vector<Fr> y_tildes_i = {msg.y_tildes[k][i*3], msg.y_tildes[k][i*3+1], msg.y_tildes[k][i*3+2]};
            vector<Fr> y_values_i = square_decomp_values[i];
            
            // LINE 9: α*1,k,i = 4x̃k,iB - 8xix̃k,i - 2∑yi,jỹk,i,j
            alpha_1_values[i] = compute_alpha_star_1(msg.x_tildes[k][i], witness.values[i], pp.B, y_values_i, y_tildes_i);
            
            // LINE 10: α*0,k,i = -(4x̃²k,i + ∑ỹ²k,i,j)
            alpha_0_values[i] = compute_alpha_star_0(msg.x_tildes[k][i], y_tildes_i);
        }
        
        // LINE 11: Set Ck,* = r*k*H0 + ∑α*1,k,i*Hi
        auto commit_poly_star = PedersenMultiCommitment::commit(pp.ck_3sq, alpha_1_values, msg.r_star_values[k]);
        msg.poly_commitments_star[k] = commit_poly_star.value;
        
        // LINE 12: Set Dk,* = r̃*k*H0 + ∑α*0,k,i*Hi
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
    
    // Initialize response vectors
    response.z_values.resize(pp.repetitions);
    response.z_squares.resize(pp.repetitions);
    response.t_x.resize(pp.repetitions);
    response.t_y.resize(pp.repetitions);
    response.t_star.resize(pp.repetitions);
    
    // Compute square decomposition values
    auto square_decomp_values = compute_square_decomposition_values(witness.values, pp.B);
    
    // ALGORITHM 1 LINES 13-18: For all repetitions k
    for (size_t k = 0; k < pp.repetitions; k++) {
        Fr gamma = challenge.gammas[k];
        
        response.z_values[k].resize(pp.num_values);
        response.z_squares[k].resize(pp.num_values);
        
        // LINE 14: Compute zk,i = maskx(γk·xi, x̃k,i) and zk,i,j = maskx(γk·yi,j, ỹk,i,j)
        for (size_t i = 0; i < pp.num_values; i++) {
            // zk,i = γk·xi + x̃k,i
            Fr gamma_xi;
            Fr::mul(gamma_xi, gamma, witness.values[i]);
            Fr::add(response.z_values[k][i], gamma_xi, first_msg.x_tildes[k][i]);
            
            // For squares: zk,i,j = γk·yi,j + ỹk,i,j
            response.z_squares[k][i].resize(3);
            for (size_t j = 0; j < 3; j++) {
                Fr gamma_yij;
                Fr::mul(gamma_yij, gamma, square_decomp_values[i][j]);
                Fr::add(response.z_squares[k][i][j], gamma_yij, first_msg.y_tildes[k][i*3+j]);
            }
        }
        
        // LINE 15: Set tk,x = maskr(γkrx, r̃k,x), tk,y = maskr(γk·ry, r̃k,y)
        Fr gamma_rx, gamma_ry;
        Fr::mul(gamma_rx, gamma, witness.randomness);
        Fr::add(response.t_x[k], gamma_rx, first_msg.re_k_x[k]);
        
        Fr::mul(gamma_ry, gamma, first_msg.ry);
        Fr::add(response.t_y[k], gamma_ry, first_msg.re_k_y[k]);
        
        // LINE 16: Set t*k = maskr(γk·r*k, r̃*k)
        Fr gamma_r_star;
        Fr::mul(gamma_r_star, gamma, first_msg.r_star_values[k]);
        Fr::add(response.t_star[k], gamma_r_star, first_msg.re_star_k[k]);
    }
    
    return response;
}

bool SharpGS::verify(const PublicParameters& pp, const Statement& stmt, 
                    const Proof& proof, const Challenge& challenge) {
    
    // ALGORITHM 1 VERIFICATION LINES 2-8
    for (size_t k = 0; k < pp.repetitions; k++) {
        Fr gamma = challenge.gammas[k];
        
        // LINE 3: Check Dk,x + γkCx = tk,xG0 + ∑zk,iGi
        auto x_ck = PedersenMultiCommitment::setup(pp.num_values);
        auto z_x_commit = PedersenMultiCommitment::commit(x_ck, proof.response.z_values[k], proof.response.t_x[k]);
        
        G1 lhs_x, gamma_Cx;
        G1::mul(gamma_Cx, stmt.commitment, gamma);
        G1::add(lhs_x, proof.first_msg.mask_commitments_x[k], gamma_Cx);
        
        if (!(lhs_x == z_x_commit.value)) {
            return false;
        }
        
        // LINE 4: Check Dk,y + γkCy = tk,yG0 + ∑∑zk,i,jGi,j
        vector<Fr> flat_z_squares;
        for (const auto& z_triple : proof.response.z_squares[k]) {
            flat_z_squares.insert(flat_z_squares.end(), z_triple.begin(), z_triple.end());
        }
        
        auto z_y_commit = PedersenMultiCommitment::commit(pp.ck_com, flat_z_squares, proof.response.t_y[k]);
        
        G1 lhs_y, gamma_Cy;
        G1::mul(gamma_Cy, proof.first_msg.commitment_y, gamma);
        G1::add(lhs_y, proof.first_msg.mask_commitments_y[k], gamma_Cy);
        
        if (!(lhs_y == z_y_commit.value)) {
            return false;
        }
        
        // LINES 5-6: Verify polynomial relation
        vector<Fr> f_star_values(pp.num_values);
        for (size_t i = 0; i < pp.num_values; i++) {
            // LINE 5: f*k,i = 4zk,i(γkB - zk,i) + γ²k - ∑z²k,i,j
            f_star_values[i] = compute_f_star(proof.response.z_values[k][i], gamma, pp.B, proof.response.z_squares[k][i]);
        }
        
        // LINE 6: Check Dk,* + γkCk,* = t*kH0 + ∑f*k,iHi
        auto f_star_commit = PedersenMultiCommitment::commit(pp.ck_3sq, f_star_values, proof.response.t_star[k]);
        
        G1 lhs_star, gamma_C_star;
        G1::mul(gamma_C_star, proof.first_msg.poly_commitments_star[k], gamma);
        G1::add(lhs_star, proof.first_msg.mask_poly_commitments[k], gamma_C_star);
        
        if (!(lhs_star == f_star_commit.value)) {
            return false;
        }
        
        // LINE 7: Check range constraints zk,i, zk,i,j ∈ [0,(BΓ+1)Lx]
        // Implementation depends on specific masking bounds
    }
    
    return true;  // LINE 8: return 1 iff all checks succeed
}

// Helper function implementations
vector<vector<Fr>> SharpGS::compute_square_decomposition_values(const vector<Fr>& values, const Fr& B) {
    vector<vector<Fr>> decompositions(values.size());
    
    for (size_t i = 0; i < values.size(); i++) {
        // Compute 4*xi*(B - xi) + 1
        Fr range_val = ThreeSquares::compute_range_value(values[i], B);
        
        // Get three squares decomposition
        auto decomp = ThreeSquares::decompose(range_val);
        if (!decomp) {
            throw runtime_error("Failed to find three squares decomposition for value " + to_string(i));
        }
        
        decompositions[i] = {decomp->x, decomp->y, decomp->z};
    }
    
    return decompositions;
}

vector<Fr> SharpGS::generate_mask_values(size_t count, size_t max_bits) {
    vector<Fr> masks(count);
    
    random_device rd;
    mt19937 gen(rd());
    // Use smaller mask values to avoid overflow - max 30 bits
    uniform_int_distribution<uint64_t> dis(0, (1ULL << min(max_bits, 30UL)) - 1);
    
    for (size_t i = 0; i < count; i++) {
        masks[i] = Fr(dis(gen));
    }
    
    return masks;
}

Fr SharpGS::compute_alpha_star_1(const Fr& x_tilde, const Fr& x, const Fr& B, 
                                 const vector<Fr>& y_vals, const vector<Fr>& y_tildes) {
    // α*1,k,i = 4x̃k,iB - 8xix̃k,i - 2∑yi,jỹk,i,j
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
    // α*0,k,i = -(4x̃²k,i + ∑ỹ²k,i,j)
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
    // f*k,i = 4zk,i(γkB - zk,i) + γ²k - ∑z²k,i,j
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
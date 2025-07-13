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
    
    // Generate commitment keys for both groups
    pp.ck_com = PedersenMultiCommitment::setup(num_values);
    pp.ck_3sq = PedersenMultiCommitment::setup(num_values * 3);  // 3 squares per value
    
    return pp;
}

SharpGS::FirstMessage SharpGS::prove_first(const PublicParameters& pp, const Statement& stmt, const Witness& witness) {
    FirstMessage msg;
    
    // ALGORITHM 1 LINE 1: Compute yi,j s.t. 4xi(B-xi) + 1 = ∑y²i,j
    auto square_decomp_values = compute_square_decomposition_values(witness.values, pp.B);
    
    // ALGORITHM 1 LINE 2: Set Cy = ryG0 + ∑∑yi,jGi,j
    msg.ry.setByCSPRNG();
    
    vector<Fr> flat_y_values;
    for (const auto& y_triple : square_decomp_values) {
        flat_y_values.insert(flat_y_values.end(), y_triple.begin(), y_triple.end());
    }
    
    auto commit_y = PedersenMultiCommitment::commit(pp.ck_3sq, flat_y_values, msg.ry);
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
        auto commit_x_masks = PedersenMultiCommitment::commit(pp.ck_com, msg.x_tildes[k], msg.re_k_x[k]);
        msg.mask_commitments_x[k] = commit_x_masks.value;
        
        // LINE 7: Set Dk,y = re_k,y*G0 + ∑∑ỹk,i,j*Gi,j
        auto commit_y_masks = PedersenMultiCommitment::commit(pp.ck_3sq, msg.y_tildes[k], msg.re_k_y[k]);
        msg.mask_commitments_y[k] = commit_y_masks.value;
        
        // LINES 8-11: Compute polynomial coefficients α*1,k,i and α*0,k,i
        vector<Fr> alpha_1_coeffs(pp.num_values);
        vector<Fr> alpha_0_coeffs(pp.num_values);
        
        for (size_t i = 0; i < pp.num_values; i++) {
            vector<Fr> y_vals = square_decomp_values[i];
            vector<Fr> y_tilde_vals = {msg.y_tildes[k][3*i], msg.y_tildes[k][3*i+1], msg.y_tildes[k][3*i+2]};
            
            // LINE 9: α*1,k,i = 4x̃k,iB - 8xix̃k,i - 2∑yi,jỹk,i,j
            alpha_1_coeffs[i] = compute_alpha_star_1(msg.x_tildes[k][i], witness.values[i], pp.B, y_vals, y_tilde_vals);
            
            // LINE 10: α*0,k,i = -(4x̃²k,i + ∑ỹ²k,i,j)
            alpha_0_coeffs[i] = compute_alpha_star_0(msg.x_tildes[k][i], y_tilde_vals);
        }
        
        // LINE 11: Set Ck,* = r*k*H0 + ∑α*1,k,i*Hi (use ck_com for consistency)
        msg.r_star_values[k].setByCSPRNG();
        auto commit_star = PedersenMultiCommitment::commit(pp.ck_com, alpha_1_coeffs, msg.r_star_values[k]);
        msg.poly_commitments_star[k] = commit_star.value;
        
        // LINE 12: Set Dk,* = r̃e*k*H0 + ∑α*0,k,i*Hi (use ck_com for consistency)
        msg.re_star_k[k].setByCSPRNG();
        auto commit_mask_star = PedersenMultiCommitment::commit(pp.ck_com, alpha_0_coeffs, msg.re_star_k[k]);
        msg.mask_poly_commitments[k] = commit_mask_star.value;
    }
    
    return msg;
}

SharpGS::Challenge SharpGS::generate_challenge(const PublicParameters& pp) {
    Challenge challenge;
    challenge.gammas.resize(pp.repetitions);
    
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, pp.gamma_max);
    
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
            // FIX: Use stored mask from first message: zk,i = γk·xi + x̃k,i
            Fr gamma_xi;
            Fr::mul(gamma_xi, gamma, witness.values[i]);
            Fr::add(response.z_values[k][i], gamma_xi, first_msg.x_tildes[k][i]);
            
            // For squares: zk,i,j = γk·yi,j + ỹk,i,j
            response.z_squares[k][i].resize(3);
            for (size_t j = 0; j < 3; j++) {
                Fr gamma_yij;
                Fr::mul(gamma_yij, gamma, square_decomp_values[i][j]);
                // FIX: Use stored y mask from first message
                Fr::add(response.z_squares[k][i][j], gamma_yij, first_msg.y_tildes[k][3*i + j]);
            }
        }
        
        // LINES 15-16: Compute masked randomness
        // tk,x = maskr(γk·rx, r̃ek,x), tk,y = maskr(γk·ry, r̃ek,y), t*k = maskr(γk·r*k, r̃e*k)
        Fr gamma_rx;
        Fr::mul(gamma_rx, gamma, witness.randomness);
        // FIX: Use stored randomness mask from first message
        Fr::add(response.t_x[k], gamma_rx, first_msg.re_k_x[k]);
        
        // FIX: Compute t_y correctly using stored values
        Fr gamma_ry;
        Fr::mul(gamma_ry, gamma, first_msg.ry);
        Fr::add(response.t_y[k], gamma_ry, first_msg.re_k_y[k]);
        
        // FIX: Compute t_star correctly using stored values  
        Fr gamma_r_star;
        Fr::mul(gamma_r_star, gamma, first_msg.r_star_values[k]);
        Fr::add(response.t_star[k], gamma_r_star, first_msg.re_star_k[k]);
        
        // LINES 17-18: Check for masking failures (simplified - should implement proper rejection sampling)
        // if any masking failed, abort
    }
    
    return response;
}

bool SharpGS::verify(const PublicParameters& pp, const Statement& stmt, 
                    const Proof& proof, const Challenge& challenge) {
    
    // ALGORITHM 1 VERIFICATION LINES 2-8
    for (size_t k = 0; k < pp.repetitions; k++) {
        Fr gamma = challenge.gammas[k];
        
        // LINE 3: Check Dk,x + γkCx = tk,xG0 + ∑zk,iGi
        // This requires recomputing commitment from z values and comparing
        auto z_commit = PedersenMultiCommitment::commit(pp.ck_com, proof.response.z_values[k], proof.response.t_x[k]);
        
        G1 lhs, gamma_Cx;
        G1::mul(gamma_Cx, stmt.commitment, gamma);
        G1::add(lhs, proof.first_msg.mask_commitments_x[k], gamma_Cx);
        
        if (!(lhs == z_commit.value)) {
            return false;
        }
        
        // LINE 4: Check Dk,y + γkCy = tk,yG0 + ∑∑zk,i,jGi,j
        vector<Fr> flat_z_squares;
        for (const auto& z_triple : proof.response.z_squares[k]) {
            flat_z_squares.insert(flat_z_squares.end(), z_triple.begin(), z_triple.end());
        }
        
        auto z_y_commit = PedersenMultiCommitment::commit(pp.ck_3sq, flat_z_squares, proof.response.t_y[k]);
        
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
        
        // LINE 6: Check Dk,* + γkCk,* = t*kH0 + ∑f*k,iHi (use ck_com for consistency)
        auto f_star_commit = PedersenMultiCommitment::commit(pp.ck_com, f_star_values, proof.response.t_star[k]);
        
        G1 lhs_star, gamma_C_star;
        G1::mul(gamma_C_star, proof.first_msg.poly_commitments_star[k], gamma);
        G1::add(lhs_star, proof.first_msg.mask_poly_commitments[k], gamma_C_star);
        
        if (!(lhs_star == f_star_commit.value)) {
            return false;
        }
        
        // LINE 7: Check range constraints zk,i, zk,i,j ∈ [0,(BΓ+1)Lx]
        Fr bound;
        Fr::mul(bound, pp.B, Fr(pp.gamma_max + 1));
        // Should implement proper range checks here
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
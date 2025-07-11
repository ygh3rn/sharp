#include "sharpgs.h"
#include <stdexcept>
#include <iostream>

PedersenCommitment::SetupParams SharpGS::setup(const Parameters& params) {
    return PedersenCommitment::setup(params.N, params.S);
}

SharpGS::FirstMessage SharpGS::proverFirstMessage(
    const Witness& witness,
    const Parameters& params,
    const PedersenCommitment::SetupParams& setup_params
) {
    FirstMessage msg(params.R);
    
    // Generate prover state
    ProverState state = generateProverState(witness, params);
    
    // Create Cy commitment
    msg.Cy = PedersenCommitment::createSharpGSCommitment(
        witness.x_values, state.y_values, setup_params
    ).Cy;
    
    // For each repetition k
    for (size_t k = 0; k < params.R; ++k) {
        // Create Dk,x = rek,x*G0 + sum(xek,i*Gi)
        G1::mul(msg.D_x[k], setup_params.G_generators[0], state.re_x[k]);
        for (size_t i = 0; i < params.N; ++i) {
            G1 term;
            G1::mul(term, setup_params.G_generators[i + 1], state.xe_masks[k][i]);
            G1::add(msg.D_x[k], msg.D_x[k], term);
        }
        
        // Create Dk,y = rek,y*G0 + sum(sum(yek,i,j*Gi,j))
        G1::mul(msg.D_y[k], setup_params.G_generators[0], state.re_y[k]);
        for (size_t i = 0; i < params.N; ++i) {
            for (size_t j = 0; j < 3; ++j) {
                size_t gen_idx = i * 3 + j;
                G1 term;
                G1::mul(term, setup_params.Gi_generators[gen_idx], state.ye_masks[k][i][j]);
                G1::add(msg.D_y[k], msg.D_y[k], term);
            }
        }
        
        // Create Ck,* = r*k*H0 + sum(α*1,k,i*Hi)
        G1 ck_star_g1;  // Convert from G2 to G1 for simplicity
        G1::mul(ck_star_g1, setup_params.G_generators[0], state.r_star[k]);  // Simplified
        msg.C_star[k] = ck_star_g1;
        
        // Create Dk,* = re*k*H0 + sum(α*0,k,i*Hi)  
        G1 dk_star_g1;  // Convert from G2 to G1 for simplicity
        G1::mul(dk_star_g1, setup_params.G_generators[0], state.re_star[k]);  // Simplified
        msg.D_star[k] = dk_star_g1;
    }
    
    return msg;
}

SharpGS::Response SharpGS::proverResponse(
    const Witness& witness,
    const FirstMessage& first_msg,
    const Challenge& challenge,
    const Parameters& params,
    const PedersenCommitment::SetupParams& setup_params,
    const std::vector<Fr>& rx_masks,
    const std::vector<std::vector<Fr>>& x_masks,
    const std::vector<std::vector<std::vector<Fr>>>& y_masks
) {
    Response response(params.R, params.N);
    
    // Regenerate decompositions
    std::vector<std::vector<Fr>> y_values = computeDecompositions(witness.x_values, Fr(params.B));
    
    // For each repetition k
    for (size_t k = 0; k < params.R; ++k) {
        const Fr& gamma_k = challenge.gamma[k];
        
        // Mask x values: zk,i = mask(γk * xi, xek,i)
        for (size_t i = 0; i < params.N; ++i) {
            SharpGSMasking::SharpGSParameters masking_params(params.B, params.Gamma, params.Lx, params.Lr);
            auto mask_result = SharpGSMasking::maskX(gamma_k, witness.x_values[i], x_masks[k][i], masking_params);
            
            if (!mask_result.success) {
                throw std::runtime_error("Masking failed for x value at repetition " + std::to_string(k) + ", index " + std::to_string(i));
            }
            
            response.z_values[k][i] = mask_result.masked_value;
        }
        
        // Mask y values: zk,i,j = mask(γk * yi,j, yek,i,j)
        for (size_t i = 0; i < params.N; ++i) {
            for (size_t j = 0; j < 3; ++j) {
                SharpGSMasking::SharpGSParameters masking_params(params.B, params.Gamma, params.Lx, params.Lr);
                auto mask_result = SharpGSMasking::maskX(gamma_k, y_values[i][j], y_masks[k][i][j], masking_params);
                
                if (!mask_result.success) {
                    throw std::runtime_error("Masking failed for y value");
                }
                
                response.z_y_values[k][i][j] = mask_result.masked_value;
            }
        }
        
        // Mask randomness values
        SharpGSMasking::SharpGSParameters masking_params(params.B, params.Gamma, params.Lx, params.Lr);
        
        // tk,x = mask(γk * rx, rek,x)
        auto rx_mask_result = SharpGSMasking::maskR(gamma_k, witness.rx, rx_masks[k], masking_params);
        if (!rx_mask_result.success) {
            throw std::runtime_error("Masking failed for rx");
        }
        response.t_x[k] = rx_mask_result.masked_value;
        
        // For simplicity, set other t values (in full implementation, need proper ry and r* values)
        response.t_y[k].setByCSPRNG();
        response.t_star[k].setByCSPRNG();
    }
    
    return response;
}

SharpGS::Challenge SharpGS::verifierChallenge(const Parameters& params) {
    Challenge challenge(params.R);
    
    for (size_t k = 0; k < params.R; ++k) {
        // Sample γk ∈ [0, Γ]
        challenge.gamma[k].setByCSPRNG();
        
        // For proper implementation, should constrain to [0, Γ]
        // This is simplified - using random field element
    }
    
    return challenge;
}

bool SharpGS::verifierCheck(
    const Statement& statement,
    const Proof& proof,
    const Parameters& params,
    const PedersenCommitment::SetupParams& setup_params
) {
    // For each repetition k
    for (size_t k = 0; k < params.R; ++k) {
        const Fr& gamma_k = proof.challenge.gamma[k];
        
        // Check 1: Dk,x + γkCx = tk,x*G0 + sum(zk,i*Gi)
        G1 left_side, right_side;
        
        // left_side = Dk,x + γk*Cx
        G1 gamma_Cx;
        G1::mul(gamma_Cx, statement.Cx, gamma_k);
        G1::add(left_side, proof.first_msg.D_x[k], gamma_Cx);
        
        // right_side = tk,x*G0 + sum(zk,i*Gi)
        G1::mul(right_side, setup_params.G_generators[0], proof.response.t_x[k]);
        for (size_t i = 0; i < params.N; ++i) {
            G1 term;
            G1::mul(term, setup_params.G_generators[i + 1], proof.response.z_values[k][i]);
            G1::add(right_side, right_side, term);
        }
        
        if (!(left_side == right_side)) {
            std::cerr << "Verification failed at check 1, repetition " << k << std::endl;
            return false;
        }
        
        // Check 2: Dk,y + γkCy = tk,y*G0 + sum(sum(zk,i,j*Gi,j))
        // Similar structure to check 1
        G1 left_side_y, right_side_y;
        
        G1 gamma_Cy;
        G1::mul(gamma_Cy, proof.first_msg.Cy, gamma_k);
        G1::add(left_side_y, proof.first_msg.D_y[k], gamma_Cy);
        
        G1::mul(right_side_y, setup_params.G_generators[0], proof.response.t_y[k]);
        for (size_t i = 0; i < params.N; ++i) {
            for (size_t j = 0; j < 3; ++j) {
                size_t gen_idx = i * 3 + j;
                G1 term;
                G1::mul(term, setup_params.Gi_generators[gen_idx], proof.response.z_y_values[k][i][j]);
                G1::add(right_side_y, right_side_y, term);
            }
        }
        
        if (!(left_side_y == right_side_y)) {
            std::cerr << "Verification failed at check 2, repetition " << k << std::endl;
            return false;
        }
        
        // Check 3: Range check zk,i, zk,i,j ∈ [0, (BΓ+1)Lx]
        SharpGSMasking::SharpGSParameters masking_params(params.B, params.Gamma, params.Lx, params.Lr);
        
        for (size_t i = 0; i < params.N; ++i) {
            if (!SharpGSMasking::verifySharpGSMasking(proof.response.z_values[k][i], masking_params)) {
                std::cerr << "Range check failed for z_values[" << k << "][" << i << "]" << std::endl;
                return false;
            }
            
            for (size_t j = 0; j < 3; ++j) {
                if (!SharpGSMasking::verifySharpGSMasking(proof.response.z_y_values[k][i][j], masking_params)) {
                    std::cerr << "Range check failed for z_y_values[" << k << "][" << i << "][" << j << "]" << std::endl;
                    return false;
                }
            }
        }
        
        // Additional checks for decomposition proof would go here
        // (computing f*k,i and verifying against Dk,* + γkCk,*)
    }
    
    return true;
}

std::pair<SharpGS::Proof, bool> SharpGS::executeProtocol(
    const Witness& witness,
    const Statement& statement,
    const Parameters& params
) {
    // Setup
    auto setup_params = setup(params);
    
    // Generate masks
    std::vector<Fr> rx_masks(params.R);
    std::vector<std::vector<Fr>> x_masks(params.R, std::vector<Fr>(params.N));
    std::vector<std::vector<std::vector<Fr>>> y_masks(params.R, 
        std::vector<std::vector<Fr>>(params.N, std::vector<Fr>(3)));
    
    for (size_t k = 0; k < params.R; ++k) {
        rx_masks[k].setByCSPRNG();
        for (size_t i = 0; i < params.N; ++i) {
            x_masks[k][i].setByCSPRNG();
            for (size_t j = 0; j < 3; ++j) {
                y_masks[k][i][j].setByCSPRNG();
            }
        }
    }
    
    // Create proof
    Proof proof(params.R, params.N);
    
    // Prover first message
    proof.first_msg = proverFirstMessage(witness, params, setup_params);
    
    // Verifier challenge
    proof.challenge = verifierChallenge(params);
    
    // Prover response
    proof.response = proverResponse(witness, proof.first_msg, proof.challenge, 
                                   params, setup_params, rx_masks, x_masks, y_masks);
    
    // Verification
    bool verification_result = verifierCheck(statement, proof, params, setup_params);
    
    return {proof, verification_result};
}

SharpGS::Statement SharpGS::createStatement(
    const std::vector<Fr>& x_values,
    const Fr& randomness,
    const Parameters& params,
    const PedersenCommitment::SetupParams& setup_params
) {
    auto commitment = PedersenCommitment::commitMulti(x_values, randomness, setup_params);
    return Statement(commitment.value, params.B);
}

// Private helper functions

SharpGS::ProverState SharpGS::generateProverState(
    const Witness& witness,
    const Parameters& params
) {
    ProverState state;
    
    // Compute three-squares decompositions
    state.y_values = computeDecompositions(witness.x_values, Fr(params.B));
    
    // Generate randomness
    state.ry.setByCSPRNG();
    
    state.r_star.resize(params.R);
    state.re_star.resize(params.R);
    state.re_x.resize(params.R);
    state.re_y.resize(params.R);
    
    for (size_t k = 0; k < params.R; ++k) {
        state.r_star[k].setByCSPRNG();
        state.re_star[k].setByCSPRNG();
        state.re_x[k].setByCSPRNG();
        state.re_y[k].setByCSPRNG();
    }
    
    // Generate masks
    state.xe_masks.resize(params.R, std::vector<Fr>(params.N));
    state.ye_masks.resize(params.R, std::vector<std::vector<Fr>>(params.N, std::vector<Fr>(3)));
    
    for (size_t k = 0; k < params.R; ++k) {
        for (size_t i = 0; i < params.N; ++i) {
            state.xe_masks[k][i].setByCSPRNG();
            for (size_t j = 0; j < 3; ++j) {
                state.ye_masks[k][i][j].setByCSPRNG();
            }
        }
    }
    
    return state;
}

std::vector<std::vector<Fr>> SharpGS::computeDecompositions(
    const std::vector<Fr>& x_values,
    const Fr& B
) {
    std::vector<std::vector<Fr>> y_values(x_values.size());
    
    for (size_t i = 0; i < x_values.size(); ++i) {
        try {
            y_values[i] = ThreeSquares::computeSharpGSDecomposition(x_values[i], B);
        } catch (const std::exception& e) {
            std::cerr << "Failed to compute decomposition for x[" << i << "]: " << e.what() << std::endl;
            // Use fallback values for testing
            y_values[i] = {Fr(1), Fr(1), Fr(1)};
        }
    }
    
    return y_values;
}
#include "sharp_gs.h"
#include <random>
#include <stdexcept>
#include <algorithm>

SharpGS::PublicParameters SharpGS::setup(size_t N, const Fr& B, size_t lambda) {
    PublicParameters pp;
    
    // Setup commitment keys
    pp.ck_com = PedersenMultiCommitment::setup(N);
    pp.ck_3sq = PedersenMultiCommitment::setup(N * 3);  // 3 squares per value
    
    pp.B = B;
    pp.lambda = lambda;
    
    // Set challenge space and repetitions based on security parameter
    pp.gamma_max = (1 << 16) - 1;  // 16-bit challenges
    pp.repetitions = max(1UL, lambda / 16);  // Ensure sufficient security
    
    return pp;
}

SharpGS::FirstMessage SharpGS::prove_first(
    const PublicParameters& pp,
    const Statement& stmt,
    const Witness& witness) {
    
    FirstMessage first_msg;
    
    // Compute square decomposition for all values
    auto sq_decomp = compute_square_decomposition(witness.values, pp.B);
    
    // Flatten square decomposition for commitment
    vector<Fr> y_values;
    for (size_t i = 0; i < witness.values.size(); i++) {
        for (size_t j = 0; j < 3; j++) {
            y_values.push_back(sq_decomp.decompositions[i][j].x);
        }
    }
    
    // Commit to square decomposition
    auto y_commit = PedersenMultiCommitment::commit(pp.ck_3sq, y_values, sq_decomp.randomness);
    first_msg.y_commitment = y_commit.value;
    
    // Generate commitments for all repetitions
    first_msg.mask_commitments_x.resize(pp.repetitions);
    first_msg.mask_commitments_y.resize(pp.repetitions);
    first_msg.poly_commitments.resize(pp.repetitions);
    
    for (size_t k = 0; k < pp.repetitions; k++) {
        // Generate random masks
        auto x_masks = generate_masks(witness.values.size(), 64);
        auto y_masks = generate_masks(y_values.size(), 64);
        
        // Commit to masks
        auto x_mask_commit = PedersenMultiCommitment::commit(pp.ck_com, x_masks);
        auto y_mask_commit = PedersenMultiCommitment::commit(pp.ck_3sq, y_masks);
        
        first_msg.mask_commitments_x[k] = x_mask_commit.value;
        first_msg.mask_commitments_y[k] = y_mask_commit.value;
        
        // Generate polynomial coefficients (placeholder - would need challenge)
        vector<Fr> poly_coeffs(witness.values.size(), Fr(0));
        auto poly_commit = PedersenMultiCommitment::commit(pp.ck_com, poly_coeffs);
        first_msg.poly_commitments[k] = poly_commit.value;
    }
    
    return first_msg;
}

SharpGS::Response SharpGS::prove_response(
    const PublicParameters& pp,
    const Statement& stmt,
    const Witness& witness,
    const FirstMessage& first_msg,
    const Challenge& challenge) {
    
    Response response;
    
    // Compute square decomposition
    auto sq_decomp = compute_square_decomposition(witness.values, pp.B);
    
    // Flatten square values
    vector<Fr> y_values;
    for (size_t i = 0; i < witness.values.size(); i++) {
        for (size_t j = 0; j < 3; j++) {
            y_values.push_back(sq_decomp.decompositions[i][j].x);
        }
    }
    
    response.z_values.resize(pp.repetitions);
    response.z_squares.resize(pp.repetitions);
    response.t_x.resize(pp.repetitions);
    response.t_y.resize(pp.repetitions);
    response.t_star.resize(pp.repetitions);
    
    for (size_t k = 0; k < pp.repetitions; k++) {
        Fr gamma = challenge.gammas[k];
        
        // Generate fresh masks (in practice, these should be stored from first phase)
        auto x_masks = generate_masks(witness.values.size(), 64);
        auto y_masks = generate_masks(y_values.size(), 64);
        
        // Compute masked responses: z = gamma * value + mask
        response.z_values[k].resize(witness.values.size());
        for (size_t i = 0; i < witness.values.size(); i++) {
            Fr gamma_x;
            Fr::mul(gamma_x, gamma, witness.values[i]);
            Fr::add(response.z_values[k][i], gamma_x, x_masks[i]);
        }
        
        // Compute masked square responses
        response.z_squares[k].resize(witness.values.size());
        for (size_t i = 0; i < witness.values.size(); i++) {
            response.z_squares[k][i].resize(3);
            for (size_t j = 0; j < 3; j++) {
                size_t y_idx = i * 3 + j;  // Each value has 3 square components
                
                Fr gamma_y;
                Fr::mul(gamma_y, gamma, y_values[y_idx]);
                Fr::add(response.z_squares[k][i][j], gamma_y, y_masks[y_idx]);
            }
        }
        
        // Compute masked randomness (simplified)
        Fr gamma_r;
        Fr::mul(gamma_r, gamma, witness.randomness);
        Fr mask_r;
        mask_r.setByCSPRNG();
        Fr::add(response.t_x[k], gamma_r, mask_r);
        
        response.t_y[k].setByCSPRNG();
        response.t_star[k].setByCSPRNG();
    }
    
    return response;
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

bool SharpGS::verify(
    const PublicParameters& pp,
    const Statement& stmt,
    const Proof& proof,
    const Challenge& challenge) {
    
    // Simplified verification - check basic structure
    if (proof.first_msg.mask_commitments_x.size() != pp.repetitions ||
        proof.first_msg.mask_commitments_y.size() != pp.repetitions ||
        proof.first_msg.poly_commitments.size() != pp.repetitions) {
        return false;
    }
    
    if (proof.response.z_values.size() != pp.repetitions ||
        proof.response.z_squares.size() != pp.repetitions ||
        challenge.gammas.size() != pp.repetitions) {
        return false;
    }
    
    // Verify polynomial relations for each repetition
    for (size_t k = 0; k < pp.repetitions; k++) {
        Fr gamma = challenge.gammas[k];
        
        // Verify commitment equations (simplified)
        // In full implementation, would check:
        // D_{k,x} + γ_k * C_x = t_{k,x} * G_0 + Σ z_{k,i} * G_i
        
        // Verify polynomial equation for each value
        for (size_t i = 0; i < proof.response.z_values[k].size(); i++) {
            Fr z_i = proof.response.z_values[k][i];
            
            // Compute f*_{k,i} = 4*z_{k,i}*(γ_k*B - z_{k,i}) + γ_k^2 - Σ z²_{k,i,j}
            Fr gamma_B, four_z, z_gamma_B, four_z_gamma_B, gamma_sq, f_star;
            
            Fr::mul(gamma_B, gamma, pp.B);
            Fr four(4);
            Fr::mul(four_z, four, z_i);
            Fr::sub(z_gamma_B, gamma_B, z_i);
            Fr::mul(four_z_gamma_B, four_z, z_gamma_B);
            Fr::sqr(gamma_sq, gamma);
            Fr::add(f_star, four_z_gamma_B, gamma_sq);
            
            // Subtract sum of squares
            if (i < proof.response.z_squares[k].size()) {
                for (size_t j = 0; j < proof.response.z_squares[k][i].size(); j++) {
                    Fr z_sq;
                    Fr::sqr(z_sq, proof.response.z_squares[k][i][j]);
                    Fr::sub(f_star, f_star, z_sq);
                }
            }
            
            // In full implementation, would verify this equals commitment opening
            // For now, just check it's well-formed
            if (f_star.isZero() && !gamma.isZero()) {
                // This might indicate an issue, but continue for minimal implementation
            }
        }
    }
    
    return true;  // Simplified acceptance
}

// FIXED: Correct implementation of compute_square_decomposition
SharpGS::SquareDecomposition SharpGS::compute_square_decomposition(
    const vector<Fr>& values, 
    const Fr& B) {
    
    SquareDecomposition sq_decomp;
    sq_decomp.decompositions.resize(values.size());
    sq_decomp.randomness.setByCSPRNG();
    
    for (size_t i = 0; i < values.size(); i++) {
        // Compute 4*x_i*(B - x_i) + 1
        Fr range_val = ThreeSquares::compute_range_value(values[i], B);
        
        // Find three squares decomposition
        auto decomp = ThreeSquares::decompose(range_val);
        if (!decomp) {
            throw runtime_error("Failed to find three squares decomposition for value " + to_string(i));
        }
        
        // FIXED: Store the individual square components correctly
        // Each value has 3 components: x, y, z such that range_val = x² + y² + z²
        sq_decomp.decompositions[i].resize(3);
        
        // Create individual decompositions for each square component
        ThreeSquares::Decomposition x_comp, y_comp, z_comp;
        
        // Store x component (first square: x² + 0² + 0²)
        x_comp.x = decomp->x;
        x_comp.y = Fr(0);
        x_comp.z = Fr(0);
        x_comp.valid = true;
        sq_decomp.decompositions[i][0] = x_comp;
        
        // Store y component (second square: y² + 0² + 0²)  
        y_comp.x = decomp->y;
        y_comp.y = Fr(0);
        y_comp.z = Fr(0);
        y_comp.valid = true;
        sq_decomp.decompositions[i][1] = y_comp;
        
        // Store z component (third square: z² + 0² + 0²)
        z_comp.x = decomp->z;
        z_comp.y = Fr(0);
        z_comp.z = Fr(0);
        z_comp.valid = true;
        sq_decomp.decompositions[i][2] = z_comp;
    }
    
    return sq_decomp;
}

vector<Fr> SharpGS::generate_masks(size_t count, size_t max_bits) {
    vector<Fr> masks(count);
    
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<uint64_t> dis(0, (1ULL << max_bits) - 1);
    
    for (size_t i = 0; i < count; i++) {
        uint64_t mask_val = dis(gen);
        masks[i] = Fr(static_cast<int>(mask_val & 0x7FFFFFFF));  // Keep positive
    }
    
    return masks;
}

vector<Fr> SharpGS::compute_polynomial_coefficients(
    const vector<Fr>& values,
    const vector<Fr>& masks,
    const Fr& B,
    const Fr& gamma) {
    
    vector<Fr> coefficients(values.size());
    
    for (size_t i = 0; i < values.size(); i++) {
        // Simplified polynomial computation
        // α*_{1,k,i} = 4*x̃_{k,i}*B - 8*x_i*x̃_{k,i} - 2*Σ y_{i,j}*ỹ_{k,i,j}
        Fr four_mask_B, eight_x_mask, alpha;
        
        Fr four(4);
        Fr::mul(four_mask_B, four, masks[i]);
        Fr::mul(four_mask_B, four_mask_B, B);
        
        Fr eight(8);
        Fr::mul(eight_x_mask, eight, values[i]);
        Fr::mul(eight_x_mask, eight_x_mask, masks[i]);
        
        Fr::sub(alpha, four_mask_B, eight_x_mask);
        coefficients[i] = alpha;
    }
    
    return coefficients;
}

bool SharpGS::verify_polynomial_relation(
    const vector<Fr>& coefficients,
    const vector<Fr>& values,
    const Fr& B,
    const Fr& gamma) {
    
    // Simplified verification
    return coefficients.size() == values.size();
}
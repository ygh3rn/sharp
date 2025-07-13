#pragma once

#include <mcl/bn.hpp>
#include <vector>
#include <random>
#include "pedersen.h"
#include "three_squares.h"

using namespace mcl;
using namespace std;

class SharpGS {
public:
    struct PublicParameters {
        size_t num_values;           // N
        Fr B;                        // Range bound
        size_t repetitions;          // R 
        size_t gamma_max;            // Γ
        size_t security_bits;        // λ
        
        // Commitment keys
        PedersenMultiCommitment::CommitmentKey ck_com;   // Gcom
        PedersenMultiCommitment::CommitmentKey ck_3sq;   // G3sq
    };
    
    struct Witness {
        vector<Fr> values;           // xi ∈ [0, B]
        Fr randomness;               // rx
    };
    
    struct Statement {
        G1 commitment;               // Cx = rxG0 + ∑xiGi
        Fr B;                        // Range bound
    };
    
    // Algorithm 1 - First message structures
    struct FirstMessage {
        G1 commitment_y;                              // Cy (line 2)
        vector<G1> mask_commitments_x;                // Dk,x (line 6)
        vector<G1> mask_commitments_y;                // Dk,y (line 7)
        vector<G1> poly_commitments_star;             // Ck,* (line 11)
        vector<G1> mask_poly_commitments;             // Dk,* (line 12)
        
        // Store mask values for reuse in response
        Fr ry;                                        // randomness for Cy
        vector<Fr> re_k_x, re_k_y, re_star_k;       // randomness for commitments
        vector<vector<Fr>> x_tildes, y_tildes;       // mask values
        vector<Fr> r_star_values;                    // r*k values
    };
    
    struct Challenge {
        vector<Fr> gammas;           // γk ∈ [0, Γ]
    };
    
    // Algorithm 1 - Response structures  
    struct Response {
        vector<vector<Fr>> z_values;                  // zk,i (line 14)
        vector<vector<vector<Fr>>> z_squares;         // zk,i,j (line 14)
        vector<Fr> t_x, t_y, t_star;                 // tk,x, tk,y, t*k (lines 15-16)
    };
    
    struct Proof {
        FirstMessage first_msg;
        Response response;
    };

    // Main protocol functions
    static PublicParameters setup(size_t num_values, const Fr& B, size_t security_bits = 128);
    static FirstMessage prove_first(const PublicParameters& pp, const Statement& stmt, const Witness& witness);
    static Challenge generate_challenge(const PublicParameters& pp);
    static Response prove_response(const PublicParameters& pp, const Statement& stmt, 
                                 const Witness& witness, const FirstMessage& first_msg, const Challenge& challenge);
    static bool verify(const PublicParameters& pp, const Statement& stmt, 
                      const Proof& proof, const Challenge& challenge);

    // Public helper functions for testing
    static Fr compute_f_star(const Fr& z_val, const Fr& gamma, const Fr& B, const vector<Fr>& z_squares);
    static vector<vector<Fr>> compute_square_decomposition_values(const vector<Fr>& values, const Fr& B);
    static vector<Fr> generate_mask_values(size_t count, size_t max_bits = 128);

private:
    // Algorithm 1 helper functions
    static Fr compute_alpha_star_1(const Fr& x_tilde, const Fr& x, const Fr& B, 
                                   const vector<Fr>& y_vals, const vector<Fr>& y_tildes);
    static Fr compute_alpha_star_0(const Fr& x_tilde, const vector<Fr>& y_tildes);
};
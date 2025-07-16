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
        size_t num_values;
        Fr B;
        size_t repetitions;
        size_t gamma_max;
        size_t security_bits;
        
        PedersenMultiCommitment::CommitmentKey ck_com;
        PedersenMultiCommitment::CommitmentKey ck_3sq;
    };
    
    struct Witness {
        vector<Fr> values;
        Fr randomness;
    };
    
    struct Statement {
        G1 commitment;
        Fr B;
    };
    
    struct FirstMessage {
        G1 commitment_y;
        vector<G1> mask_commitments_x;
        vector<G1> mask_commitments_y;
        vector<G1> poly_commitments_star;
        vector<G1> mask_poly_commitments;
        Fr ry;
        vector<Fr> re_k_x, re_k_y, re_star_k;
        vector<vector<Fr>> x_tildes, y_tildes;
        vector<Fr> r_star_values;
    };
    
    struct Challenge {
        vector<Fr> gammas;
    };
    
    struct Response {
        vector<vector<Fr>> z_values;
        vector<vector<vector<Fr>>> z_squares;
        vector<Fr> t_x, t_y, t_star;
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
    static Fr compute_alpha_star_1(const Fr& x_tilde, const Fr& x, const Fr& B, 
                                   const vector<Fr>& y_vals, const vector<Fr>& y_tildes);
    static Fr compute_alpha_star_0(const Fr& x_tilde, const vector<Fr>& y_tildes);
    static Fr compute_f_star(const Fr& z_val, const Fr& gamma, const Fr& B, const vector<Fr>& z_squares);
    static vector<vector<Fr>> compute_square_decomposition_values(const vector<Fr>& values, const Fr& B);
    static vector<Fr> generate_mask_values(size_t count, size_t max_bits = 128);
};
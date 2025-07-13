#pragma once

#include <mcl/bn.hpp>
#include <vector>
#include "pedersen.h"
#include "three_squares.h"

using namespace mcl;
using namespace std;

class SharpGS {
public:
    struct PublicParameters {
        PedersenMultiCommitment::CommitmentKey ck_com;  // Commitment group
        PedersenMultiCommitment::CommitmentKey ck_3sq;  // 3-square group
        Fr B;                                            // Range bound [0, B]
        size_t gamma_max;                               // Challenge space [0, gamma_max]
        size_t lambda;                                  // Security parameter
        size_t repetitions;                             // Number of repetitions R
    };
    
    struct Witness {
        vector<Fr> values;      // x1, ..., xN ∈ [0, B]
        Fr randomness;          // Commitment randomness
    };
    
    struct Statement {
        G1 commitment;          // Commitment to values
        Fr B;                   // Range bound
    };
    
    struct FirstMessage {
        G1 y_commitment;        // Commitment to square decomposition
        vector<G1> mask_commitments_x;  // Masked value commitments
        vector<G1> mask_commitments_y;  // Masked square commitments  
        vector<G1> poly_commitments;    // Polynomial coefficient commitments
    };
    
    struct Challenge {
        vector<Fr> gammas;      // Random challenges γ1, ..., γR
    };
    
    struct Response {
        vector<vector<Fr>> z_values;    // Masked values z_{k,i}
        vector<vector<vector<Fr>>> z_squares;  // Masked squares z_{k,i,j}
        vector<Fr> t_x, t_y, t_star;   // Masked randomness
    };
    
    struct Proof {
        FirstMessage first_msg;
        Response response;
    };
    
    // Setup phase - generate public parameters
    static PublicParameters setup(size_t N, const Fr& B, size_t lambda = 128);
    
    // Prover - generate first message
    static FirstMessage prove_first(const PublicParameters& pp,
                                  const Statement& stmt,
                                  const Witness& witness);
    
    // Prover - generate response to challenge
    static Response prove_response(const PublicParameters& pp,
                                 const Statement& stmt,
                                 const Witness& witness,
                                 const FirstMessage& first_msg,
                                 const Challenge& challenge);
    
    // Verifier - generate random challenge
    static Challenge generate_challenge(const PublicParameters& pp);
    
    // Verifier - verify proof
    static bool verify(const PublicParameters& pp,
                      const Statement& stmt,
                      const Proof& proof,
                      const Challenge& challenge);
    
private:
    struct SquareDecomposition {
        vector<vector<ThreeSquares::Decomposition>> decompositions;  // y_{i,j} for each x_i
        Fr randomness;
    };
    
    // Compute three-square decomposition for all values
    static SquareDecomposition compute_square_decomposition(const vector<Fr>& values, const Fr& B);
    
    // Generate random masks for zero-knowledge
    static vector<Fr> generate_masks(size_t count, size_t max_bits);
    
    // Compute polynomial coefficients for decomposition proof
    static vector<Fr> compute_polynomial_coefficients(const vector<Fr>& values,
                                                     const vector<Fr>& masks,
                                                     const Fr& B,
                                                     const Fr& gamma);
    
    // Verify polynomial relation
    static bool verify_polynomial_relation(const vector<Fr>& coefficients,
                                          const vector<Fr>& values,
                                          const Fr& B,
                                          const Fr& gamma);
};
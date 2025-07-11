#pragma once

#include "commitment.h"
#include "masking.h"
#include "three_squares.h"
#include <mcl/bn.hpp>
#include <vector>
#include <memory>

using namespace mcl;

class SharpGS {
public:
    // Protocol parameters
    struct Parameters {
        size_t N;           // Number of values to prove
        size_t B;           // Range bound [0, B]
        size_t Gamma;       // Challenge space [0, Gamma]
        size_t R;           // Number of repetitions
        size_t S;           // Hiding parameter
        size_t Lx, Lr;      // Masking overheads
        
        Parameters(size_t N_ = 1, size_t B_ = 64, size_t Gamma_ = 128, size_t R_ = 1, 
                  size_t S_ = 256, size_t Lx_ = 10, size_t Lr_ = 10)
            : N(N_), B(B_), Gamma(Gamma_), R(R_), S(S_), Lx(Lx_), Lr(Lr_) {}
    };
    
    // Prover's witness
    struct Witness {
        std::vector<Fr> x_values;              // xi ∈ [0, B]
        Fr rx;                                 // Randomness for Cx
        
        Witness(const std::vector<Fr>& x_vals, const Fr& rx_val) 
            : x_values(x_vals), rx(rx_val) {}
    };
    
    // Public statement
    struct Statement {
        G1 Cx;                                 // Commitment to x_values
        size_t B;                              // Range bound
        
        Statement(const G1& Cx_, size_t B_) : Cx(Cx_), B(B_) {}
    };
    
    // First message from prover
    struct FirstMessage {
        G1 Cy;                                 // Commitment to yi,j values
        std::vector<G1> C_star;                // Ck,* commitments (R elements)
        std::vector<G1> D_x, D_y, D_star;     // Dk,x, Dk,y, Dk,* commitments (R elements each)
        
        FirstMessage(size_t R) {
            C_star.resize(R);
            D_x.resize(R);
            D_y.resize(R); 
            D_star.resize(R);
        }
    };
    
    // Challenge from verifier
    struct Challenge {
        std::vector<Fr> gamma;                 // γk ∈ [0, Γ] for k ∈ [1, R]
        
        Challenge(size_t R) : gamma(R) {}
    };
    
    // Response from prover
    struct Response {
        std::vector<std::vector<Fr>> z_values;     // zk,i values [R][N]
        std::vector<std::vector<std::vector<Fr>>> z_y_values; // zk,i,j values [R][N][3]
        std::vector<Fr> t_x, t_y, t_star;         // tk,x, tk,y, t*k values [R]
        
        Response(size_t R, size_t N) {
            z_values.resize(R, std::vector<Fr>(N));
            z_y_values.resize(R, std::vector<std::vector<Fr>>(N, std::vector<Fr>(3)));
            t_x.resize(R);
            t_y.resize(R);
            t_star.resize(R);
        }
    };
    
    // Complete proof
    struct Proof {
        FirstMessage first_msg;
        Challenge challenge; 
        Response response;
        
        Proof(size_t R, size_t N) : first_msg(R), challenge(R), response(R, N) {}
    };
    
    // Setup and key generation
    static PedersenCommitment::SetupParams setup(const Parameters& params);
    
    // Prover algorithms
    static FirstMessage proverFirstMessage(
        const Witness& witness,
        const Parameters& params,
        const PedersenCommitment::SetupParams& setup_params
    );
    
    static Response proverResponse(
        const Witness& witness,
        const FirstMessage& first_msg,
        const Challenge& challenge,
        const Parameters& params,
        const PedersenCommitment::SetupParams& setup_params,
        const std::vector<Fr>& rx_masks,           // Masks used in first message
        const std::vector<std::vector<Fr>>& x_masks,  // xe_{k,i} masks [R][N]
        const std::vector<std::vector<std::vector<Fr>>>& y_masks  // ye_{k,i,j} masks [R][N][3]
    );
    
    // Verifier algorithms
    static Challenge verifierChallenge(const Parameters& params);
    
    static bool verifierCheck(
        const Statement& statement,
        const Proof& proof,
        const Parameters& params,
        const PedersenCommitment::SetupParams& setup_params
    );
    
    // Complete protocol execution
    static std::pair<Proof, bool> executeProtocol(
        const Witness& witness,
        const Statement& statement,
        const Parameters& params
    );
    
    // Utility functions
    static Statement createStatement(
        const std::vector<Fr>& x_values,
        const Fr& randomness,
        const Parameters& params,
        const PedersenCommitment::SetupParams& setup_params
    );
    
private:
    // Internal helper functions
    struct ProverState {
        std::vector<std::vector<Fr>> y_values;     // yi,j decomposition values [N][3]
        Fr ry;                                     // randomness for Cy
        std::vector<Fr> r_star;                    // r*k values [R]
        std::vector<Fr> re_star;                   // re*k values [R]
        std::vector<Fr> re_x, re_y;                // rek,x, rek,y values [R]
        std::vector<std::vector<Fr>> xe_masks;     // xek,i masks [R][N]
        std::vector<std::vector<std::vector<Fr>>> ye_masks; // yek,i,j masks [R][N][3]
    };
    
    static ProverState generateProverState(
        const Witness& witness,
        const Parameters& params
    );
    
    static std::vector<std::vector<Fr>> computeDecompositions(
        const std::vector<Fr>& x_values,
        const Fr& B
    );
};
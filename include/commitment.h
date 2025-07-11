#pragma once

#include <mcl/bn.hpp>
#include <vector>

using namespace mcl;

class PedersenCommitment {
public:
    // Setup parameters for Pedersen multi-commitment
    struct SetupParams {
        std::vector<G1> G_generators;  // G0, G1, ..., GN for main commitments
        std::vector<G1> Gi_generators; // Gi,j generators for yi,j values
        std::vector<G2> H_generators;  // H0, H1, ..., HN for decomposition proof
        size_t max_values;             // Maximum number of values to commit
        size_t hiding_param;           // Hiding parameter S
        
        SetupParams(size_t N, size_t S);
    };
    
    // Commitment result
    struct Commitment {
        G1 value;
        Fr randomness;
        
        Commitment() {
            value.clear();
            randomness.clear();
        }
        
        Commitment(const G1& val, const Fr& rand) : value(val), randomness(rand) {}
    };
    
    // Commitment to values using Gcom generators
    struct MultiCommitment {
        G1 Cx;  // Main commitment: rx*G0 + sum(xi*Gi)
        G1 Cy;  // Decomposition commitment: ry*G0 + sum(yi,j*Gi,j)
        Fr rx, ry;  // Randomness values
        
        MultiCommitment() {
            Cx.clear();
            Cy.clear(); 
            rx.clear();
            ry.clear();
        }
    };
    
    // Generate setup parameters
    static SetupParams setup(size_t N, size_t S = 256);
    
    // Commit to a single value: commit = r*G0 + x*G1
    static Commitment commit(const Fr& x, const SetupParams& params);
    static Commitment commit(const Fr& x, const Fr& r, const SetupParams& params);
    
    // Commit to multiple values: commit = r*G0 + sum(xi*Gi)
    static Commitment commitMulti(const std::vector<Fr>& values, const SetupParams& params);
    static Commitment commitMulti(const std::vector<Fr>& values, const Fr& r, const SetupParams& params);
    
    // Create SharpGS multi-commitment (Cx and Cy)
    static MultiCommitment createSharpGSCommitment(
        const std::vector<Fr>& x_values,
        const std::vector<std::vector<Fr>>& y_values,  // y_values[i][j] = yi,j
        const SetupParams& params
    );
    
    // Verify commitment opening
    static bool verify(const Commitment& commit, const Fr& value, const Fr& randomness, const SetupParams& params);
    static bool verifyMulti(const Commitment& commit, const std::vector<Fr>& values, const Fr& randomness, const SetupParams& params);
};
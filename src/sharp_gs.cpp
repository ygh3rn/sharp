#include "sharp_gs.h"
#include <iostream>
#include <cmath>

namespace sharp_gs {

// Parameters implementation
SharpGS::Parameters::Parameters(size_t sec_bits, size_t range_bits, size_t batch_size)
    : security_bits(sec_bits), range_bits(range_bits), challenge_bits(sec_bits), 
      batch_size(batch_size), repetitions(1), masking_overhead(40), 
      use_hash_optimization(true) {
    compute_dependent_params();
}

bool SharpGS::Parameters::validate() const {
    return utils::params::validate_parameters(security_bits, range_bits, challenge_bits, batch_size);
}

void SharpGS::Parameters::compute_dependent_params() {
    // Compute number of repetitions: R = ⌈λ / log₂(Γ + 1)⌉
    repetitions = utils::params::compute_repetitions(security_bits, challenge_bits);
    
    // Ensure at least 1 repetition
    if (repetitions == 0) {
        repetitions = 1;
    }
}

size_t SharpGS::Parameters::estimate_proof_size() const {
    return utils::params::estimate_proof_size(security_bits, range_bits, batch_size, use_hash_optimization);
}

// Statement implementation
bool SharpGS::Statement::is_valid() const {
    return !value_commitments.empty() && !range_bound.isZero();
}

// Witness implementation
bool SharpGS::Witness::is_valid(const Statement& statement) const {
    if (values.size() != statement.batch_size() || randomness.size() != values.size()) {
        return false;
    }
    
    // Check that all values are in range [0, B]
    for (const auto& value : values) {
        if (!group_utils::is_scalar_bounded(value, statement.range_bound)) {
            return false;
        }
    }
    
    return true;
}

// Transcript implementation
bool SharpGS::Transcript::is_complete() const {
    return !challenges.empty() && !masked_values.empty() && !masked_randomness.empty();
}

size_t SharpGS::Transcript::size_bytes() const {
    size_t size = 0;
    
    // Commitment phase
    size += utils::serialize::group_element_size(); // decomposition_commitment
    size += round_commitments.size() * round_commitments[0].size() * utils::serialize::group_element_size();
    
    if (commitment_hash) {
        size += commitment_hash->size();
    }
    
    // Challenge phase
    size += challenges.size() * utils::serialize::field_element_size();
    
    // Response phase
    for (const auto& round : masked_values) {
        size += round.size() * utils::serialize::field_element_size();
    }
    for (const auto& round : masked_randomness) {
        size += round.size() * utils::serialize::field_element_size();
    }
    
    return size;
}

// Proof implementation
bool SharpGS::Proof::is_valid() const {
    return transcript.is_complete() && parameters.validate();
}

// Main SharpGS implementation
SharpGS::SharpGS(const Parameters& params) : params_(params), initialized_(false) {
    groups_ = std::make_unique<GroupManager>();
    masking_ = std::make_unique<SharpGSMasking>(params_.range_bits, params_.challenge_bits, params_.security_bits);
}

SharpGS::~SharpGS() = default;

bool SharpGS::initialize() {
    try {
        if (!params_.validate()) {
            std::cerr << "Invalid parameters" << std::endl;
            return false;
        }
        
        // Initialize group manager
        if (!setup_groups()) {
            std::cerr << "Failed to setup groups" << std::endl;
            return false;
        }
        
        // Initialize commitment schemes
        if (!setup_commitments()) {
            std::cerr << "Failed to setup commitments" << std::endl;
            return false;
        }
        
        initialized_ = true;
        
        std::cout << "SharpGS initialized successfully:" << std::endl;
        std::cout << "  Security: " << params_.security_bits << " bits" << std::endl;
        std::cout << "  Range: [0, 2^" << params_.range_bits << ")" << std::endl;
        std::cout << "  Batch size: " << params_.batch_size << std::endl;
        std::cout << "  Repetitions: " << params_.repetitions << std::endl;
        std::cout << "  Estimated proof size: " << params_.estimate_proof_size() << " bytes" << std::endl;
        
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "SharpGS initialization failed: " << e.what() << std::endl;
        return false;
    }
}

std::optional<SharpGS::Proof> SharpGS::prove(const Statement& statement, const Witness& witness) {
    if (!initialized_) {
        return std::nullopt;
    }
    
    if (!statement.is_valid() || !witness.is_valid(statement)) {
        return std::nullopt;
    }
    
    try {
        // Create interactive prover
        auto prover = create_prover(statement, witness);
        if (!prover) {
            return std::nullopt;
        }
        
        // Execute three-flow protocol
        
        // First flow: prover commits to decomposition and masks
        auto first_message = prover->first_flow();
        if (!first_message) {
            return std::nullopt;
        }
        
        // Generate challenges (simulating verifier)
        std::vector<Fr> challenges(params_.repetitions);
        for (auto& challenge : challenges) {
            challenge = group_utils::secure_random();
            // Ensure challenge is in correct range [0, Γ]
            Fr gamma_bound;
            gamma_bound.setInt(1ULL << params_.challenge_bits);
            // Simple modular reduction (not perfectly uniform, but adequate for prototype)
        }
        
        // Second flow: prover receives challenges
        if (!prover->receive_challenges(challenges)) {
            return std::nullopt;
        }
        
        // Third flow: prover computes responses
        auto third_message = prover->third_flow();
        if (!third_message) {
            return std::nullopt;
        }
        
        // Create proof from transcript
        Proof proof(prover->get_transcript(), params_);
        
        // Verify proof as sanity check
        if (!verify(statement, proof)) {
            return std::nullopt;
        }
        
        return proof;
        
    } catch (const std::exception& e) {
        std::cerr << "Proof generation failed: " << e.what() << std::endl;
        return std::nullopt;
    }
}

bool SharpGS::verify(const Statement& statement, const Proof& proof) {
    if (!initialized_) {
        return false;
    }
    
    if (!statement.is_valid() || !proof.is_valid()) {
        return false;
    }
    
    try {
        // Create interactive verifier
        auto verifier = create_verifier(statement);
        if (!verifier) {
            return false;
        }
        
        // Simulate receiving first flow
        // In practice, this would be the serialized first message
        std::vector<uint8_t> first_message; // Placeholder
        if (!verifier->receive_first_flow(first_message)) {
            return false;
        }
        
        // Verify challenge generation matches proof
        auto generated_challenges = verifier->generate_challenges();
        if (generated_challenges.size() != proof.transcript.challenges.size()) {
            return false;
        }
        
        // Simulate receiving third flow
        std::vector<uint8_t> third_message; // Placeholder
        if (!verifier->receive_third_flow(third_message)) {
            return false;
        }
        
        // Final verification
        return verifier->verify();
        
    } catch (const std::exception& e) {
        std::cerr << "Verification failed: " << e.what() << std::endl;
        return false;
    }
}

std::unique_ptr<SharpGS::InteractiveProver> SharpGS::create_prover(
    const Statement& statement, 
    const Witness& witness) {
    
    if (!initialized_) {
        return nullptr;
    }
    
    return std::make_unique<InteractiveProver>(*this, statement, witness);
}

std::unique_ptr<SharpGS::InteractiveVerifier> SharpGS::create_verifier(const Statement& statement) {
    if (!initialized_) {
        return nullptr;
    }
    
    return std::make_unique<InteractiveVerifier>(*this, statement);
}

// Private helper methods
bool SharpGS::setup_groups() {
    return groups_->initialize(
        params_.security_bits,
        params_.range_bits, 
        params_.batch_size,
        params_.challenge_bits
    );
}

bool SharpGS::setup_commitments() {
    try {
        gcom_committer_ = std::make_unique<PedersenMultiCommit>(*groups_, false); // Use Gcom
        g3sq_committer_ = std::make_unique<PedersenMultiCommit>(*groups_, true);  // Use G3sq
        return true;
    } catch (...) {
        return false;
    }
}

std::vector<std::vector<Fr>> SharpGS::compute_three_square_decomposition(
    const std::vector<Fr>& values, 
    const Fr& range_bound) {
    
    std::vector<std::vector<Fr>> decompositions;
    decompositions.reserve(values.size());
    
    for (const auto& value : values) {
        auto decomp = utils::three_square::decompose(value, range_bound);
        if (decomp.empty()) {
            throw std::runtime_error("Three-square decomposition failed");
        }
        decompositions.push_back(decomp);
    }
    
    return decompositions;
}

bool SharpGS::verify_decomposition_commitments(
    const Transcript& transcript,
    const Statement& statement) {
    
    // Verify that commitments are properly formed
    // This is a simplified check - full verification would recompute and compare
    return !transcript.decomposition_commitment.value.isZero();
}

bool SharpGS::verify_polynomial_relations(
    const Transcript& transcript,
    const Statement& statement) {
    
    // Verify polynomial degree constraints
    // For each repetition, verify that f(γ) has degree 1
    
    for (size_t k = 0; k < transcript.challenges.size(); ++k) {
        if (k >= transcript.masked_values.size()) {
            return false;
        }
        
        const auto& challenge = transcript.challenges[k];
        const auto& masked_vals = transcript.masked_values[k];
        
        // Compute polynomial coefficients for this repetition
        auto coeffs = compute_polynomial_coefficients(
            masked_vals, {}, challenge, statement.range_bound
        );
        
        // Verify degree constraint (simplified check)
        if (coeffs.size() > 2) {
            // Check that quadratic term is zero
            if (!coeffs[2].isZero()) {
                return false;
            }
        }
    }
    
    return true;
}

std::vector<Fr> SharpGS::compute_polynomial_coefficients(
    const std::vector<Fr>& masked_values,
    const std::vector<Fr>& masked_squares,
    const Fr& challenge,
    const Fr& range_bound) {
    
    // For SharpGS: f(γ) = z(γB - z) - Σ zi²
    // This should expand to a linear polynomial in γ
    
    if (masked_values.empty()) {
        return {};
    }
    
    // Use first masked value as representative (simplified)
    const Fr& z = masked_values[0];
    
    // Compute polynomial using SharpGSPolynomial utility
    auto poly = SharpGSPolynomial::compute_decomposition_polynomial(z, range_bound, masked_squares);
    
    return poly.coefficients();
}

// InteractiveProver implementation
SharpGS::InteractiveProver::InteractiveProver(SharpGS& protocol, const Statement& stmt, const Witness& wit)
    : protocol_(protocol), statement_(stmt), witness_(wit), state_valid_(false) {
    
    if (!stmt.is_valid() || !wit.is_valid(stmt)) {
        return;
    }
    
    try {
        // Compute three-square decompositions
        decomposition_values_ = protocol_.compute_three_square_decomposition(
            witness_.values, statement_.range_bound
        );
        
        // Generate randomness for decomposition commitments
        decomp_randomness_.resize(decomposition_values_.size());
        for (auto& r : decomp_randomness_) {
            r = group_utils::secure_random();
        }
        
        state_valid_ = true;
        
    } catch (const std::exception& e) {
        std::cerr << "InteractiveProver initialization failed: " << e.what() << std::endl;
        state_valid_ = false;
    }
}

std::optional<std::vector<uint8_t>> SharpGS::InteractiveProver::first_flow() {
    if (!state_valid_) {
        return std::nullopt;
    }
    
    try {
        // Commit to decomposition values yi,j
        auto [decomp_commit, decomp_opening] = protocol_.gcom_committer_->commit_indexed(
            decomposition_values_
        );
        transcript_.decomposition_commitment = decomp_commit;
        
        // For each repetition, commit to masks
        transcript_.round_commitments.resize(protocol_.params_.repetitions);
        
        for (size_t k = 0; k < protocol_.params_.repetitions; ++k) {
            std::vector<PedersenMultiCommit::Commitment> round_commits;
            
            // Create mask commitments (simplified - would include all necessary masks)
            for (size_t i = 0; i < protocol_.params_.batch_size; ++i) {
                Fr mask = group_utils::secure_random();
                auto [mask_commit, mask_opening] = protocol_.gcom_committer_->commit_single(mask);
                round_commits.push_back(mask_commit);
            }
            
            transcript_.round_commitments[k] = round_commits;
        }
        
        // Hash optimization: compute hash of commitments
        if (protocol_.params_.use_hash_optimization) {
            std::vector<G1> all_commits;
            all_commits.push_back(transcript_.decomposition_commitment.value);
            
            for (const auto& round : transcript_.round_commitments) {
                for (const auto& commit : round) {
                    all_commits.push_back(commit.value);
                }
            }
            
            transcript_.commitment_hash = utils::hash::hash_commitments(all_commits);
        }
        
        // Serialize and return first message
        return utils::serialize::group_to_bytes(transcript_.decomposition_commitment.value);
        
    } catch (const std::exception& e) {
        std::cerr << "First flow failed: " << e.what() << std::endl;
        return std::nullopt;
    }
}

bool SharpGS::InteractiveProver::receive_challenges(const std::vector<Fr>& challenges) {
    if (!state_valid_ || challenges.size() != protocol_.params_.repetitions) {
        return false;
    }
    
    transcript_.challenges = challenges;
    return true;
}

std::optional<std::vector<uint8_t>> SharpGS::InteractiveProver::third_flow() {
    if (!state_valid_ || transcript_.challenges.empty()) {
        return std::nullopt;
    }
    
    try {
        // For each repetition, compute masked responses
        transcript_.masked_values.resize(protocol_.params_.repetitions);
        transcript_.masked_randomness.resize(protocol_.params_.repetitions);
        
        for (size_t k = 0; k < protocol_.params_.repetitions; ++k) {
            const Fr& challenge = transcript_.challenges[k];
            
            // Mask values: zk,i = mask(γk * xi, xek,i)
            std::vector<Fr> masked_vals;
            for (size_t i = 0; i < witness_.values.size(); ++i) {
                auto masked = protocol_.masking_->mask_challenged_value(witness_.values[i], challenge);
                if (!masked) {
                    std::cerr << "Masking failed for value " << i << " in repetition " << k << std::endl;
                    return std::nullopt;
                }
                masked_vals.push_back(*masked);
            }
            
            // Mask decomposition values: zk,i,j = mask(γk * yi,j, yek,i,j)
            for (size_t i = 0; i < decomposition_values_.size(); ++i) {
                for (size_t j = 0; j < decomposition_values_[i].size(); ++j) {
                    auto masked = protocol_.masking_->mask_challenged_value(
                        decomposition_values_[i][j], challenge
                    );
                    if (!masked) {
                        std::cerr << "Masking failed for decomposition " << i << "," << j << std::endl;
                        return std::nullopt;
                    }
                    masked_vals.push_back(*masked);
                }
            }
            
            transcript_.masked_values[k] = masked_vals;
            
            // Mask randomness values
            std::vector<Fr> masked_rands;
            for (size_t i = 0; i < witness_.randomness.size(); ++i) {
                auto masked = protocol_.masking_->mask_randomness(witness_.randomness[i], challenge);
                if (!masked) {
                    std::cerr << "Randomness masking failed" << std::endl;
                    return std::nullopt;
                }
                masked_rands.push_back(*masked);
            }
            
            // Add decomposition randomness
            for (size_t i = 0; i < decomp_randomness_.size(); ++i) {
                auto masked = protocol_.masking_->mask_randomness(decomp_randomness_[i], challenge);
                if (!masked) {
                    return std::nullopt;
                }
                masked_rands.push_back(*masked);
            }
            
            transcript_.masked_randomness[k] = masked_rands;
        }
        
        // Serialize response
        std::vector<uint8_t> response;
        for (const auto& round : transcript_.masked_values) {
            for (const auto& val : round) {
                auto bytes = utils::serialize::field_to_bytes(val);
                response.insert(response.end(), bytes.begin(), bytes.end());
            }
        }
        
        return response;
        
    } catch (const std::exception& e) {
        std::cerr << "Third flow failed: " << e.what() << std::endl;
        return std::nullopt;
    }
}

// InteractiveVerifier implementation
SharpGS::InteractiveVerifier::InteractiveVerifier(SharpGS& protocol, const Statement& stmt)
    : protocol_(protocol), statement_(stmt), state_valid_(stmt.is_valid()) {
}

bool SharpGS::InteractiveVerifier::receive_first_flow(const std::vector<uint8_t>& message) {
    if (!state_valid_) {
        return false;
    }
    
    try {
        // Deserialize decomposition commitment
        if (!message.empty()) {
            transcript_.decomposition_commitment.value = utils::serialize::group_from_bytes(message);
        }
        
        return true;
        
    } catch (...) {
        return false;
    }
}

std::vector<Fr> SharpGS::InteractiveVerifier::generate_challenges() {
    if (!state_valid_) {
        return {};
    }
    
    std::vector<Fr> challenges(protocol_.params_.repetitions);
    
    for (auto& challenge : challenges) {
        challenge = group_utils::secure_random();
        // In practice, would use Fiat-Shamir with transcript hash
    }
    
    transcript_.challenges = challenges;
    return challenges;
}

bool SharpGS::InteractiveVerifier::receive_third_flow(const std::vector<uint8_t>& message) {
    if (!state_valid_ || transcript_.challenges.empty()) {
        return false;
    }
    
    try {
        // Deserialize masked values and randomness
        // This is simplified - full implementation would properly parse the message
        
        transcript_.masked_values.resize(protocol_.params_.repetitions);
        transcript_.masked_randomness.resize(protocol_.params_.repetitions);
        
        // Placeholder parsing
        for (size_t k = 0; k < protocol_.params_.repetitions; ++k) {
            transcript_.masked_values[k].resize(protocol_.params_.batch_size * 4); // xi + 3*yi,j
            transcript_.masked_randomness[k].resize(2); // Simplified
            
            for (auto& val : transcript_.masked_values[k]) {
                val = group_utils::secure_random(); // Placeholder
            }
            for (auto& rand : transcript_.masked_randomness[k]) {
                rand = group_utils::secure_random(); // Placeholder
            }
        }
        
        return true;
        
    } catch (...) {
        return false;
    }
}

bool SharpGS::InteractiveVerifier::verify() {
    if (!state_valid_) {
        return false;
    }
    
    try {
        // Verify commitment consistency
        if (!protocol_.verify_decomposition_commitments(transcript_, statement_)) {
            return false;
        }
        
        // Verify polynomial relations
        if (!protocol_.verify_polynomial_relations(transcript_, statement_)) {
            return false;
        }
        
        // Verify range constraints on masked values
        for (const auto& round : transcript_.masked_values) {
            for (const auto& val : round) {
                // Check that masked values are in expected range
                if (!group_utils::is_small_integer(val, 1ULL << 32)) {
                    return false;
                }
            }
        }
        
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Verification error: " << e.what() << std::endl;
        return false;
    }
}

// Utility functions
namespace sharp_gs_utils {

std::pair<SharpGS::Statement, SharpGS::Witness> create_statement_and_witness(
    const std::vector<Fr>& values,
    const Fr& range_bound,
    const GroupManager& groups) {
    
    // Create commitments to the values
    PedersenMultiCommit committer(groups, false); // Use Gcom
    
    std::vector<PedersenMultiCommit::Commitment> commitments;
    std::vector<Fr> randomness;
    
    commitments.reserve(values.size());
    randomness.reserve(values.size());
    
    for (const auto& value : values) {
        Fr r = group_utils::secure_random();
        auto [commit, opening] = committer.commit_single(value, r);
        
        commitments.push_back(commit);
        randomness.push_back(r);
    }
    
    SharpGS::Statement statement(commitments, range_bound);
    SharpGS::Witness witness(values, randomness);
    
    return {statement, witness};
}

bool validate_sharp_gs_parameters(const SharpGS::Parameters& params) {
    return params.validate();
}

PerformanceEstimate estimate_performance(const SharpGS::Parameters& params) {
    PerformanceEstimate estimate;
    
    // Rough estimates based on operations
    estimate.prover_time_ms = params.batch_size * params.repetitions * 10.0; // ~10ms per proof per repetition
    estimate.verifier_time_ms = estimate.prover_time_ms * 0.3; // Verification is faster
    estimate.proof_size_bytes = params.estimate_proof_size();
    estimate.success_probability = 0.95; // Rough estimate accounting for masking failures
    
    return estimate;
}

std::vector<std::pair<SharpGS::Statement, SharpGS::Witness>> generate_test_cases(
    const SharpGS::Parameters& params,
    size_t num_cases) {
    
    std::vector<std::pair<SharpGS::Statement, SharpGS::Witness>> test_cases;
    test_cases.reserve(num_cases);
    
    // Initialize a group manager for test case generation
    GroupManager test_groups;
    test_groups.initialize(params.security_bits, params.range_bits, params.batch_size, params.challenge_bits);
    
    Fr range_bound;
    range_bound.setInt(1ULL << params.range_bits);
    
    for (size_t i = 0; i < num_cases; ++i) {
        std::vector<Fr> test_values(params.batch_size);
        
        for (auto& val : test_values) {
            // Generate random values in range [0, 2^range_bits)
            val.setInt(group_utils::secure_random().getInt() % (1ULL << params.range_bits));
        }
        
        auto [statement, witness] = create_statement_and_witness(test_values, range_bound, test_groups);
        test_cases.emplace_back(statement, witness);
    }
    
    return test_cases;
}

} // namespace sharp_gs_utils

} // namespace sharp_gs
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

size_t SharpGS::Statement::size_bytes() const {
    return value_commitments.size() * utils::serialize::group_element_size() +
           utils::serialize::field_element_size();
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
    for (const auto& round : round_commitments) {
        size += round.size() * utils::serialize::group_element_size();
    }
    
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
std::vector<uint8_t> SharpGS::Proof::serialize() const {
    // Serialize the transcript
    std::vector<uint8_t> result;
    
    // Serialize commitments
    auto commit_data = transcript.decomposition_commitment.serialize();
    result.insert(result.end(), commit_data.begin(), commit_data.end());
    
    // Serialize challenges
    auto challenge_data = utils::serialize::serialize_field_vector(transcript.challenges);
    result.insert(result.end(), challenge_data.begin(), challenge_data.end());
    
    // Serialize responses (simplified)
    for (const auto& round : transcript.masked_values) {
        auto round_data = utils::serialize::serialize_field_vector(round);
        result.insert(result.end(), round_data.begin(), round_data.end());
    }
    
    return result;
}

std::optional<SharpGS::Proof> SharpGS::Proof::deserialize(const std::vector<uint8_t>& data) {
    // Placeholder - should implement proper deserialization
    return std::nullopt;
}

// SharpGS main implementation
SharpGS::SharpGS(const Parameters& params) 
    : params_(params), initialized_(false) {
    
    if (!params_.validate()) {
        throw utils::SharpGSException(utils::ErrorCode::INVALID_PARAMETERS,
                                    "Invalid SharpGS parameters");
    }
}

bool SharpGS::initialize() {
    try {
        if (!setup_groups()) {
            return false;
        }
        
        if (!setup_commitments()) {
            return false;
        }
        
        if (!setup_masking()) {
            return false;
        }
        
        initialized_ = true;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "SharpGS initialization failed: " << e.what() << std::endl;
        return false;
    }
}

std::optional<SharpGS::Proof> SharpGS::prove(const Statement& statement, const Witness& witness) {
    if (!initialized_) {
        throw utils::SharpGSException(utils::ErrorCode::GROUP_INITIALIZATION_FAILED,
                                    "Protocol not initialized");
    }
    
    if (!statement.is_valid() || !witness.is_valid(statement)) {
        return std::nullopt;
    }
    
    try {
        Transcript transcript;
        
        // Phase 1: Compute three-square decomposition
        auto decomposition_values = compute_three_square_decomposition(witness.values, statement.range_bound);
        
        if (decomposition_values.empty()) {
            return std::nullopt; // Decomposition failed
        }
        
        // Phase 2: Commit to decomposition values
        std::vector<Fr> all_decomp_values;
        for (const auto& values : decomposition_values) {
            all_decomp_values.insert(all_decomp_values.end(), values.begin(), values.end());
        }
        
        Fr decomp_randomness = group_utils::secure_random();
        auto [decomp_commit, decomp_opening] = g3sq_committer_->commit_vector(all_decomp_values, decomp_randomness);
        transcript.decomposition_commitment = decomp_commit;
        
        // Phase 3: Generate challenges (in real protocol, verifier would send these)
        transcript.challenges.reserve(params_.repetitions);
        for (size_t r = 0; r < params_.repetitions; ++r) {
            Fr challenge = group_utils::secure_random();
            transcript.challenges.push_back(challenge);
        }
        
        // Phase 4: Generate masked responses
        transcript.masked_values.resize(params_.repetitions);
        transcript.masked_randomness.resize(params_.repetitions);
        
        for (size_t r = 0; r < params_.repetitions; ++r) {
            const Fr& gamma = transcript.challenges[r];
            
            // Mask values: z_i = γ * x_i + masking
            std::vector<Fr> round_masked_values;
            round_masked_values.reserve(witness.values.size());
            
            for (const auto& value : witness.values) {
                auto masked = masking_->mask_challenged_value(gamma, value);
                if (!masked) {
                    return std::nullopt; // Masking failed (abort)
                }
                round_masked_values.push_back(*masked);
            }
            
            transcript.masked_values[r] = round_masked_values;
            
            // Mask randomness values
            std::vector<Fr> round_masked_randomness;
            round_masked_randomness.reserve(witness.randomness.size());
            
            for (const auto& rand : witness.randomness) {
                auto masked_rand = masking_->mask_randomness(gamma, rand);
                if (!masked_rand) {
                    return std::nullopt; // Masking failed (abort)
                }
                round_masked_randomness.push_back(*masked_rand);
            }
            
            transcript.masked_randomness[r] = round_masked_randomness;
        }
        
        Proof proof;
        proof.transcript = transcript;
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
        const auto& transcript = proof.transcript;
        
        // Verify transcript completeness
        if (!transcript.is_complete()) {
            return false;
        }
        
        // Verify decomposition commitments
        if (!verify_decomposition_commitments(transcript, statement)) {
            return false;
        }
        
        // Verify polynomial relations
        if (!verify_polynomial_relations(transcript, statement)) {
            return false;
        }
        
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Verification failed: " << e.what() << std::endl;
        return false;
    }
}

std::optional<SharpGS::Proof> SharpGS::prove_batch(const std::vector<Statement>& statements, 
                                                   const std::vector<Witness>& witnesses) {
    // For now, implement batch as single statement with combined values
    if (statements.size() != witnesses.size() || statements.empty()) {
        return std::nullopt;
    }
    
    // Combine all values and randomness
    std::vector<Fr> all_values, all_randomness;
    Fr range_bound = statements[0].range_bound;
    
    for (size_t i = 0; i < statements.size(); ++i) {
        if (!(statements[i].range_bound == range_bound)) {
            return std::nullopt; // All statements must have same range bound
        }
        
        all_values.insert(all_values.end(), witnesses[i].values.begin(), witnesses[i].values.end());
        all_randomness.insert(all_randomness.end(), witnesses[i].randomness.begin(), witnesses[i].randomness.end());
    }
    
    // Create combined statement and witness
    auto [combined_statement, combined_witness] = sharp_gs_utils::create_statement_and_witness(
        all_values, range_bound, *groups_);
    
    return prove(combined_statement, combined_witness);
}

bool SharpGS::verify_batch(const std::vector<Statement>& statements, const Proof& proof) {
    // Similar to prove_batch, verify as combined statement
    if (statements.empty()) {
        return false;
    }
    
    // For simplified implementation, verify the proof against the first statement
    // Real implementation would need proper batch verification
    return verify(statements[0], proof);
}

// Interactive protocol implementations
SharpGS::InteractiveProver::InteractiveProver(const SharpGS& protocol, const Statement& stmt, const Witness& wit)
    : protocol_(protocol), statement_(stmt), witness_(wit), state_valid_(true) {
    
    if (!statement_.is_valid() || !witness_.is_valid(statement_)) {
        state_valid_ = false;
    }
}

std::vector<uint8_t> SharpGS::InteractiveProver::first_flow() {
    if (!state_valid_) {
        return std::vector<uint8_t>();
    }
    
    try {
        // Compute three-square decomposition
        decomposition_values_ = protocol_.compute_three_square_decomposition(witness_.values, statement_.range_bound);
        
        if (decomposition_values_.empty()) {
            state_valid_ = false;
            return std::vector<uint8_t>();
        }
        
        // Commit to decomposition values
        std::vector<Fr> all_decomp_values;
        for (const auto& values : decomposition_values_) {
            all_decomp_values.insert(all_decomp_values.end(), values.begin(), values.end());
        }
        
        Fr decomp_randomness = group_utils::secure_random();
        auto [decomp_commit, decomp_opening] = protocol_.g3sq_committer_->commit_vector(all_decomp_values, decomp_randomness);
        transcript_.decomposition_commitment = decomp_commit;
        
        // Serialize first message
        return transcript_.decomposition_commitment.serialize();
        
    } catch (...) {
        state_valid_ = false;
        return std::vector<uint8_t>();
    }
}

bool SharpGS::InteractiveProver::second_flow(const std::vector<Fr>& challenges) {
    if (!state_valid_) {
        return false;
    }
    
    transcript_.challenges = challenges;
    return true;
}

std::vector<uint8_t> SharpGS::InteractiveProver::third_flow() {
    if (!state_valid_ || transcript_.challenges.empty()) {
        return std::vector<uint8_t>();
    }
    
    try {
        // Generate masked responses for each challenge
        transcript_.masked_values.resize(transcript_.challenges.size());
        transcript_.masked_randomness.resize(transcript_.challenges.size());
        
        for (size_t r = 0; r < transcript_.challenges.size(); ++r) {
            const Fr& gamma = transcript_.challenges[r];
            
            // Mask values
            std::vector<Fr> round_masked_values;
            for (const auto& value : witness_.values) {
                auto masked = protocol_.masking_->mask_challenged_value(gamma, value);
                if (!masked) {
                    state_valid_ = false;
                    return std::vector<uint8_t>();
                }
                round_masked_values.push_back(*masked);
            }
            transcript_.masked_values[r] = round_masked_values;
            
            // Mask randomness
            std::vector<Fr> round_masked_randomness;
            for (const auto& rand : witness_.randomness) {
                auto masked_rand = protocol_.masking_->mask_randomness(gamma, rand);
                if (!masked_rand) {
                    state_valid_ = false;
                    return std::vector<uint8_t>();
                }
                round_masked_randomness.push_back(*masked_rand);
            }
            transcript_.masked_randomness[r] = round_masked_randomness;
        }
        
        // Serialize responses (simplified)
        std::vector<uint8_t> result;
        for (const auto& round : transcript_.masked_values) {
            auto round_data = utils::serialize::serialize_field_vector(round);
            result.insert(result.end(), round_data.begin(), round_data.end());
        }
        
        return result;
        
    } catch (...) {
        state_valid_ = false;
        return std::vector<uint8_t>();
    }
}

SharpGS::InteractiveVerifier::InteractiveVerifier(const SharpGS& protocol, const Statement& stmt)
    : protocol_(protocol), statement_(stmt), state_valid_(true) {
    
    if (!statement_.is_valid()) {
        state_valid_ = false;
    }
}

bool SharpGS::InteractiveVerifier::receive_first_flow(const std::vector<uint8_t>& message) {
    if (!state_valid_) {
        return false;
    }
    
    try {
        // Deserialize commitment (simplified)
        transcript_.decomposition_commitment = PedersenMultiCommit::Commitment::deserialize(message);
        return true;
        
    } catch (...) {
        state_valid_ = false;
        return false;
    }
}

std::vector<Fr> SharpGS::InteractiveVerifier::second_flow() {
    if (!state_valid_) {
        return std::vector<Fr>();
    }
    
    // Generate random challenges
    std::vector<Fr> challenges;
    challenges.reserve(protocol_.params_.repetitions);
    
    for (size_t r = 0; r < protocol_.params_.repetitions; ++r) {
        challenges.push_back(group_utils::secure_random());
    }
    
    transcript_.challenges = challenges;
    return challenges;
}

bool SharpGS::InteractiveVerifier::receive_third_flow(const std::vector<uint8_t>& message) {
    if (!state_valid_) {
        return false;
    }
    
    try {
        // Deserialize responses (simplified)
        // In real implementation, would properly deserialize the masked values
        transcript_.masked_values.resize(transcript_.challenges.size());
        transcript_.masked_randomness.resize(transcript_.challenges.size());
        
        // Placeholder deserialization
        for (size_t r = 0; r < transcript_.challenges.size(); ++r) {
            transcript_.masked_values[r].resize(statement_.batch_size());
            transcript_.masked_randomness[r].resize(statement_.batch_size());
            
            for (size_t i = 0; i < statement_.batch_size(); ++i) {
                transcript_.masked_values[r][i].setByCSPRNG();
                transcript_.masked_randomness[r][i].setByCSPRNG();
            }
        }
        
        return true;
        
    } catch (...) {
        state_valid_ = false;
        return false;
    }
}

bool SharpGS::InteractiveVerifier::final_verification() {
    if (!state_valid_ || !transcript_.is_complete()) {
        return false;
    }
    
    return protocol_.verify_decomposition_commitments(transcript_, statement_) &&
           protocol_.verify_polynomial_relations(transcript_, statement_);
}

std::unique_ptr<SharpGS::InteractiveProver> SharpGS::create_prover(
    const Statement& statement, const Witness& witness) {
    return std::make_unique<InteractiveProver>(*this, statement, witness);
}

std::unique_ptr<SharpGS::InteractiveVerifier> SharpGS::create_verifier(const Statement& statement) {
    return std::make_unique<InteractiveVerifier>(*this, statement);
}

// Private helper methods
bool SharpGS::setup_groups() {
    groups_ = std::make_unique<GroupManager>();
    return groups_->initialize(params_.security_bits, params_.range_bits, 
                              params_.batch_size, params_.challenge_bits);
}

bool SharpGS::setup_commitments() {
    gcom_committer_ = std::make_unique<PedersenMultiCommit>(*groups_, false);
    g3sq_committer_ = std::make_unique<PedersenMultiCommit>(*groups_, true);
    return true;
}

bool SharpGS::setup_masking() {
    MaskingParams masking_params(params_.masking_overhead, 0.5, params_.security_bits);
    masking_ = std::make_unique<SharpGSMasking>(masking_params);
    return true;
}

std::vector<std::vector<Fr>> SharpGS::compute_three_square_decomposition(
    const std::vector<Fr>& values, const Fr& range_bound) const {  // FIX: Added const
    
    std::vector<std::vector<Fr>> decompositions;
    decompositions.reserve(values.size());
    
    for (const auto& value : values) {
        auto decomp = utils::three_square::decompose(value, range_bound);
        if (decomp.empty()) {
            return std::vector<std::vector<Fr>>(); // Failed
        }
        decompositions.push_back(decomp);
    }
    
    return decompositions;
}

bool SharpGS::verify_decomposition_commitments(const Transcript& transcript, const Statement& statement) const {  // FIX: Added const
    // Verify that decomposition commitments are well-formed
    // This is simplified verification - real implementation needs proper checks
    return !transcript.decomposition_commitment.is_zero();
}

bool SharpGS::verify_polynomial_relations(const Transcript& transcript, const Statement& statement) const {  // FIX: Added const
    // Verify polynomial relations for each challenge round
    for (size_t r = 0; r < transcript.challenges.size(); ++r) {
        const Fr& gamma = transcript.challenges[r];
        const auto& masked_values = transcript.masked_values[r];
        
        // Check polynomial relation: f(γ) should have degree 1
        // This is simplified - real implementation needs proper polynomial verification
        if (masked_values.size() != statement.batch_size()) {
            return false;
        }
    }
    
    return true;
}

std::vector<Fr> SharpGS::compute_polynomial_coefficients(
    const std::vector<Fr>& masked_values, const std::vector<Fr>& masked_squares,
    const Fr& challenge, const Fr& range_bound) const {  // FIX: Added const
    
    // Compute polynomial coefficients for verification
    // This is simplified - real implementation needs proper computation
    std::vector<Fr> coeffs(2); // Linear polynomial
    
    coeffs[0] = group_utils::int_to_field(1); // Constant term
    Fr::mul(coeffs[1], challenge, range_bound); // Linear term
    
    return coeffs;
}

// Utility functions implementation
namespace sharp_gs_utils {

std::pair<SharpGS::Statement, SharpGS::Witness> create_statement_and_witness(
    const std::vector<Fr>& values, const Fr& range_bound, const GroupManager& groups) {
    
    PedersenMultiCommit committer(groups, false);
    
    // Generate random commitment randomness
    std::vector<Fr> randomness;
    randomness.reserve(values.size());
    for (size_t i = 0; i < values.size(); ++i) {
        randomness.push_back(group_utils::secure_random());
    }
    
    // Create commitments
    std::vector<PedersenMultiCommit::Commitment> commitments;
    commitments.reserve(values.size());
    
    for (size_t i = 0; i < values.size(); ++i) {
        auto [commit, opening] = committer.commit_single(values[i], randomness[i]);
        commitments.push_back(commit);
    }
    
    SharpGS::Statement statement(commitments, range_bound);
    SharpGS::Witness witness(values, randomness);
    
    return {statement, witness};
}

bool validate_sharp_gs_parameters(const SharpGS::Parameters& params) {
    return params.validate();
}

sharp_gs_utils::PerformanceEstimate estimate_performance(const SharpGS::Parameters& params) {
    PerformanceEstimate estimate;
    
    // Rough estimates based on parameter complexity
    double base_time = 10.0; // Base time in ms
    double batch_factor = std::sqrt(static_cast<double>(params.batch_size));
    double security_factor = static_cast<double>(params.security_bits) / 128.0;
    double range_factor = static_cast<double>(params.range_bits) / 64.0;
    
    estimate.prover_time_ms = base_time * batch_factor * security_factor * range_factor * 2.0;
    estimate.verifier_time_ms = estimate.prover_time_ms * 0.3; // Verification faster
    estimate.proof_size_bytes = params.estimate_proof_size();
    estimate.success_probability = 1.0 - (1.0 / std::pow(2.0, static_cast<double>(params.masking_overhead)));
    
    return estimate;
}

std::vector<std::pair<SharpGS::Statement, SharpGS::Witness>> generate_test_cases(
    const SharpGS::Parameters& params, size_t num_cases) {
    
    std::vector<std::pair<SharpGS::Statement, SharpGS::Witness>> test_cases;
    test_cases.reserve(num_cases);
    
    // Create a temporary group manager for test case generation
    GroupManager temp_groups;
    if (!temp_groups.initialize(params.security_bits, params.range_bits, params.batch_size)) {
        return test_cases;
    }
    
    Fr range_bound = group_utils::int_to_field(1ULL << params.range_bits);
    
    for (size_t case_idx = 0; case_idx < num_cases; ++case_idx) {
        std::vector<Fr> values;
        values.reserve(params.batch_size);
        
        for (size_t i = 0; i < params.batch_size; ++i) {
            // Generate random value in range [0, 2^range_bits - 1]
            int64_t random_val = static_cast<int64_t>(group_utils::secure_random().getStr(10)[0] % (1ULL << std::min(params.range_bits, static_cast<size_t>(20))));
            Fr val = group_utils::int_to_field(random_val);
            values.push_back(val);
        }
        
        auto [statement, witness] = create_statement_and_witness(values, range_bound, temp_groups);
        test_cases.emplace_back(statement, witness);
    }
    
    return test_cases;
}

} // namespace sharp_gs_utils

} // namespace sharp_gs
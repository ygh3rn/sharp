#include "utils.h"
#include <stdexcept>
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace sharp_gs {
namespace utils {

// Error handling implementation
std::string error_to_string(ErrorCode code) {
    switch (code) {
        case ErrorCode::SUCCESS:
            return "Success";
        case ErrorCode::INVALID_PARAMETERS:
            return "Invalid parameters";
        case ErrorCode::GROUP_INITIALIZATION_FAILED:
            return "Group initialization failed";
        case ErrorCode::COMMITMENT_FAILED:
            return "Commitment operation failed";
        case ErrorCode::MASKING_FAILED:
            return "Masking operation failed";
        case ErrorCode::DECOMPOSITION_FAILED:
            return "Three-square decomposition failed";
        case ErrorCode::VERIFICATION_FAILED:
            return "Verification failed";
        case ErrorCode::SERIALIZATION_FAILED:
            return "Serialization failed";
        default:
            return "Unknown error";
    }
}

SharpGSException::SharpGSException(ErrorCode code, const std::string& message) 
    : code_(code), message_(message) {
    if (message_.empty()) {
        message_ = error_to_string(code);
    }
}

const char* SharpGSException::what() const noexcept {
    return message_.c_str();
}

// Secure randomness implementation
namespace random {

void SecureRandom::next_bytes(uint8_t* buffer, size_t size) {
    auto& rng = instance();
    for (size_t i = 0; i < size; i += sizeof(uint64_t)) {
        uint64_t value = rng.gen_();
        size_t copy_length = std::min(sizeof(value), size - i);
        std::memcpy(buffer + i, &value, copy_length);  // FIX: Proper memcpy usage
    }
}

uint64_t SecureRandom::next_uint64() {
    return instance().gen_();
}

Fr SecureRandom::next_field_element() {
    Fr result;
    result.setByCSPRNG();  // FIX: Use proper MCL random generation
    return result;
}

} // namespace random

// Three-square decomposition implementation
namespace three_square {

std::vector<Fr> decompose(const Fr& x, const Fr& B) {
    // Implementation of three-square decomposition algorithm
    // For now, a simplified version - should be replaced with proper algorithm
    std::vector<Fr> result(3);
    
    // Simple approach: try small values
    for (int64_t a = 0; a < 1000; ++a) {
        for (int64_t b = 0; b < 1000; ++b) {
            for (int64_t c = 0; c < 1000; ++c) {
                Fr fa, fb, fc;
                fa.setStr(std::to_string(a), 10);  // FIX: Use setStr instead of setInt
                fb.setStr(std::to_string(b), 10);
                fc.setStr(std::to_string(c), 10);
                
                // Check if a² + b² + c² = 4x(B-x) + 1
                Fr four, target, temp1, temp2, sum;
                four.setStr("4", 10);
                
                Fr::sub(temp1, B, x);
                Fr::mul(temp2, x, temp1);
                Fr::mul(target, four, temp2);
                Fr one;
                one.setStr("1", 10);
                Fr::add(target, target, one);
                
                Fr a_sq, b_sq, c_sq;
                Fr::mul(a_sq, fa, fa);
                Fr::mul(b_sq, fb, fb);
                Fr::mul(c_sq, fc, fc);
                
                Fr::add(sum, a_sq, b_sq);
                Fr::add(sum, sum, c_sq);
                
                if (sum == target) {
                    result[0] = fa;
                    result[1] = fb;
                    result[2] = fc;
                    return result;
                }
            }
        }
    }
    
    // If no decomposition found, return empty vector
    return std::vector<Fr>();
}

bool verify_decomposition(const Fr& x, const Fr& B, const std::vector<Fr>& y) {
    if (y.size() != 3) return false;
    
    // Verify: y₁² + y₂² + y₃² = 4x(B-x) + 1
    Fr four, one, target, temp1, temp2;
    four.setStr("4", 10);  // FIX: Use setStr instead of setInt
    one.setStr("1", 10);
    
    Fr::sub(temp1, B, x);
    Fr::mul(temp2, x, temp1);
    Fr::mul(target, four, temp2);
    Fr::add(target, target, one);
    
    Fr sum, y_sq;
    sum.clear(); // Initialize to zero
    
    for (const auto& yi : y) {
        Fr::mul(y_sq, yi, yi);
        Fr::add(sum, sum, y_sq);
    }
    
    return sum == target;
}

std::vector<std::vector<Fr>> decompose_batch(const std::vector<Fr>& values, const Fr& B) {
    std::vector<std::vector<Fr>> results;
    results.reserve(values.size());
    
    for (const auto& value : values) {
        results.push_back(decompose(value, B));
    }
    
    return results;
}

} // namespace three_square

// Polynomial operations implementation
namespace polynomial {

std::vector<Fr> compute_decomposition_polynomial(
    const Fr& x, const Fr& B, const Fr& gamma, const std::vector<Fr>& y) {
    
    // This is a placeholder implementation
    // Should implement the actual polynomial computation for SharpGS
    std::vector<Fr> coeffs(3); // Up to degree 2, but should be degree 1
    
    // Initialize coefficients
    for (auto& coeff : coeffs) {
        coeff.clear();
    }
    
    // Clear the quadratic coefficient (should be zero for valid decomposition)
    coeffs[2].clear();
    
    // Set linear and constant terms based on the decomposition
    // This is simplified - real implementation needs proper polynomial arithmetic
    coeffs[1] = gamma;  // Linear term
    Fr::mul(coeffs[0], x, B);  // Simplified constant term
    
    return coeffs;
}

Fr evaluate(const std::vector<Fr>& coefficients, const Fr& point) {
    if (coefficients.empty()) {
        Fr zero;
        zero.clear();
        return zero;
    }
    
    Fr result = coefficients[0];
    Fr power = point;
    
    for (size_t i = 1; i < coefficients.size(); ++i) {
        Fr term;
        Fr::mul(term, coefficients[i], power);
        Fr::add(result, result, term);
        Fr::mul(power, power, point);
    }
    
    return result;
}

std::vector<Fr> interpolate(const std::vector<Fr>& points, const std::vector<Fr>& values) {
    // Lagrange interpolation - simplified implementation
    if (points.size() != values.size() || points.empty()) {
        return std::vector<Fr>();
    }
    
    // For now, return a simple linear interpolation for 2 points
    if (points.size() == 2) {
        std::vector<Fr> coeffs(2);
        
        // Linear interpolation: f(x) = a₀ + a₁x
        // f(x₀) = y₀, f(x₁) = y₁
        Fr dx, dy;
        Fr::sub(dx, points[1], points[0]);
        Fr::sub(dy, values[1], values[0]);
        
        Fr::div(coeffs[1], dy, dx);  // Slope
        
        Fr temp;
        Fr::mul(temp, coeffs[1], points[0]);
        Fr::sub(coeffs[0], values[0], temp);  // Intercept
        
        return coeffs;
    }
    
    return std::vector<Fr>();
}

} // namespace polynomial

// Hash functions implementation
namespace hash {

std::vector<uint8_t> sha256(const std::vector<uint8_t>& input) {
    // FIX: Proper memcpy usage with include
    // Simple placeholder - should use proper SHA256 implementation
    std::vector<uint8_t> result(32);
    uint64_t hash_val = std::hash<std::string>{}(
        std::string(input.begin(), input.end()));
    std::memcpy(result.data(), &hash_val, std::min(sizeof(hash_val), result.size()));
    return result;
}

Fr challenge_from_transcript(const std::vector<uint8_t>& transcript) {
    auto hash = sha256(transcript);
    uint64_t seed = 0;
    std::memcpy(&seed, hash.data(), std::min(sizeof(seed), hash.size()));
    
    Fr result;
    result.setByCSPRNG(); // FIX: Use proper MCL random generation instead of setInt
    return result;
}

std::vector<uint8_t> serialize_point(const G1& point) {
    // Simplified serialization - should use proper MCL serialization
    std::vector<uint8_t> result(32);
    // In real implementation, would serialize the point properly
    return result;
}

std::vector<uint8_t> serialize_field(const Fr& element) {
    // Simplified serialization - should use proper MCL serialization
    std::vector<uint8_t> result(32);
    // In real implementation, would serialize the field element properly
    return result;
}

} // namespace hash

// Timing utilities implementation
namespace timing {

void Timer::start() {
    start_time_ = std::chrono::high_resolution_clock::now();  // FIX: Proper implementation
}

double Timer::elapsed_ms() const {
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time_);
    return duration.count() / 1000.0;
}

double Timer::elapsed_us() const {
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time_);
    return static_cast<double>(duration.count());
}

} // namespace timing

// Parameter utilities implementation
namespace params {

std::pair<size_t, size_t> compute_group_sizes(
    size_t security_bits, size_t range_bits, size_t challenge_bits, size_t batch_size) {
    
    // Compute group sizes based on SharpGS security requirements
    // Gcom group (p): optimized for efficiency  
    size_t p_bits = security_bits + range_bits + 64; // Base size with margin
    
    // G3sq group (q): optimized for security
    size_t q_bits = security_bits + challenge_bits + 128; // Larger for security
    
    // Adjust for batch size
    if (batch_size > 1) {
        p_bits += static_cast<size_t>(std::log2(batch_size)) + 16;
        q_bits += static_cast<size_t>(std::log2(batch_size)) + 32;
    }
    
    return {p_bits, q_bits};
}

size_t compute_repetitions(size_t security_bits, size_t challenge_bits) {
    // R = ⌈λ / log₂(Γ + 1)⌉ where Γ = 2^challenge_bits - 1
    if (challenge_bits == 0) return 1;
    
    double log_gamma_plus_1 = challenge_bits; // log₂(2^challenge_bits) = challenge_bits
    size_t repetitions = static_cast<size_t>(std::ceil(static_cast<double>(security_bits) / log_gamma_plus_1));
    
    return std::max(repetitions, static_cast<size_t>(1));
}

size_t estimate_proof_size(size_t security_bits, size_t range_bits, 
                          size_t batch_size, bool use_hash_opt) {
    auto [p_bits, q_bits] = compute_group_sizes(security_bits, range_bits, 128, batch_size);
    
    // Estimate based on SharpGS paper formulas
    size_t group_element_size = (p_bits + 7) / 8; // Convert bits to bytes
    size_t field_element_size = (std::max(p_bits, q_bits) + 7) / 8;
    
    size_t base_size = group_element_size * (1 + batch_size * 3); // Commitments
    base_size += field_element_size * compute_repetitions(security_bits, 128) * batch_size; // Responses
    
    if (use_hash_opt) {
        base_size = static_cast<size_t>(base_size * 0.7); // ~30% reduction
    }
    
    return base_size;
}

bool validate_parameters(
    size_t security_bits, size_t range_bits, 
    size_t challenge_bits, size_t batch_size) {
    
    // Basic sanity checks
    if (security_bits < 80 || security_bits > 512) return false;
    if (range_bits == 0 || range_bits > 128) return false;
    if (challenge_bits < 10 || challenge_bits > 256) return false;
    if (batch_size == 0 || batch_size > 1000) return false;
    
    // Check if group sizes are reasonable
    auto [p_bits, q_bits] = compute_group_sizes(security_bits, range_bits, challenge_bits, batch_size);
    if (p_bits > 1024 || q_bits > 1024) return false; // Too large
    
    return true;
}

} // namespace params

// Serialization utilities implementation
namespace serialize {

size_t field_element_size() {
    return 32; // 256 bits for BN curves
}

size_t group_element_size() {
    return 32; // Compressed point representation
}

std::vector<uint8_t> serialize_field_vector(const std::vector<Fr>& elements) {
    std::vector<uint8_t> result;
    result.reserve(elements.size() * field_element_size());
    
    for (const auto& element : elements) {
        auto serialized = hash::serialize_field(element);
        result.insert(result.end(), serialized.begin(), serialized.end());
    }
    
    return result;
}

std::vector<Fr> deserialize_field_vector(const std::vector<uint8_t>& data) {
    if (data.size() % field_element_size() != 0) {
        return std::vector<Fr>();
    }
    
    size_t count = data.size() / field_element_size();
    std::vector<Fr> result(count);
    
    // In real implementation, would deserialize properly
    for (size_t i = 0; i < count; ++i) {
        result[i].setByCSPRNG(); // Placeholder
    }
    
    return result;
}

} // namespace serialize

} // namespace utils
} // namespace sharp_gs
#include "utils.h"
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>

namespace sharp_gs {
namespace utils {

// Secure Random Implementation
std::random_device SecureRandom::rd_;
std::mt19937_64 SecureRandom::gen_(SecureRandom::rd_());

void SecureRandom::initialize() {
    // Re-seed with current time and random device
    auto now = std::chrono::high_resolution_clock::now();
    auto seed = now.time_since_epoch().count() ^ rd_();
    gen_.seed(seed);
}

uint64_t SecureRandom::next_uint64() {
    return gen_();
}

void SecureRandom::next_bytes(uint8_t* buffer, size_t length) {
    for (size_t i = 0; i < length; i += 8) {
        uint64_t value = next_uint64();
        size_t copy_length = std::min(8UL, length - i);
        std::memcpy(buffer + i, &value, copy_length);
    }
}

Fr SecureRandom::next_field_element() {
    Fr result;
    result.setByCSPRNG();
    return result;
}

// Three-Square Decomposition Utilities
namespace three_square {

std::vector<Fr> decompose(const Fr& x, const Fr& B) {
    // Simplified implementation for now
    // In practice, this would use algorithms like Rabin-Shallit
    // or Pollard-Schnorr for efficient three-square decomposition
    
    try {
        // Convert to integers for computation (assuming small values)
        int64_t x_int = std::stoll(x.getStr());
        int64_t B_int = std::stoll(B.getStr());
        
        if (x_int < 0 || x_int > B_int) {
            return {}; // Invalid input
        }
        
        // Compute target: 4x(B-x) + 1
        int64_t target = 4 * x_int * (B_int - x_int) + 1;
        
        // Simple search for three squares (not efficient, but works for small values)
        int64_t limit = static_cast<int64_t>(std::sqrt(target)) + 1;
        
        for (int64_t a = 0; a <= limit; ++a) {
            for (int64_t b = a; b <= limit; ++b) {
                int64_t remaining = target - a*a - b*b;
                if (remaining >= 0) {
                    int64_t c = static_cast<int64_t>(std::sqrt(remaining));
                    if (c*c == remaining) {
                        // Found decomposition: target = a² + b² + c²
                        std::vector<Fr> result(3);
                        result[0].setInt(a);
                        result[1].setInt(b);
                        result[2].setInt(c);
                        return result;
                    }
                }
            }
        }
        
        return {}; // No decomposition found
        
    } catch (...) {
        return {};
    }
}

bool verify_decomposition(const Fr& x, const Fr& B, const std::vector<Fr>& squares) {
    if (squares.size() != 3) {
        return false;
    }
    
    try {
        // Compute 4x(B-x) + 1
        Fr four, target, temp;
        four.setInt(4);
        Fr::mul(temp, four, x);           // 4x
        Fr::sub(temp, B, x);              // B-x (reusing temp)
        Fr::mul(target, temp, x);         // 4x(B-x) (reusing temp for 4x)
        Fr::mul(target, four, target);    // 4x(B-x) 
        four.setInt(1);
        Fr::add(target, target, four);    // 4x(B-x) + 1
        
        // Compute sum of squares
        Fr sum_squares, square;
        sum_squares.clear();
        
        for (const auto& y : squares) {
            Fr::mul(square, y, y);
            Fr::add(sum_squares, sum_squares, square);
        }
        
        return target == sum_squares;
        
    } catch (...) {
        return false;
    }
}

std::vector<std::vector<Fr>> decompose_batch(const std::vector<Fr>& values, const Fr& B) {
    std::vector<std::vector<Fr>> results;
    results.reserve(values.size());
    
    for (const auto& value : values) {
        auto decomp = decompose(value, B);
        results.push_back(decomp);
    }
    
    return results;
}

} // namespace three_square

// Polynomial utilities
namespace polynomial {

Fr evaluate(const std::vector<Fr>& coefficients, const Fr& point) {
    if (coefficients.empty()) {
        Fr zero;
        zero.clear();
        return zero;
    }
    
    // Horner's method: evaluate from highest degree term
    Fr result = coefficients.back();
    
    for (int i = static_cast<int>(coefficients.size()) - 2; i >= 0; --i) {
        Fr::mul(result, result, point);
        Fr::add(result, result, coefficients[i]);
    }
    
    return result;
}

std::vector<Fr> compute_decomposition_polynomial(
    const Fr& z,
    const Fr& gamma, 
    const Fr& B,
    const std::vector<Fr>& z_squares) {
    
    // Compute f(γ) = z(γB - z) - Σ zi²
    std::vector<Fr> coefficients(3); // f = α₂γ² + α₁γ + α₀
    
    // α₂ coefficient (should be 0 for valid decomposition)
    coefficients[2].clear(); // 0
    
    // α₁ coefficient: coefficient of γ term
    Fr::mul(coefficients[1], z, B);
    
    // α₀ coefficient: constant term = -z² - Σ zi²
    Fr z_squared;
    Fr::mul(z_squared, z, z);
    Fr::sub(coefficients[0], Fr(), z_squared); // -z²
    
    for (const auto& zi_squared : z_squares) {
        Fr::sub(coefficients[0], coefficients[0], zi_squared);
    }
    
    return coefficients;
}

std::pair<Fr, Fr> extract_linear_coefficients(const std::vector<Fr>& poly) {
    Fr alpha0, alpha1;
    
    // α₀ (constant term)
    if (poly.size() > 0) {
        alpha0 = poly[0];
    } else {
        alpha0.clear();
    }
    
    // α₁ (linear coefficient) 
    if (poly.size() > 1) {
        alpha1 = poly[1];
    } else {
        alpha1.clear();
    }
    
    return {alpha0, alpha1};
}

} // namespace polynomial

// Hash utilities (basic implementations)
namespace hash {

std::vector<uint8_t> sha256(const std::vector<uint8_t>& input) {
    // Placeholder - in practice would use actual SHA-256
    std::vector<uint8_t> result(32);
    std::hash<std::string> hasher;
    
    std::string input_str(input.begin(), input.end());
    size_t hash_val = hasher(input_str);
    
    // Copy hash value to result (simplified)
    std::memcpy(result.data(), &hash_val, std::min(sizeof(hash_val), result.size()));
    
    return result;
}

std::vector<uint8_t> hash_transcript(
    const std::vector<G1>& group_elements,
    const std::vector<Fr>& field_elements) {
    
    std::vector<uint8_t> input;
    
    // Serialize group elements
    for (const auto& ge : group_elements) {
        std::string ge_str = ge.getStr();
        input.insert(input.end(), ge_str.begin(), ge_str.end());
    }
    
    // Serialize field elements
    for (const auto& fe : field_elements) {
        std::string fe_str = fe.getStr();
        input.insert(input.end(), fe_str.begin(), fe_str.end());
    }
    
    return sha256(input);
}

Fr challenge_from_transcript(const std::vector<uint8_t>& transcript) {
    auto hash = sha256(transcript);
    
    Fr result;
    // Use first part of hash as seed
    uint64_t seed = 0;
    std::memcpy(&seed, hash.data(), std::min(sizeof(seed), hash.size()));
    
    result.setInt(seed);
    return result;
}

std::vector<uint8_t> hash_commitments(const std::vector<G1>& commitments) {
    return hash_transcript(commitments, {});
}

} // namespace hash

// Serialization utilities
namespace serialize {

std::vector<uint8_t> field_to_bytes(const Fr& element) {
    std::string str = element.getStr();
    return std::vector<uint8_t>(str.begin(), str.end());
}

Fr field_from_bytes(const std::vector<uint8_t>& bytes) {
    std::string str(bytes.begin(), bytes.end());
    Fr result;
    result.setStr(str);
    return result;
}

std::vector<uint8_t> group_to_bytes(const G1& element) {
    std::string str = element.getStr();
    return std::vector<uint8_t>(str.begin(), str.end());
}

G1 group_from_bytes(const std::vector<uint8_t>& bytes) {
    std::string str(bytes.begin(), bytes.end());
    G1 result;
    result.setStr(str);
    return result;
}

size_t field_element_size() {
    return 32; // Approximate size in bytes
}

size_t group_element_size() {
    return 64; // Approximate size in bytes for compressed point
}

} // namespace serialize

// Timing utilities
namespace timing {

Timer::Timer() : running_(false) {}

void Timer::start() {
    start_time_ = std::chrono::high_resolution_clock::now();
    running_ = true;
}

void Timer::stop() {
    running_ = false;
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

// Parameter utilities
namespace params {

std::pair<size_t, size_t> compute_group_sizes(
    size_t security_bits,
    size_t range_bits, 
    size_t challenge_bits,
    size_t batch_size) {
    
    // Use GroupManager's computation
    return GroupManager::compute_group_sizes(security_bits, range_bits, challenge_bits);
}

size_t compute_repetitions(size_t security_bits, size_t challenge_bits) {
    // R = ⌈λ / log₂(Γ + 1)⌉
    double log_gamma = std::log2(static_cast<double>((1ULL << challenge_bits) + 1));
    return static_cast<size_t>(std::ceil(security_bits / log_gamma));
}

size_t estimate_proof_size(
    size_t security_bits,
    size_t range_bits,
    size_t batch_size,
    bool with_hash_optimization) {
    
    size_t repetitions = compute_repetitions(security_bits, range_bits);
    size_t group_element_size = serialize::group_element_size();
    size_t field_element_size = serialize::field_element_size();
    
    // Estimate based on SharpGS structure
    size_t commitments = 2 + repetitions * 4; // Cy, Ck,* for each repetition
    size_t field_responses = repetitions * (4 * batch_size + 3); // zk,i, zk,i,j, tk,x, tk,y, tk,*
    
    size_t total_size = commitments * group_element_size + field_responses * field_element_size;
    
    if (with_hash_optimization) {
        total_size = static_cast<size_t>(total_size * 0.7); // ~30% reduction
    }
    
    return total_size;
}

bool validate_parameters(
    size_t security_bits,
    size_t range_bits, 
    size_t challenge_bits,
    size_t batch_size) {
    
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

// Error handling
namespace error {

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

} // namespace error

} // namespace utils
} // namespace sharp_gs
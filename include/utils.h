#pragma once

#include <vector>
#include <string>
#include <functional>
#include <random>
#include <chrono>      // FIX: Added missing include
#include <cstring>     // FIX: Added missing include for memcpy
#include <stdexcept>
#include <optional>
#include <memory>
#include <mcl/bn.hpp>

namespace sharp_gs {

using Fr = mcl::Fr;
using G1 = mcl::G1;

namespace utils {

// Error handling
enum class ErrorCode {
    SUCCESS = 0,
    INVALID_PARAMETERS,
    GROUP_INITIALIZATION_FAILED,
    COMMITMENT_FAILED,
    MASKING_FAILED,
    DECOMPOSITION_FAILED,
    VERIFICATION_FAILED,
    SERIALIZATION_FAILED
};

class SharpGSException : public std::exception {
private:
    ErrorCode code_;
    std::string message_;

public:
    SharpGSException(ErrorCode code, const std::string& message = "");
    ErrorCode code() const { return code_; }
    const char* what() const noexcept override;
};

std::string error_to_string(ErrorCode code);

// Secure randomness
namespace random {
    class SecureRandom {
    private:
        std::random_device rd_;
        std::mt19937_64 gen_;
        
    public:
        SecureRandom() : gen_(rd_()) {}
        
        static SecureRandom& instance() {
            static SecureRandom instance;
            return instance;
        }
        
        static void next_bytes(uint8_t* buffer, size_t size);
        static uint64_t next_uint64();
        static Fr next_field_element();
    };
}

// Three-square decomposition
namespace three_square {
    std::vector<Fr> decompose(const Fr& x, const Fr& B);
    bool verify_decomposition(const Fr& x, const Fr& B, const std::vector<Fr>& y);
    std::vector<std::vector<Fr>> decompose_batch(const std::vector<Fr>& values, const Fr& B);
}

// Polynomial operations
namespace polynomial {
    std::vector<Fr> compute_decomposition_polynomial(
        const Fr& x, const Fr& B, const Fr& gamma, const std::vector<Fr>& y);
    Fr evaluate(const std::vector<Fr>& coefficients, const Fr& point);
    std::vector<Fr> interpolate(const std::vector<Fr>& points, const std::vector<Fr>& values);
}

// Hash functions
namespace hash {
    std::vector<uint8_t> sha256(const std::vector<uint8_t>& input);
    Fr challenge_from_transcript(const std::vector<uint8_t>& transcript);
    std::vector<uint8_t> serialize_point(const G1& point);
    std::vector<uint8_t> serialize_field(const Fr& element);
}

// Timing utilities
namespace timing {
    class Timer {
    private:
        std::chrono::high_resolution_clock::time_point start_time_;  // FIX: Added proper type
        
    public:
        void start();
        double elapsed_ms() const;
        double elapsed_us() const;
        
        template<typename Func>
        double benchmark(Func&& func, size_t iterations = 1) {
            start();
            for (size_t i = 0; i < iterations; ++i) {
                func();
            }
            return elapsed_ms() / iterations;
        }
    };
}

// Parameter utilities
namespace params {
    std::pair<size_t, size_t> compute_group_sizes(
        size_t security_bits, size_t range_bits, size_t challenge_bits, size_t batch_size);
    
    bool validate_parameters(
        size_t security_bits, size_t range_bits, size_t challenge_bits, size_t batch_size);
    
    size_t compute_repetitions(size_t security_bits, size_t challenge_bits);
    size_t estimate_proof_size(size_t security_bits, size_t range_bits, 
                               size_t batch_size, bool use_hash_opt);
}

// Serialization utilities
namespace serialize {
    size_t field_element_size();
    size_t group_element_size();
    std::vector<uint8_t> serialize_field_vector(const std::vector<Fr>& elements);
    std::vector<Fr> deserialize_field_vector(const std::vector<uint8_t>& data);
}

} // namespace utils
} // namespace sharp_gs
#pragma once

#include "groups.h"
#include <vector>
#include <string>
#include <random>

namespace sharp_gs {

/**
 * @brief Utility functions and helpers for SharpGS implementation
 */
namespace utils {

    /**
     * @brief Cryptographically secure random number generator
     */
    class SecureRandom {
    private:
        static std::random_device rd_;
        static std::mt19937_64 gen_;
        
    public:
        static void initialize();
        static uint64_t next_uint64();
        static void next_bytes(uint8_t* buffer, size_t length);
        static Fr next_field_element();
    };

    /**
     * @brief Three-square decomposition utilities
     */
    namespace three_square {
        
        /**
         * @brief Find three squares such that 4x(B-x) + 1 = y1² + y2² + y3²
         * @param x Value in range [0, B]
         * @param B Range bound
         * @return Vector of three field elements [y1, y2, y3] or empty if not found
         */
        std::vector<Fr> decompose(const Fr& x, const Fr& B);

        /**
         * @brief Verify three-square decomposition
         */
        bool verify_decomposition(const Fr& x, const Fr& B, const std::vector<Fr>& squares);

        /**
         * @brief Batch decomposition for multiple values
         */
        std::vector<std::vector<Fr>> decompose_batch(const std::vector<Fr>& values, const Fr& B);
    }

    /**
     * @brief Polynomial operations for SharpGS decomposition proof
     */
    namespace polynomial {
        
        /**
         * @brief Evaluate polynomial at given point
         */
        Fr evaluate(const std::vector<Fr>& coefficients, const Fr& point);

        /**
         * @brief Compute f = z(γB - z) - Σ zi²
         * This should be degree 1 in γ if decomposition is valid
         */
        std::vector<Fr> compute_decomposition_polynomial(
            const Fr& z,           // Masked x value  
            const Fr& gamma,       // Challenge
            const Fr& B,           // Range bound
            const std::vector<Fr>& z_squares  // Masked yi,j values squared
        );

        /**
         * @brief Extract coefficients α0, α1 from polynomial f = α1*γ + α0
         */
        std::pair<Fr, Fr> extract_linear_coefficients(const std::vector<Fr>& poly);
    }

    /**
     * @brief Hash functions for Fiat-Shamir and optimization
     */
    namespace hash {
        
        /**
         * @brief Cryptographic hash function (SHA-256)
         */
        std::vector<uint8_t> sha256(const std::vector<uint8_t>& input);

        /**
         * @brief Hash group elements and field elements
         */
        std::vector<uint8_t> hash_transcript(
            const std::vector<G1>& group_elements,
            const std::vector<Fr>& field_elements
        );

        /**
         * @brief Generate challenge from transcript (Fiat-Shamir)
         */
        Fr challenge_from_transcript(const std::vector<uint8_t>& transcript);

        /**
         * @brief Hash optimization for reducing communication
         */
        std::vector<uint8_t> hash_commitments(const std::vector<G1>& commitments);
    }

    /**
     * @brief Serialization utilities
     */
    namespace serialize {
        
        /**
         * @brief Serialize field element to bytes
         */
        std::vector<uint8_t> field_to_bytes(const Fr& element);

        /**
         * @brief Deserialize field element from bytes
         */
        Fr field_from_bytes(const std::vector<uint8_t>& bytes);

        /**
         * @brief Serialize group element to bytes
         */
        std::vector<uint8_t> group_to_bytes(const G1& element);

        /**
         * @brief Deserialize group element from bytes
         */
        G1 group_from_bytes(const std::vector<uint8_t>& bytes);

        /**
         * @brief Get serialized size estimates
         */
        size_t field_element_size();
        size_t group_element_size();
    }

    /**
     * @brief Timing and benchmarking utilities
     */
    namespace timing {
        
        class Timer {
        private:
            std::chrono::high_resolution_clock::time_point start_time_;
            bool running_;
            
        public:
            Timer();
            void start();
            void stop();
            double elapsed_ms() const;
            double elapsed_us() const;
        };

        /**
         * @brief Benchmark a function
         */
        template<typename Func>
        double benchmark(Func&& func, size_t iterations = 1) {
            Timer timer;
            timer.start();
            for (size_t i = 0; i < iterations; ++i) {
                func();
            }
            timer.stop();
            return timer.elapsed_ms() / iterations;
        }
    }

    /**
     * @brief Parameter computation utilities
     */
    namespace params {
        
        /**
         * @brief Compute required group sizes for security
         */
        std::pair<size_t, size_t> compute_group_sizes(
            size_t security_bits,
            size_t range_bits, 
            size_t challenge_bits,
            size_t batch_size = 1
        );

        /**
         * @brief Compute number of repetitions needed
         */
        size_t compute_repetitions(size_t security_bits, size_t challenge_bits);

        /**
         * @brief Estimate proof size in bytes
         */
        size_t estimate_proof_size(
            size_t security_bits,
            size_t range_bits,
            size_t batch_size = 1,
            bool with_hash_optimization = true
        );

        /**
         * @brief Validate parameter consistency
         */
        bool validate_parameters(
            size_t security_bits,
            size_t range_bits, 
            size_t challenge_bits,
            size_t batch_size
        );
    }

    /**
     * @brief Error handling and logging
     */
    namespace error {
        
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

        std::string error_to_string(ErrorCode code);
        
        class SharpGSException : public std::exception {
        private:
            ErrorCode code_;
            std::string message_;
            
        public:
            SharpGSException(ErrorCode code, const std::string& message = "");
            const char* what() const noexcept override;
            ErrorCode code() const { return code_; }
        };
    }

} // namespace utils
} // namespace sharp_gs
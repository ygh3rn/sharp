#include <mcl/bn.hpp>
#include <iostream>
#include <chrono>
#include <vector>
#include <iomanip>
#include <random>
#include <cmath>

#include "sharp_gs.h"
#include "pedersen.h"
#include "three_squares.h"

using namespace mcl;
using namespace std;
using namespace std::chrono;

class SharpGSBenchmark {
private:
    mt19937 rng{random_device{}()};
    
    struct BenchmarkResult {
        string operation;
        size_t batch_size;
        size_t log_b;
        size_t repetitions;
        double avg_time_ms;
        size_t proof_size_bytes;
        size_t iterations;
    };
    
    vector<BenchmarkResult> results;
    
    template<typename Func>
    double benchmark_operation(Func&& func, size_t iterations = 10) {
        vector<double> times;
        
        for (size_t i = 0; i < iterations; i++) {
            auto start = high_resolution_clock::now();
            func();
            auto end = high_resolution_clock::now();
            
            auto duration = duration_cast<microseconds>(end - start);
            times.push_back(duration.count() / 1000.0);
        }
        
        if (times.size() >= 3) {
            sort(times.begin(), times.end());
            double sum = 0;
            for (size_t i = 1; i < times.size() - 1; i++) {
                sum += times[i];
            }
            return sum / (times.size() - 2);
        } else {
            double sum = 0;
            for (double t : times) sum += t;
            return sum / times.size();
        }
    }
    
    Fr create_range_bound(size_t log_b) {
        // Create actual 2^log_b values for realistic testing
        Fr result;
        if (log_b <= 32) {
            // 2^32 - 1
            result.setStr("4294967295");
        } else if (log_b <= 64) {
            // 2^64 - 1  
            result.setStr("18446744073709551615");
        } else {
            // 2^128 - 1
            result.setStr("340282366920938463463374607431768211455");
        }
        return result;
    }
    
    Fr random_value_in_range(size_t log_b) {
        // Use small random values that work with three squares decomposition
        uint32_t val = rng() % 10000;
        return Fr(val);
    }
    
    size_t calculate_proof_size(const SharpGS::Proof& proof, const SharpGS::PublicParameters& pp) {
        // Serialize the entire proof structure to get actual byte size
        vector<uint8_t> proof_bytes;
        
        // Serialize entire proof structure
        serialize_proof_to_bytes(proof, proof_bytes);
        
        return proof_bytes.size();
    }
    
    void serialize_proof_to_bytes(const SharpGS::Proof& proof, vector<uint8_t>& bytes) {
        bytes.clear();
        
        // Serialize first message
        append_g1_to_bytes(proof.first_msg.commitment_y, bytes);
        
        for (const auto& point : proof.first_msg.mask_commitments_x) {
            append_g1_to_bytes(point, bytes);
        }
        for (const auto& point : proof.first_msg.mask_commitments_y) {
            append_g1_to_bytes(point, bytes);
        }
        for (const auto& point : proof.first_msg.poly_commitments_star) {
            append_g1_to_bytes(point, bytes);
        }
        for (const auto& point : proof.first_msg.mask_poly_commitments) {
            append_g1_to_bytes(point, bytes);
        }
        
        // Serialize response
        for (const auto& z_vec : proof.response.z_values) {
            for (const auto& fr_val : z_vec) {
                append_fr_to_bytes(fr_val, bytes);
            }
        }
        for (const auto& z_mat : proof.response.z_squares) {
            for (const auto& z_vec : z_mat) {
                for (const auto& fr_val : z_vec) {
                    append_fr_to_bytes(fr_val, bytes);
                }
            }
        }
        for (const auto& fr_val : proof.response.t_x) {
            append_fr_to_bytes(fr_val, bytes);
        }
        for (const auto& fr_val : proof.response.t_y) {
            append_fr_to_bytes(fr_val, bytes);
        }
        for (const auto& fr_val : proof.response.t_star) {
            append_fr_to_bytes(fr_val, bytes);
        }
    }
    
    void append_g1_to_bytes(const G1& point, vector<uint8_t>& bytes) {
        uint8_t temp[256];
        size_t len = point.serialize(temp, sizeof(temp));
        bytes.insert(bytes.end(), temp, temp + len);
    }
    
    void append_fr_to_bytes(const Fr& element, vector<uint8_t>& bytes) {
        uint8_t temp[256]; 
        size_t len = element.serialize(temp, sizeof(temp));
        bytes.insert(bytes.end(), temp, temp + len);
    }

public:
    void run_benchmarks() {
        cout << "SharpGS Performance Benchmark" << endl;
        cout << "=============================" << endl;
        
        initPairing(BN_SNARK1);
        
        // Test configurations from paper + large ranges
        vector<size_t> batch_sizes = {1, 8, 16};
        vector<size_t> log_b_values = {32, 64, 128}; // 2^32, 2^64, 2^128
        
        for (size_t log_b : log_b_values) {
            Fr B = create_range_bound(log_b);
            
            for (size_t N : batch_sizes) {
                cout << "\nTesting: N=" << N << ", log B=" << log_b << " (B≈2^" << log_b << ")" << endl;
                cout << string(50, '-') << endl;
                
                benchmark_full_protocol(N, B, log_b);
                benchmark_individual_phases(N, B, log_b);
            }
        }
        
        cout << "\n" << string(80, '=') << endl;
        print_table();
        cout << "\n" << string(80, '=') << endl;
        analyze_performance();
    }

private:
    void benchmark_full_protocol(size_t N, const Fr& B, size_t log_b) {
        auto pp = SharpGS::setup(N, B, 128);
        
        size_t actual_proof_size = 0;
        double protocol_time = benchmark_operation([&]() {
            SharpGS::Witness witness;
            witness.values.clear();
            for (size_t i = 0; i < N; i++) {
                witness.values.push_back(random_value_in_range(log_b));
            }
            witness.randomness.setByCSPRNG();
            
            auto commit = PedersenMultiCommitment::commit(pp.ck_com, witness.values, witness.randomness);
            SharpGS::Statement stmt;
            stmt.commitment = commit.value;
            stmt.B = B;
            
            auto first_msg = SharpGS::prove_first(pp, stmt, witness);
            auto challenge = SharpGS::generate_challenge(pp);
            auto response = SharpGS::prove_response(pp, stmt, witness, first_msg, challenge);
            
            SharpGS::Proof proof;
            proof.first_msg = first_msg;
            proof.response = response;
            
            // MEASURE ACTUAL PROOF SIZE HERE
            actual_proof_size = calculate_proof_size(proof, pp);
            
            bool verified = SharpGS::verify(pp, stmt, proof, challenge);
            if (!verified) throw runtime_error("Verification failed");
        }, 5);
        
        results.push_back({"Full Protocol", N, log_b, pp.repetitions, protocol_time, actual_proof_size, 5});
        cout << "Full Protocol: " << fixed << setprecision(1) << protocol_time << " ms, " 
             << actual_proof_size << " bytes" << endl;
    }
    
    void benchmark_individual_phases(size_t N, const Fr& B, size_t log_b) {
        auto pp = SharpGS::setup(N, B, 128);
        
        SharpGS::Witness witness;
        witness.values.clear();
        for (size_t i = 0; i < N; i++) {
            witness.values.push_back(random_value_in_range(log_b));
        }
        witness.randomness.setByCSPRNG();
        
        auto commit = PedersenMultiCommitment::commit(pp.ck_com, witness.values, witness.randomness);
        SharpGS::Statement stmt;
        stmt.commitment = commit.value;
        stmt.B = B;
        
        // Prove First
        double prove_first_time = benchmark_operation([&]() {
            auto first_msg = SharpGS::prove_first(pp, stmt, witness);
        }, 10);
        
        results.push_back({"Prove First", N, log_b, pp.repetitions, prove_first_time, 0, 10});
        cout << "  Prove First: " << fixed << setprecision(1) << prove_first_time << " ms" << endl;
        
        // Generate Challenge
        double challenge_time = benchmark_operation([&]() {
            auto challenge = SharpGS::generate_challenge(pp);
        }, 50);
        
        results.push_back({"Generate Challenge", N, log_b, pp.repetitions, challenge_time, 0, 50});
        cout << "  Generate Challenge: " << fixed << setprecision(2) << challenge_time << " ms" << endl;
        
        // Prove Response
        auto first_msg = SharpGS::prove_first(pp, stmt, witness);
        auto challenge = SharpGS::generate_challenge(pp);
        
        double prove_response_time = benchmark_operation([&]() {
            auto response = SharpGS::prove_response(pp, stmt, witness, first_msg, challenge);
        }, 10);
        
        results.push_back({"Prove Response", N, log_b, pp.repetitions, prove_response_time, 0, 10});
        cout << "  Prove Response: " << fixed << setprecision(1) << prove_response_time << " ms" << endl;
        
        // Verify
        auto response = SharpGS::prove_response(pp, stmt, witness, first_msg, challenge);
        SharpGS::Proof proof;
        proof.first_msg = first_msg;
        proof.response = response;
        
        double verify_time = benchmark_operation([&]() {
            bool verified = SharpGS::verify(pp, stmt, proof, challenge);
            if (!verified) throw runtime_error("Verification failed");
        }, 15);
        
        results.push_back({"Verify", N, log_b, pp.repetitions, verify_time, 0, 15});
        cout << "  Verify: " << fixed << setprecision(1) << verify_time << " ms" << endl;
        
        // Three Squares Decomposition
        double decomp_time = benchmark_operation([&]() {
            for (const Fr& val : witness.values) {
                Fr range_val = ThreeSquares::compute_range_value(val, B);
                auto decomp = ThreeSquares::decompose(range_val);
                if (!decomp || !decomp->valid) {
                    throw runtime_error("Decomposition failed");
                }
            }
        }, 5);
        
        results.push_back({"Three Squares Decomp", N, log_b, 0, decomp_time, 0, 5});
        cout << "  Three Squares (×" << N << "): " << fixed << setprecision(1) << decomp_time << " ms" << endl;
    }
    
    void print_table() {
        cout << "SharpGS Performance Table (λ=128)" << endl;
        cout << left << setw(20) << "Operation" 
             << setw(5) << "N" 
             << setw(8) << "log B" 
             << setw(5) << "R" 
             << setw(12) << "Time (ms)" 
             << setw(12) << "Size (bytes)" 
             << setw(8) << "Iters" << endl;
        cout << string(70, '-') << endl;
        
        for (const auto& result : results) {
            cout << left << setw(20) << result.operation
                 << setw(5) << result.batch_size
                 << setw(8) << result.log_b
                 << setw(5) << result.repetitions
                 << setw(12) << fixed << setprecision(1) << result.avg_time_ms
                 << setw(12) << (result.proof_size_bytes > 0 ? to_string(result.proof_size_bytes) : "-")
                 << setw(8) << result.iterations << endl;
        }
        
        cout << "\nComparison with Table 1 (λ=128, log B=64):" << endl;
        cout << "Paper SharpGS: N=1→360B, N=8→1070B, N=16→1882B" << endl;
        
        for (size_t N : {1, 8, 16}) {
            auto it = find_if(results.begin(), results.end(), [N](const BenchmarkResult& r) {
                return r.operation == "Full Protocol" && r.batch_size == N && r.log_b == 64;
            });
            if (it != results.end()) {
                cout << "Our impl: N=" << N << "→" << it->proof_size_bytes << "B";
                if (N == 1) cout << " (vs 360B paper)";
                else if (N == 8) cout << " (vs 1070B paper)";
                else if (N == 16) cout << " (vs 1882B paper)";
                cout << endl;
            }
        }
    }
    
    void analyze_performance() {
        cout << "Performance Analysis" << endl;
        cout << "===================" << endl;
        
        // Scaling by batch size
        cout << "\nBatch Size Scaling (log B=64):" << endl;
        for (size_t N : {1, 8, 16}) {
            auto it = find_if(results.begin(), results.end(), [N](const BenchmarkResult& r) {
                return r.operation == "Full Protocol" && r.batch_size == N && r.log_b == 64;
            });
            if (it != results.end()) {
                cout << "N=" << N << ": " << fixed << setprecision(1) << it->avg_time_ms 
                     << "ms, " << it->proof_size_bytes << " bytes" << endl;
            }
        }
        
        // Scaling by range size
        cout << "\nRange Size Scaling (N=1):" << endl;
        for (size_t log_b : {32, 64, 128}) {
            auto it = find_if(results.begin(), results.end(), [log_b](const BenchmarkResult& r) {
                return r.operation == "Full Protocol" && r.batch_size == 1 && r.log_b == log_b;
            });
            if (it != results.end()) {
                cout << "2^" << log_b << ": " << fixed << setprecision(1) << it->avg_time_ms 
                     << "ms, " << it->proof_size_bytes << " bytes" << endl;
            }
        }
        
        // Efficiency metrics
        cout << "\nEfficiency Metrics:" << endl;
        auto n1 = find_if(results.begin(), results.end(), [](const BenchmarkResult& r) {
            return r.operation == "Full Protocol" && r.batch_size == 1 && r.log_b == 64;
        });
        auto n8 = find_if(results.begin(), results.end(), [](const BenchmarkResult& r) {
            return r.operation == "Full Protocol" && r.batch_size == 8 && r.log_b == 64;
        });
        
        if (n1 != results.end() && n8 != results.end()) {
            double time_efficiency = (n1->avg_time_ms * 8) / n8->avg_time_ms;
            double size_efficiency = (double)(n1->proof_size_bytes * 8) / n8->proof_size_bytes;
            cout << "Batch efficiency (8×N=1 vs N=8):" << endl;
            cout << "  Time: " << fixed << setprecision(2) << time_efficiency << "x speedup" << endl;
            cout << "  Size: " << fixed << setprecision(2) << size_efficiency << "x compression" << endl;
            cout << "  Time per proof (N=8): " << fixed << setprecision(1) 
                 << n8->avg_time_ms / 8 << " ms" << endl;
            cout << "  Size per proof (N=8): " << n8->proof_size_bytes / 8 << " bytes" << endl;
        }
    }
};

int main() {
    try {
        SharpGSBenchmark benchmark;
        benchmark.run_benchmarks();
        return 0;
    } catch (const exception& e) {
        cerr << "Benchmark error: " << e.what() << endl;
        return 1;
    }
}
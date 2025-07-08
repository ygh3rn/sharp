# SharpGS: Optimized Range Proofs with Group Switching

A C++ implementation of the SharpGS range proof protocol from the paper ["Sharp: Short Relaxed Range Proofs"](https://eprint.iacr.org/2024/1751) by Couteau, Goudarzi, Klooß, and Reichle.

## Overview

SharpGS is an optimized range proof system that allows proving that committed values lie within specified ranges [0, B] with significant efficiency improvements over previous approaches like Bulletproofs. Key features include:

- **Group Switching**: Uses different elliptic curve groups for commitment and decomposition phases
- **Batch Proofs**: Efficiently prove multiple range statements simultaneously  
- **Polynomial Techniques**: Novel polynomial-based approach for the decomposition proof
- **Relaxed Soundness**: Binds to rational representatives while maintaining practical security
- **Transparent Setup**: No trusted setup required (unlike some alternatives)

## Technical Features

### Core Protocol
- **Three-Square Decomposition**: Proves range membership via 4x(B-x) + 1 = Σ yᵢ²
- **Polynomial Proof**: Shows decomposition validity through degree constraints
- **Masking Schemes**: Uniform rejection sampling for zero-knowledge
- **Multiple Groups**: Gcom (order p) for commitments, G3sq (order q) for decomposition

### Performance Improvements
- **Communication**: 34-75% smaller proofs than CKLR, competitive with Bulletproofs
- **Computation**: 10-20x faster proving than Bulletproofs in benchmarks
- **Batching**: Near-constant overhead for multiple simultaneous proofs
- **Flexibility**: Works with standard 256-bit elliptic curves

## Mathematical Background

SharpGS proves that a committed value x satisfies x ∈ [0, B] by:

1. **Commitment Phase**: Commit to x and decomposition values yᵢ,ⱼ
2. **Challenge Phase**: Verifier sends random challenges γₖ  
3. **Response Phase**: Prover reveals masked values zₖ,ᵢ = γₖxᵢ + masking
4. **Verification**: Check polynomial f(γ) = z(γB - z) - Σzᵢ² has degree 1

The protocol achieves:
- **Soundness**: Knowledge error (2/(Γ+1))^R for R repetitions
- **Zero-Knowledge**: Statistical hiding via rejection sampling
- **Efficiency**: O(log B) proof size, O(B) prover time

## Project Structure

```
SharpGS/
├── CMakeLists.txt           # Build configuration
├── README.md               # This file
├── LICENSE                 # MIT license
├── .gitignore             # Git ignore rules
├── include/               # Header files
│   ├── sharp_gs.h         # Main protocol interface
│   ├── groups.h           # Elliptic curve group management
│   ├── commitments.h      # Pedersen multi-commitments
│   ├── polynomial.h       # Polynomial operations
│   ├── masking.h          # Zero-knowledge masking
│   └── utils.h            # Utilities and helpers
├── src/                   # Implementation files
│   ├── sharp_gs.cpp       # Main protocol implementation
│   ├── groups.cpp         # Group operations
│   ├── commitments.cpp    # Commitment schemes
│   ├── polynomial.cpp     # Polynomial arithmetic
│   ├── masking.cpp        # Masking schemes
│   └── utils.cpp          # Utility functions
├── tests/
│   └── test_sharp_gs.cpp  # Comprehensive test suite
└── examples/
    └── demo.cpp           # Usage examples and demonstrations
```

## Dependencies

- **MCL Library**: High-performance elliptic curve and pairing library
- **CMake**: Build system (version 3.12+)
- **C++17**: Modern C++ compiler
- **OpenMP**: Optional, for parallel operations

## Installation

### 1. Install MCL Library

```bash
# Clone and build MCL
git clone https://github.com/herumi/mcl.git
cd mcl
make -j$(nproc)
sudo make install
```

### 2. Build SharpGS

```bash
# Clone the repository
git clone <your-repo-url>
cd SharpGS

# Create build directory
mkdir build && cd build

# Configure and build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

# Run tests
./test_sharp_gs
```

### 3. System Requirements

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y cmake g++ libomp-dev

# macOS  
brew install cmake libomp
```

## Usage Examples

### Basic Range Proof

```cpp
#include "sharp_gs.h"
using namespace sharp_gs;

// Initialize protocol
SharpGS::Parameters params(128, 64, 1);  // 128-bit security, 64-bit range, batch size 1
SharpGS protocol(params);
protocol.initialize();

// Create statement and witness
std::vector<Fr> values = {Fr(42)};  // Prove 42 ∈ [0, 2^64-1]
Fr range_bound = Fr(1) << 64;

auto [statement, witness] = sharp_gs_utils::create_statement_and_witness(
    values, range_bound, *protocol.groups_
);

// Generate proof
auto proof = protocol.prove(statement, witness);
if (proof) {
    std::cout << "Proof generated successfully!\n";
    std::cout << "Proof size: " << proof->size_bytes() << " bytes\n";
}

// Verify proof
bool valid = protocol.verify(statement, *proof);
std::cout << "Proof verification: " << (valid ? "PASSED" : "FAILED") << "\n";
```

### Batch Range Proofs

```cpp
// Prove multiple values simultaneously
SharpGS::Parameters batch_params(128, 32, 8);  // Batch of 8 values
SharpGS batch_protocol(batch_params);
batch_protocol.initialize();

std::vector<Fr> batch_values = {
    Fr(10), Fr(20), Fr(30), Fr(40), 
    Fr(50), Fr(60), Fr(70), Fr(80)
};
Fr range_32bit = Fr(1) << 32;

auto [batch_stmt, batch_wit] = sharp_gs_utils::create_statement_and_witness(
    batch_values, range_32bit, *batch_protocol.groups_
);

auto batch_proof = batch_protocol.prove(batch_stmt, batch_wit);
std::cout << "Batch proof size: " << batch_proof->size_bytes() << " bytes\n";
std::cout << "Per-proof overhead: " << batch_proof->size_bytes() / 8 << " bytes\n";
```

### Interactive Protocol

```cpp
// Prover side
auto prover = protocol.create_prover(statement, witness);
auto first_message = prover->first_flow();

// Verifier side  
auto verifier = protocol.create_verifier(statement);
verifier->receive_first_flow(*first_message);
auto challenges = verifier->generate_challenges();

// Continue interaction
prover->receive_challenges(challenges);
auto third_message = prover->third_flow();
verifier->receive_third_flow(*third_message);

bool interactive_valid = verifier->verify();
```

## Performance Characteristics

### Proof Sizes (bytes)

| Security | Range | Batch Size | SharpGS | Bulletproofs | Improvement |
|----------|-------|------------|---------|--------------|-------------|
| 128-bit  | 32-bit| 1          | 335     | 608          | 45% smaller |
| 128-bit  | 64-bit| 1          | 389     | 672          | 42% smaller |
| 128-bit  | 32-bit| 8          | 932     | 800          | -16% larger |
| 128-bit  | 64-bit| 8          | 1119    | 864          | -30% larger |

### Computational Performance

- **Prover**: 10-20x faster than Bulletproofs
- **Verifier**: 2-4x faster than Bulletproofs  
- **Memory**: O(N + log B) working space
- **Parallelization**: Batch operations parallelize well

### Security Parameters

```cpp
// Recommended parameter sets
SharpGS::Parameters conservative(128, 64, 1);   // Single 64-bit range, max security
SharpGS::Parameters balanced(112, 32, 4);       // Batch of 4 32-bit ranges  
SharpGS::Parameters performance(96, 16, 16);    // Large batch, smaller ranges
```

## Testing and Validation

### Comprehensive Test Suite

```bash
# Run all tests
./test_sharp_gs

# Expected output:
# PASS Three-Square Decomposition
# PASS Polynomial Operations  
# PASS Commitment Schemes
# PASS Masking Schemes
# PASS SharpGS Protocol - Single Value
# PASS SharpGS Protocol - Batch Values
# PASS Interactive Protocol
# PASS Security Properties
# PASS Performance Benchmarks
# Tests Passed: 45/45 - All passed!
```

### Benchmarking

```cpp
// Built-in performance testing
auto estimate = sharp_gs_utils::estimate_performance(params);
std::cout << "Estimated prover time: " << estimate.prover_time_ms << "ms\n";
std::cout << "Estimated verifier time: " << estimate.verifier_time_ms << "ms\n";
std::cout << "Estimated proof size: " << estimate.proof_size_bytes << " bytes\n";
```

## Advanced Features

### Hash Optimization

```cpp
// Reduce communication by ~30% using hash commitments
SharpGS::Parameters optimized_params(128, 64, 1);
optimized_params.use_hash_optimization = true;
```

### Custom Parameters

```cpp
// Fine-tune for specific applications
SharpGS::Parameters custom_params;
custom_params.security_bits = 128;
custom_params.range_bits = 40;           // Custom range size
custom_params.challenge_bits = 100;      // Smaller challenges, more repetitions
custom_params.batch_size = 12;           // Application-specific batch size
custom_params.masking_overhead = 60;     // Higher security margin
```

### Group Switching Configuration

```cpp
// The protocol automatically selects optimal group sizes:
// - Gcom: ~256 bits for commitments (efficiency)
// - G3sq: ~350 bits for decomposition (security)
// This provides the best of both worlds
```

## Applications

SharpGS is suitable for:

- **Anonymous Credentials**: Age verification, attribute ranges
- **Confidential Transactions**: Balance non-negativity proofs
- **Auctions**: Bid validity without revealing amounts  
- **IoT Security**: Resource-constrained range proofs
- **Regulatory Compliance**: Proving values within legal bounds

## Security Considerations

### Relaxed Soundness

SharpGS provides "relaxed soundness" - it binds the prover to rational representatives rather than strict integers. This is sufficient for most applications but requires care in:

- **Homomorphic Operations**: Limited number of additions before overflow
- **Cross-Protocol Usage**: May need integer binding for some applications

### Mitigation Strategies

```cpp
// For applications requiring integer binding:
// 1. Use four-square decomposition (exact range membership)
// 2. Limit number of homomorphic operations
// 3. Add auxiliary integer binding proofs when needed
```

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## References

- **[Sharp Paper]**: Couteau, G., Goudarzi, D., Klooß, M., Reichle, M. "Sharp: Short Relaxed Range Proofs"
- **[CKLR21]**: Couteau, G., et al. "Efficient Range Proofs with Transparent Setup from Bounded Integer Commitments" 
- **[Bulletproofs]**: Bünz, B., et al. "Bulletproofs: Short Proofs for Confidential Transactions and More"
- **[MCL Library]**: https://github.com/herumi/mcl

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Original Sharp paper authors for the innovative protocol design
- MCL library developers for high-performance cryptographic primitives
- Zero-knowledge proof research community for foundational work
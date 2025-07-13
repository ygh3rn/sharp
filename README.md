# SharpGS: Short Relaxed Range Proofs

A C++ implementation of the SharpGS range proof algorithm from the research paper "Sharp: Short Relaxed Range Proofs" by Couteau, Goudarzi, Klooß, and Reichle.

## Overview

SharpGS is an optimized range proof scheme that allows proving that committed values lie within a specified range [0, B] using square decomposition techniques. Key features include:

- **Group Switching**: Uses different cryptographic groups for commitment and decomposition proof phases
- **Batching**: Efficient batch proofs for multiple range statements simultaneously  
- **Square Decomposition**: Based on three-square decomposition instead of binary decomposition
- **Relaxed Soundness**: Provides relaxed soundness guarantees with significant efficiency improvements

## Features

- ✅ Pedersen multi-commitments with homomorphic properties
- ✅ Three squares decomposition using PARI/GP integration
- ✅ Interactive SharpGS protocol implementation
- ✅ Batch range proofs for multiple values
- ✅ Comprehensive test suite with benchmarks
- ✅ Group switching between commitment and proof groups

## Prerequisites

### Required Dependencies

```bash
# Install MCL cryptographic library
git clone https://github.com/herumi/mcl.git
cd mcl && make -j$(nproc) && sudo make install

# Install PARI/GP for three squares decomposition
sudo apt update
sudo apt install -y pari-gp

# System requirements
sudo apt install -y cmake g++ build-essential
```

### System Requirements

- **Compiler**: GCC 7+ or Clang 6+ with C++17 support
- **CMake**: Version 3.12 or higher
- **MCL Library**: For elliptic curve operations
- **PARI/GP**: For three squares decomposition computation

## Building

```bash
# Clone the repository
git clone <repository-url>
cd sharp-gs

# Create build directory
mkdir build && cd build

# Configure and build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

# Run tests
./test_sharp_gs

# Or use the convenience target
make run
```

## Usage

### Basic Range Proof

```cpp
#include <mcl/bn.hpp>
#include "sharp_gs.h"

// Initialize pairing
mcl::initPairing(mcl::BN_SNARK1);

// Setup parameters for range [0, 100]
Fr B;
B.setInt(100);
auto pp = SharpGS::setup(1, B, 128);  // 1 value, range [0,100], 128-bit security

// Create witness
SharpGS::Witness witness;
witness.values = {Fr(42)};  // Prove that 42 ∈ [0, 100]
witness.randomness.setByCSPRNG();

// Create commitment
auto commit = PedersenMultiCommitment::commit(pp.ck_com, witness.values, witness.randomness);
SharpGS::Statement stmt;
stmt.commitment = commit.value;
stmt.B = B;

// Generate proof
auto first_msg = SharpGS::prove_first(pp, stmt, witness);
auto challenge = SharpGS::generate_challenge(pp);
auto response = SharpGS::prove_response(pp, stmt, witness, first_msg, challenge);

SharpGS::Proof proof;
proof.first_msg = first_msg;
proof.response = response;

// Verify proof
bool verified = SharpGS::verify(pp, stmt, proof, challenge);
```

### Batch Range Proof

```cpp
// Setup for 4 values
auto pp = SharpGS::setup(4, B, 128);

// Create batch witness
SharpGS::Witness witness;
witness.values = {Fr(10), Fr(25), Fr(42), Fr(63)};  // All in [0, 100]
witness.randomness.setByCSPRNG();

// Rest of the protocol is identical
// The proof will be more efficient than 4 individual proofs
```

## Algorithm Details

### SharpGS Protocol

The SharpGS protocol consists of the following phases:

1. **Setup**: Generate commitment keys for both groups
2. **First Message**: 
   - Compute three-square decomposition: `4x(B-x) + 1 = y₁² + y₂² + y₃²`
   - Commit to square decomposition values
   - Generate masked commitments for zero-knowledge
3. **Challenge**: Verifier sends random challenges γₖ
4. **Response**: 
   - Compute masked responses `zₖ,ᵢ = γₖ·xᵢ + x̃ₖ,ᵢ`
   - Provide polynomial coefficients proving decomposition
5. **Verification**: Check linear relations and polynomial constraints

### Three Squares Decomposition

The implementation uses PARI/GP for computing three squares decomposition:

```gp
threesquares(n) = 
  /* Returns [x, y, z] such that n = x² + y² + z² if possible */
```

This is called via process execution and output parsing for integration with C++.

### Group Switching

SharpGS uses two elliptic curve groups:
- **Gcom**: For value commitments (can be 256-bit for efficiency)
- **G3sq**: For decomposition proofs (larger group for security requirements)

## Project Structure

```
include/
├── sharp_gs.h           # Main SharpGS protocol interface
├── pedersen.h           # Pedersen multi-commitment scheme
└── three_squares.h      # Three squares decomposition

src/
├── sharp_gs.cpp         # SharpGS protocol implementation
├── pedersen.cpp         # Pedersen commitment implementation
└── three_squares.cpp    # PARI/GP integration for three squares

tests/
└── test_sharp_gs.cpp    # Comprehensive test suite

CMakeLists.txt           # Build configuration
LICENSE                  # MIT license
README.md               # This file
.gitignore              # Git ignore rules
```

## Performance

Based on the research paper, SharpGS provides significant improvements over Bulletproofs:

- **Proof Size**: ~34% smaller than CKLR, ~50% smaller than Bulletproofs
- **Prover Time**: 11-17x faster than Bulletproofs for single proofs
- **Verifier Time**: 2-4x faster than Bulletproofs
- **Batch Efficiency**: Excellent scaling for multiple proofs

## Security

SharpGS provides **relaxed soundness**, meaning:
- Honest provers with integer values get standard soundness
- Malicious provers are bound to rational values in the range
- Can be upgraded to standard soundness using additional techniques

Security level is determined by:
- Challenge space size (Γ)
- Number of repetitions (R)
- Target security parameter (λ)

## Limitations

1. **Relaxed Soundness**: Not suitable for all applications without additional measures
2. **PARI/GP Dependency**: Requires external process calls for three squares computation
3. **Implementation Status**: This is a minimal working implementation for research/educational purposes

## Research Paper

This implementation is based on:

**"Sharp: Short Relaxed Range Proofs"**  
*Geoffroy Couteau, Dahmun Goudarzi, Michael Klooß, Michael Reichle*  
*October 18, 2024*

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

This is a research implementation. For production use, consider:
- More robust error handling
- Optimized field arithmetic
- Security auditing
- Extended test coverage

---

*This implementation is for educational and research purposes. Mathematical rigor and correctness are prioritized over performance optimization.*
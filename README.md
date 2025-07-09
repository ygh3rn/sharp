# Sharp: Short Relaxed Range Proofs

A C++ implementation of the SharpGS protocol from the research paper ["Sharp: Short Relaxed Range Proofs"](https://eprint.iacr.org/2024/1566) by Couteau et al.

## Overview

SharpGS is an efficient zero-knowledge range proof system that allows proving a committed value lies within a given range [0, B] without revealing the actual value. This implementation provides:

- **Efficient range proofs** based on square decomposition
- **Group switching** between commitment and decomposition groups  
- **Batching support** for multiple range proofs
- **Transparent setup** with no trusted parameters

## Features

- ✅ **Core SharpGS Protocol** - Complete implementation of Algorithm 1
- ✅ **NTT-based Polynomial Operations** - Efficient polynomial arithmetic
- ✅ **Pedersen Commitments** - Multi-value commitment scheme
- ✅ **Interactive & Non-interactive** modes (Fiat-Shamir)
- ✅ **Comprehensive Tests** - Full test suite with benchmarks
- ✅ **Example Demonstrations** - Working examples and demos

## Dependencies

- **MCL Library** - Pairing-based cryptography library
- **CMake 3.12+** - Build system
- **C++17** - Modern C++ standard

### Installing MCL

```bash
# Clone and build MCL
git clone https://github.com/herumi/mcl.git
cd mcl
make -j$(nproc)
sudo make install
```

## Building

```bash
# Clone the repository
git clone <repository-url>
cd sharp

# Build the project
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

## Usage

### Basic Range Proof

```cpp
#include "sharpgs.h"

// Initialize pairing
initPairing(BN254);

// Setup parameters
SharpGSParams params(128, 32);  // 128-bit security, 32-bit range
SharpGSPublicParams pp = SharpGS::setup(params);

// Create witness (secret value and randomness)
Fr secret_value = Utils::from_int(12345);
auto [commit, randomness] = PedersenCommitment::commit(pp.ck_com, secret_value);

SharpGSWitness witness({secret_value}, randomness);
SharpGSStatement statement(commit, Fr(1ULL << 32));

// Generate proof
SharpGSProof proof = SharpGS::prove(pp, statement, witness);

// Verify proof  
bool is_valid = SharpGS::verify(pp, statement, proof);
```

### Batch Range Proof

```cpp
// Multiple values
vector<Fr> values = {Utils::from_int(100), Utils::from_int(200), Utils::from_int(300)};
auto [batch_commit, batch_rand] = PedersenCommitment::commit(pp.ck_com, values);

SharpGSWitness batch_witness(values, batch_rand);
SharpGSStatement batch_statement(batch_commit, Fr(1ULL << 16));

// Single proof for all values
SharpGSProof batch_proof = SharpGS::prove(pp, batch_statement, batch_witness);
bool batch_valid = SharpGS::verify(pp, batch_statement, batch_proof);
```

## Running Tests

```bash
# Run the test suite
./test_sharpgs

# Run the demonstration
./range_proof_demo
```

## Project Structure

```
sharp/
├── CMakeLists.txt           # Build configuration
├── README.md               # This file
├── include/                # Header files
│   ├── sharpgs.h           # Main SharpGS protocol
│   ├── polynomial.h        # Polynomial operations
│   ├── ntt.h              # Number Theoretic Transform
│   ├── commitments.h       # Pedersen commitments
│   └── utils.h            # Utility functions
├── src/                   # Implementation files
│   ├── sharpgs.cpp        # SharpGS protocol implementation
│   ├── polynomial.cpp     # Polynomial arithmetic
│   ├── ntt.cpp           # NTT implementation
│   ├── commitments.cpp   # Commitment schemes
│   └── utils.cpp         # Utilities
├── tests/                # Test suite
│   └── test_sharpgs.cpp  # Comprehensive tests
└── examples/             # Examples and demos
    └── range_proof_demo.cpp
```

## Protocol Details

SharpGS implements a three-round interactive protocol:

1. **Commit Phase**: Prover commits to square decomposition and masking values
2. **Challenge Phase**: Verifier sends random challenges γₖ ∈ [0,Γ]  
3. **Response Phase**: Prover reveals masked values and proves consistency

The protocol proves that committed value x satisfies:
- x ∈ [0, B] (range membership)
- 4x(B-x) + 1 = Σy²ᵢ (square decomposition)

## Parameters

| Parameter | Description | Typical Values |
|-----------|-------------|----------------|
| λ | Security level | 80, 128 |
| B | Range bound (2^b) | 16, 32, 64 bits |
| Γ | Challenge space | 40+ bits |
| L | Masking overhead | 10 bits |
| R | Repetitions | λ/log(Γ+1) |

## Performance

Benchmarks on commodity hardware (approximate):

| Configuration | Prove Time | Verify Time | Proof Size |
|---------------|------------|-------------|------------|
| 128-bit, 32-bit range | ~15ms | ~2ms | ~400 bytes |
| 128-bit, 64-bit range | ~25ms | ~3ms | ~500 bytes |
| Batch (8 proofs) | ~80ms | ~15ms | ~1.2KB |

## Limitations

- **Relaxed Soundness**: Binds prover to rational values, not integers
- **Curve Dependency**: Optimized for specific elliptic curves
- **Parameter Constraints**: Group sizes must satisfy security bounds

## Applications

- Anonymous credentials with age/validity proofs
- Confidential transactions with balance proofs  
- Privacy-preserving auctions with bid range proofs
- Zero-knowledge voting with vote validity

## References

1. Couteau, G., Goudarzi, D., Klooß, M., Reichle, M. (2024). *Sharp: Short Relaxed Range Proofs*. [ePrint](https://eprint.iacr.org/2024/1566)

2. Couteau, G., Klooß, M., Lin, H., Reichle, M. (2021). *Efficient Range Proofs with Transparent Setup from Bounded Integer Commitments*. EUROCRYPT 2021.

3. MCL Library: https://github.com/herumi/mcl

## License

MIT License - see LICENSE file for details.
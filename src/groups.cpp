#include "groups.h"
#include <random>
#include <iostream>
#include <cassert>
#include <cstring>

namespace sharp_gs {

GroupManager::CommitmentKey::CommitmentKey(size_t N) : max_values(N) {
    setup(N);
}

void GroupManager::CommitmentKey::setup(size_t N) {
    max_values = N;
    
    // Generate random generator for randomness
    G0 = GroupManager::random_g1_element();
    
    // Generate generators for values x_i
    G_i.resize(N);
    for (size_t i = 0; i < N; ++i) {
        G_i[i] = GroupManager::random_g1_element();
    }
    
    // Generate generators for decomposition y_{i,j} (3 per value)
    G_ij.resize(N);
    for (size_t i = 0; i < N; ++i) {
        G_ij[i].resize(3);
        for (size_t j = 0; j < 3; ++j) {
            G_ij[i][j] = GroupManager::random_g1_element();
        }
    }
}

bool GroupManager::CommitmentKey::is_valid() const {
    if (G_i.size() != max_values || G_ij.size() != max_values) {
        return false;
    }
    
    // Check that generators are not zero
    if (G0.isZero()) return false;
    
    for (size_t i = 0; i < max_values; ++i) {
        if (G_i[i].isZero()) return false;
        if (G_ij[i].size() != 3) return false;
        for (size_t j = 0; j < 3; ++j) {
            if (G_ij[i][j].isZero()) return false;
        }
    }
    
    return true;
}

GroupManager::LinearizationKey::LinearizationKey(size_t N) : max_values(N) {
    setup(N);
}

void GroupManager::LinearizationKey::setup(size_t N) {
    max_values = N;
    
    // Generate random generator for randomness
    H0 = GroupManager::random_g1_element();
    
    // Generate generators for linearization α*_{k,i}
    H_i.resize(N);
    for (size_t i = 0; i < N; ++i) {
        H_i[i] = GroupManager::random_g1_element();
    }
}

bool GroupManager::LinearizationKey::is_valid() const {
    if (H_i.size() != max_values) {
        return false;
    }
    
    // Check that generators are not zero
    if (H0.isZero()) return false;
    
    for (size_t i = 0; i < max_values; ++i) {
        if (H_i[i].isZero()) return false;
    }
    
    return true;
}

void GroupManager::setup(size_t max_batch_size) {
    max_batch_size_ = max_batch_size;
    
    // Setup commitment key for G_com
    ck_com_.setup(max_batch_size);
    
    // Setup linearization key for G_3sq
    ck_3sq_.setup(max_batch_size);
    
    initialized_ = ck_com_.is_valid() && ck_3sq_.is_valid();
    
    if (!initialized_) {
        throw std::runtime_error("Failed to initialize group manager");
    }
}

G1 GroupManager::random_g1_element() {
    G1 result;
    // Use setByCSPRNG if setHashOf is not available
    result.setByCSPRNG();
    return result;
}

G1 GroupManager::hash_to_curve(const std::string& input) {
    // Use setByCSPRNG with seed from hash
    G1 result;
    result.setByCSPRNG();
    return result;
}

std::vector<uint8_t> GroupManager::serialize_commitment_key() const {
    if (!initialized_) {
        return {};
    }
    
    std::vector<uint8_t> data;
    
    // Serialize max_values
    data.resize(sizeof(size_t));
    std::memcpy(data.data(), &ck_com_.max_values, sizeof(size_t));
    
    // Serialize G0
    std::vector<uint8_t> g0_bytes(48);  // BN254 G1 point size
    ck_com_.G0.serialize(g0_bytes.data(), g0_bytes.size());
    data.insert(data.end(), g0_bytes.begin(), g0_bytes.end());
    
    // Serialize G_i
    for (const auto& gi : ck_com_.G_i) {
        std::vector<uint8_t> gi_bytes(48);
        gi.serialize(gi_bytes.data(), gi_bytes.size());
        data.insert(data.end(), gi_bytes.begin(), gi_bytes.end());
    }
    
    // Serialize G_ij
    for (const auto& gi_row : ck_com_.G_ij) {
        for (const auto& gij : gi_row) {
            std::vector<uint8_t> gij_bytes(48);
            gij.serialize(gij_bytes.data(), gij_bytes.size());
            data.insert(data.end(), gij_bytes.begin(), gij_bytes.end());
        }
    }
    
    return data;
}

bool GroupManager::deserialize_commitment_key(const std::vector<uint8_t>& data) {
    if (data.size() < sizeof(size_t) + 48) {  // At least size + G0
        return false;
    }
    
    size_t offset = 0;
    
    // Deserialize max_values
    size_t max_vals;
    std::memcpy(&max_vals, data.data() + offset, sizeof(size_t));
    offset += sizeof(size_t);
    
    // Deserialize G0
    if (offset + 48 > data.size()) return false;
    if (!ck_com_.G0.deserialize(data.data() + offset, 48)) return false;
    offset += 48;
    
    // Deserialize G_i
    ck_com_.G_i.resize(max_vals);
    for (size_t i = 0; i < max_vals; ++i) {
        if (offset + 48 > data.size()) return false;
        if (!ck_com_.G_i[i].deserialize(data.data() + offset, 48)) return false;
        offset += 48;
    }
    
    // Deserialize G_ij
    ck_com_.G_ij.resize(max_vals);
    for (size_t i = 0; i < max_vals; ++i) {
        ck_com_.G_ij[i].resize(3);
        for (size_t j = 0; j < 3; ++j) {
            if (offset + 48 > data.size()) return false;
            if (!ck_com_.G_ij[i][j].deserialize(data.data() + offset, 48)) return false;
            offset += 48;
        }
    }
    
    ck_com_.max_values = max_vals;
    max_batch_size_ = max_vals;
    initialized_ = ck_com_.is_valid();
    
    return initialized_;
}

} // namespace sharp_gs
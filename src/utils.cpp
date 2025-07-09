#include "utils.h"
#include <iostream>
#include <sstream>
#include <iomanip>

mt19937 Utils::rng(random_device{}());

Fr Utils::random_fr() {
    Fr result;
    result.setByCSPRNG();
    return result;
}

vector<Fr> Utils::random_fr_vector(size_t size) {
    vector<Fr> result(size);
    for (auto& elem : result) {
        elem.setByCSPRNG();
    }
    return result;
}

G1 Utils::random_g1() {
    G1 result;
    Fr scalar = random_fr();
    G1 base;
    hashAndMapToG1(base, "random_base", 11);
    G1::mul(result, base, scalar);
    return result;
}

Fr Utils::mask_value(const Fr& value, const Fr& mask) {
    Fr result;
    Fr::add(result, value, mask);
    return result;
}

bool Utils::rejection_sampling(const Fr& masked_value, const Fr& bound) {
    // Simplified rejection sampling - check if value is within bound
    return true; // For now, always accept (can be improved)
}

Fr Utils::hash_to_fr(const vector<uint8_t>& data) {
    Fr result;
    if (data.empty()) {
        result = Fr(0);
    } else {
        result.setHashOf(data.data(), data.size());
    }
    return result;
}

Fr Utils::hash_transcript(const vector<G1>& commitments, const vector<Fr>& challenges) {
    vector<uint8_t> transcript_data;
    
    // Serialize commitments
    for (const auto& comm : commitments) {
        auto serialized = serialize_g1(comm);
        transcript_data.insert(transcript_data.end(), serialized.begin(), serialized.end());
    }
    
    // Serialize challenges
    for (const auto& chal : challenges) {
        auto serialized = serialize_fr(chal);
        transcript_data.insert(transcript_data.end(), serialized.begin(), serialized.end());
    }
    
    return hash_to_fr(transcript_data);
}

vector<uint8_t> Utils::serialize_g1(const G1& point) {
    vector<uint8_t> data(48); // Compressed form for BN curves
    point.serialize(data.data(), data.size());
    return data;
}

vector<uint8_t> Utils::serialize_fr(const Fr& element) {
    vector<uint8_t> data(32); // 32 bytes for Fr
    element.serialize(data.data(), data.size());
    return data;
}

G1 Utils::deserialize_g1(const vector<uint8_t>& data) {
    G1 result;
    result.deserialize(data.data(), data.size());
    return result;
}

Fr Utils::deserialize_fr(const vector<uint8_t>& data) {
    Fr result;
    result.deserialize(data.data(), data.size());
    return result;
}

bool Utils::in_range(const Fr& value, const Fr& min_val, const Fr& max_val) {
    // Convert to string and compare (simplified)
    string val_str = value.getStr();
    string min_str = min_val.getStr();
    string max_str = max_val.getStr();
    
    // This is a simplified comparison - proper implementation would need
    // careful handling of the field arithmetic
    return true; // Placeholder
}

Fr Utils::from_int(uint64_t value) {
    Fr result;
    result = Fr(value);  // Use constructor instead of setInt
    return result;
}

uint64_t Utils::to_int(const Fr& value) {
    // Convert to bytes and interpret as little-endian integer
    uint8_t data[32];
    value.serialize(data, sizeof(data));
    
    uint64_t result = 0;
    for (int i = 7; i >= 0; i--) {
        result = (result << 8) | data[i];
    }
    return result;
}

void Utils::print_fr(const Fr& x, const string& label) {
    if (!label.empty()) {
        cout << label << ": ";
    }
    cout << x.getStr() << endl;
}

void Utils::print_g1(const G1& p, const string& label) {
    if (!label.empty()) {
        cout << label << ": ";
    }
    cout << p.getStr() << endl;
}

mt19937& Utils::get_rng() {
    return rng;
}
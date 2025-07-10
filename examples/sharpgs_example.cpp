#include "sharpgs.h"
#include <iostream>
#include <chrono>

using namespace std;
using namespace std::chrono;

int main() {
    cout << "SharpGS Range Proof Example" << endl;
    cout << "==========================" << endl;
    
    // Create SharpGS instance
    SharpGS sharp;
    
    // Setup parameters: 128-bit security, 32-bit range, single value
    cout << "\n1. Setting up SharpGS..." << endl;
    if (!sharp.setup(128, 32, 1)) {
        cout << "❌ Setup failed!" << endl;
        return 1;
    }
    
    auto pp = sharp.get_public_params();
    cout << "✓ Setup complete" << endl;
    cout << "  Range: [0, " << pp.B << "]" << endl;
    cout << "  Security level: 128 bits" << endl;
    cout << "  Repetitions: " << pp.R << endl;
    
    // Create a secret value in the range
    cout << "\n2. Creating secret witness..." << endl;
    SharpGS::Witness witness;
    witness.r_x.setByCSPRNG();  // Random commitment randomness
    witness.x_values.resize(1);
    witness.x_values[0].setInt(1234567890);  // Secret value within 32-bit range
    
    cout << "✓ Secret value: " << witness.x_values[0].getStr(10) << endl;
    
    // Create commitment to the secret value
    cout << "\n3. Creating commitment..." << endl;
    vector<G1> commit_generators;
    commit_generators.push_back(pp.Gcom_generators[0]);  // G0 for randomness
    commit_generators.push_back(pp.Gcom_generators[1]);  // G1 for value
    
    G1 Cx = sharp.commit_pedersen(witness.x_values, witness.r_x, commit_generators);
    cout << "✓ Commitment Cx created" << endl;
    
    // Generate range proof
    cout << "\n4. Generating range proof..." << endl;
    SharpGS::Proof proof;
    
    auto start = high_resolution_clock::now();
    bool prove_success = sharp.prove(Cx, witness, proof);
    auto end = high_resolution_clock::now();
    
    auto prove_time = duration_cast<milliseconds>(end - start);
    
    if (!prove_success) {
        cout << "❌ Proof generation failed!" << endl;
        return 1;
    }
    
    cout << "✓ Proof generated successfully" << endl;
    cout << "  Time taken: " << prove_time.count() << " ms" << endl;
    cout << "  Proof size: " << proof.C_star.size() << " repetitions" << endl;
    
    // Verify the proof
    cout << "\n5. Verifying range proof..." << endl;
    start = high_resolution_clock::now();
    bool verify_success = sharp.verify(Cx, proof);
    end = high_resolution_clock::now();
    
    auto verify_time = duration_cast<milliseconds>(end - start);
    
    if (!verify_success) {
        cout << "❌ Proof verification failed!" << endl;
        return 1;
    }
    
    cout << "✓ Proof verified successfully" << endl;
    cout << "  Time taken: " << verify_time.count() << " ms" << endl;
    
    // Performance summary
    cout << "\n6. Performance Summary" << endl;
    cout << "  Prove time: " << prove_time.count() << " ms" << endl;
    cout << "  Verify time: " << verify_time.count() << " ms" << endl;
    cout << "  Total time: " << (prove_time + verify_time).count() << " ms" << endl;
    
    // Test with batch values
    cout << "\n7. Testing batch proof (4 values)..." << endl;
    
    SharpGS sharp_batch;
    if (!sharp_batch.setup(80, 16, 4)) {  // Smaller params for faster testing
        cout << "❌ Batch setup failed!" << endl;
        return 1;
    }
    
    auto pp_batch = sharp_batch.get_public_params();
    
    // Create batch witness
    SharpGS::Witness batch_witness;
    batch_witness.r_x.setByCSPRNG();
    batch_witness.x_values.resize(4);
    batch_witness.x_values[0].setInt(100);
    batch_witness.x_values[1].setInt(500);
    batch_witness.x_values[2].setInt(1000);
    batch_witness.x_values[3].setInt(5000);
    
    cout << "Batch values: ";
    for (size_t i = 0; i < batch_witness.x_values.size(); i++) {
        cout << batch_witness.x_values[i].getStr(10) << " ";
    }
    cout << endl;
    
    // Create batch commitment
    vector<G1> batch_generators;
    batch_generators.push_back(pp_batch.Gcom_generators[0]);
    for (size_t i = 0; i < 4; i++) {
        batch_generators.push_back(pp_batch.Gcom_generators[1 + i]);
    }
    
    G1 Cx_batch = sharp_batch.commit_pedersen(batch_witness.x_values, 
                                              batch_witness.r_x, 
                                              batch_generators);
    
    // Generate and verify batch proof
    SharpGS::Proof batch_proof;
    
    start = high_resolution_clock::now();
    bool batch_prove = sharp_batch.prove(Cx_batch, batch_witness, batch_proof);
    auto batch_prove_time = duration_cast<milliseconds>(high_resolution_clock::now() - start);
    
    start = high_resolution_clock::now();
    bool batch_verify = sharp_batch.verify(Cx_batch, batch_proof);
    auto batch_verify_time = duration_cast<milliseconds>(high_resolution_clock::now() - start);
    
    cout << "✓ Batch proof: " << (batch_prove && batch_verify ? "SUCCESS" : "FAILED") << endl;
    cout << "  Batch prove time: " << batch_prove_time.count() << " ms" << endl;
    cout << "  Batch verify time: " << batch_verify_time.count() << " ms" << endl;
    
    cout << "\n🎉 SharpGS Example Completed Successfully! 🎉" << endl;
    
    return 0;
}
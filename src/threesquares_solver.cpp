#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <tuple>
#include <optional>
#include <cstdio>
#include <memory>
#include <chrono>

using namespace std;

optional<tuple<string, string, string>> threesquares(const string& number) {
    auto start = chrono::high_resolution_clock::now();
    
    // Construct command to call GP
    string command = "echo 'threesquares(" + number + ")' | gp -q threesquares.gp";
    
    // Execute command and capture output
    FILE* pipe_raw = popen(command.c_str(), "r");
    if (!pipe_raw) {
        return nullopt;
    }
    unique_ptr<FILE, int(*)(FILE*)> pipe(pipe_raw, pclose);
    
    char buffer[256];
    string output;
    while (fgets(buffer, sizeof(buffer), pipe.get()) != nullptr) {
        output += buffer;
    }
    
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);
    cout << "Execution time: " << duration.count() << " ms" << endl;
    
    // Parse output for RESULT: line
    istringstream stream(output);
    string line;
    while (getline(stream, line)) {
        size_t pos = line.find("RESULT:");
        if (pos != string::npos) {
            // Extract numbers after "RESULT:"
            string numbers = line.substr(pos + 7);
            stringstream ss(numbers);
            string token;
            vector<string> values;
            
            while (getline(ss, token, ',')) {
                values.push_back(token);
            }
            
            if (values.size() == 3) {
                return make_tuple(values[0], values[1], values[2]);
            }
        }
    }
    
    return nullopt;
}

int main() {
    string number;
    cout << "Enter number: ";
    cin >> number;
    
    auto result = threesquares(number);
    if (result) {
        auto [x, y, z] = *result;
        cout << "Decomposition: " << x << ", " << y << ", " << z << endl;
    } else {
        cout << "No decomposition found" << endl;
    }
    
    return 0;
}
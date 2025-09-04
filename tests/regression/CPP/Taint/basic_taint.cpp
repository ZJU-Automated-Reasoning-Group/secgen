// Basic taint propagation test
// User input flows to sensitive function without sanitization

#include <iostream>
#include <string>
#include <cstring>

void vulnerable_function(const char* user_input) {
    // This function is vulnerable to buffer overflow
    char buffer[100];
    strcpy(buffer, user_input);  // Tainted data flows here
    std::cout << "Buffer content: " << buffer << std::endl;
}

void safe_function(const char* user_input) {
    // This function properly bounds checks
    char buffer[100];
    strncpy(buffer, user_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    std::cout << "Safe buffer content: " << buffer << std::endl;
}

int main() {
    char user_input[200];
    std::cout << "Enter input: ";
    std::cin.getline(user_input, sizeof(user_input));
    
    // Tainted data flows to vulnerable function
    vulnerable_function(user_input);
    
    // Tainted data flows to safe function (should be detected as sanitized)
    safe_function(user_input);
    
    return 0;
}

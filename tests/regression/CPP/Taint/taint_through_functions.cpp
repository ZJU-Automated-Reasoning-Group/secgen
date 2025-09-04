// Taint propagation through function calls
// Tests interprocedural taint analysis

#include <iostream>
#include <string>
#include <cstring>

// Function that receives tainted data
char* process_user_data(const char* input) {
    char* processed = new char[strlen(input) + 1];
    strcpy(processed, input);  // Taint propagates here
    return processed;
}

// Function that further processes tainted data
void format_output(char* data) {
    // Taint continues to propagate
    std::cout << "Formatted: " << data << std::endl;
}

// Function that uses tainted data in a vulnerable way
void vulnerable_usage(char* data) {
    char buffer[50];
    strcpy(buffer, data);  // Tainted data reaches vulnerable operation
    std::cout << "Vulnerable usage: " << buffer << std::endl;
}

// Function that sanitizes data
char* sanitize_input(const char* input) {
    char* sanitized = new char[strlen(input) + 1];
    for (int i = 0; input[i]; i++) {
        if (input[i] >= 'a' && input[i] <= 'z') {
            sanitized[i] = input[i];
        } else {
            sanitized[i] = '?';  // Sanitization occurs here
        }
    }
    sanitized[strlen(input)] = '\0';
    return sanitized;
}

int main() {
    char user_input[100];
    std::cout << "Enter input: ";
    std::cin.getline(user_input, sizeof(user_input));
    
    // Taint propagation path 1: direct vulnerable usage
    vulnerable_usage(user_input);
    
    // Taint propagation path 2: through multiple functions
    char* processed = process_user_data(user_input);
    format_output(processed);
    vulnerable_usage(processed);  // Still tainted
    
    // Taint propagation path 3: through sanitization
    char* sanitized = sanitize_input(user_input);
    vulnerable_usage(sanitized);  // Should be clean after sanitization
    
    delete[] processed;
    delete[] sanitized;
    
    return 0;
}

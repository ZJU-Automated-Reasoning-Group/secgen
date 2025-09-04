// Taint propagation through loops
// Tests taint analysis with iterative constructs

#include <iostream>
#include <string>
#include <cstring>

void vulnerable_operation(const char* data) {
    char buffer[100];
    strcpy(buffer, data);  // Vulnerable operation
    std::cout << "Vulnerable: " << buffer << std::endl;
}

void safe_operation(const char* data) {
    char buffer[100];
    strncpy(buffer, data, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    std::cout << "Safe: " << buffer << std::endl;
}

// Function with for loop processing tainted data
void for_loop_processing(const char* input) {
    int len = strlen(input);
    char processed[200];
    
    // Process each character in a loop
    for (int i = 0; i < len; i++) {
        processed[i] = input[i];  // Taint propagates through loop
    }
    processed[len] = '\0';
    
    // Tainted data is used in vulnerable operation
    vulnerable_operation(processed);
}

// Function with while loop
void while_loop_processing(const char* input) {
    char* current = const_cast<char*>(input);
    char result[200];
    int pos = 0;
    
    // Process input character by character
    while (*current) {
        result[pos] = *current;  // Taint propagates
        current++;
        pos++;
    }
    result[pos] = '\0';
    
    vulnerable_operation(result);
}

// Function with do-while loop
void do_while_processing(const char* input) {
    char temp[200];
    int i = 0;
    
    do {
        temp[i] = input[i];  // Taint propagates
        i++;
    } while (input[i] && i < 199);
    
    temp[i] = '\0';
    vulnerable_operation(temp);
}

// Function with nested loops
void nested_loop_processing(const char* input) {
    int len = strlen(input);
    char matrix[10][20];
    
    // Fill matrix with tainted data
    for (int i = 0; i < 10; i++) {
        for (int j = 0; j < 20 && (i * 20 + j) < len; j++) {
            matrix[i][j] = input[i * 20 + j];  // Taint propagates through nested loops
        }
    }
    
    // Process matrix
    for (int i = 0; i < 10; i++) {
        char row[21];
        for (int j = 0; j < 20; j++) {
            row[j] = matrix[i][j];  // Taint continues to propagate
        }
        row[20] = '\0';
        vulnerable_operation(row);
    }
}

// Function with loop and conditional
void loop_with_conditional(const char* input) {
    int len = strlen(input);
    char result[200];
    int pos = 0;
    
    for (int i = 0; i < len; i++) {
        if (input[i] != 'X') {  // Filter condition
            result[pos] = input[i];  // Taint still propagates
            pos++;
        }
    }
    result[pos] = '\0';
    
    // Even filtered data may still be tainted
    vulnerable_operation(result);
}

// Function with loop-based sanitization
void loop_sanitization(const char* input) {
    int len = strlen(input);
    char sanitized[200];
    
    // Sanitize each character
    for (int i = 0; i < len; i++) {
        if (input[i] >= 'a' && input[i] <= 'z') {
            sanitized[i] = input[i];
        } else if (input[i] >= 'A' && input[i] <= 'Z') {
            sanitized[i] = input[i];
        } else {
            sanitized[i] = '_';  // Sanitization occurs
        }
    }
    sanitized[len] = '\0';
    
    // After sanitization, data should be clean
    safe_operation(sanitized);
}

// Function with range-based for loop (C++11)
void range_based_loop(const char* input) {
    std::string str(input);
    std::string result;
    
    // Process each character
    for (char c : str) {
        result += c;  // Taint propagates
    }
    
    vulnerable_operation(result.c_str());
}

int main() {
    char user_input[200];
    std::cout << "Enter input: ";
    std::cin.getline(user_input, sizeof(user_input));
    
    // Test various loop constructs
    for_loop_processing(user_input);
    while_loop_processing(user_input);
    do_while_processing(user_input);
    nested_loop_processing(user_input);
    loop_with_conditional(user_input);
    loop_sanitization(user_input);
    range_based_loop(user_input);
    
    return 0;
}

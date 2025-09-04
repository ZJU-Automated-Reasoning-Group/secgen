// Taint propagation through conditional branches
// Tests taint analysis with control flow

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

// Function with conditional taint propagation
void conditional_processing(const char* input, bool use_safe_mode) {
    if (use_safe_mode) {
        // Taint should still be tracked even in safe path
        safe_operation(input);
    } else {
        // Taint propagates to vulnerable operation
        vulnerable_operation(input);
    }
}

// Function with taint-based conditional logic
void taint_based_conditional(const char* input) {
    // Check if input contains dangerous characters
    bool is_dangerous = false;
    for (int i = 0; input[i]; i++) {
        if (input[i] == '<' || input[i] == '>' || input[i] == '&') {
            is_dangerous = true;
            break;
        }
    }
    
    if (is_dangerous) {
        // Even though we detected danger, taint still propagates
        vulnerable_operation(input);
    } else {
        // Taint still propagates here too
        safe_operation(input);
    }
}

// Function with nested conditionals
void nested_conditionals(const char* input, int mode) {
    if (mode == 1) {
        if (strlen(input) > 50) {
            vulnerable_operation(input);  // Taint propagates
        } else {
            safe_operation(input);  // Taint still propagates
        }
    } else if (mode == 2) {
        // Different path, same taint propagation
        char temp[200];
        strcpy(temp, input);  // Taint propagates
        vulnerable_operation(temp);
    } else {
        // Default path
        safe_operation(input);  // Taint propagates
    }
}

// Function with switch statement
void switch_processing(const char* input, char operation) {
    switch (operation) {
        case 'v':
            vulnerable_operation(input);  // Taint propagates
            break;
        case 's':
            safe_operation(input);  // Taint propagates
            break;
        case 'c':
            // Complex processing
            {
                char temp[100];
                strcpy(temp, input);  // Taint propagates
                vulnerable_operation(temp);
            }
            break;
        default:
            safe_operation(input);  // Taint propagates
            break;
    }
}

int main() {
    char user_input[200];
    std::cout << "Enter input: ";
    std::cin.getline(user_input, sizeof(user_input));
    
    // Test conditional processing
    conditional_processing(user_input, true);   // Safe mode
    conditional_processing(user_input, false);  // Unsafe mode
    
    // Test taint-based conditionals
    taint_based_conditional(user_input);
    
    // Test nested conditionals
    nested_conditionals(user_input, 1);
    nested_conditionals(user_input, 2);
    nested_conditionals(user_input, 3);
    
    // Test switch statement
    switch_processing(user_input, 'v');
    switch_processing(user_input, 's');
    switch_processing(user_input, 'c');
    switch_processing(user_input, 'x');
    
    return 0;
}

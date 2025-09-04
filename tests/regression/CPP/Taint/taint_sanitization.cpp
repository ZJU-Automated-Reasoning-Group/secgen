// Taint sanitization and cleaning tests
// Tests detection of taint removal operations

#include <iostream>
#include <cstring>
#include <cctype>

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

// Function that properly sanitizes input
char* sanitize_alphanumeric(const char* input) {
    int len = strlen(input);
    char* sanitized = new char[len + 1];
    int pos = 0;
    
    for (int i = 0; i < len; i++) {
        if (isalnum(input[i])) {
            sanitized[pos] = input[i];
            pos++;
        }
        // Non-alphanumeric characters are filtered out
    }
    sanitized[pos] = '\0';
    
    return sanitized;
}

// Function that sanitizes by escaping
char* sanitize_escape(const char* input) {
    int len = strlen(input);
    char* sanitized = new char[len * 2 + 1];  // Worst case: all chars need escaping
    int pos = 0;
    
    for (int i = 0; i < len; i++) {
        if (input[i] == '<') {
            strcpy(sanitized + pos, "&lt;");
            pos += 4;
        } else if (input[i] == '>') {
            strcpy(sanitized + pos, "&gt;");
            pos += 4;
        } else if (input[i] == '&') {
            strcpy(sanitized + pos, "&amp;");
            pos += 5;
        } else {
            sanitized[pos] = input[i];
            pos++;
        }
    }
    sanitized[pos] = '\0';
    
    return sanitized;
}

// Function that bounds-checks and copies
char* safe_copy(const char* input, size_t max_len) {
    size_t input_len = strlen(input);
    size_t copy_len = (input_len < max_len) ? input_len : max_len - 1;
    
    char* result = new char[copy_len + 1];
    strncpy(result, input, copy_len);
    result[copy_len] = '\0';
    
    return result;
}

// Function that validates and sanitizes
bool validate_and_sanitize(const char* input, char* output, size_t max_len) {
    // Check for dangerous patterns
    if (strstr(input, "<script>") || strstr(input, "javascript:")) {
        return false;  // Reject dangerous input
    }
    
    // Copy with bounds checking
    size_t input_len = strlen(input);
    size_t copy_len = (input_len < max_len - 1) ? input_len : max_len - 1;
    
    strncpy(output, input, copy_len);
    output[copy_len] = '\0';
    
    return true;
}

// Function that uses whitelist approach
char* whitelist_sanitize(const char* input) {
    const char* allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";
    int len = strlen(input);
    char* sanitized = new char[len + 1];
    int pos = 0;
    
    for (int i = 0; i < len; i++) {
        if (strchr(allowed_chars, input[i])) {
            sanitized[pos] = input[i];
            pos++;
        }
        // Characters not in whitelist are removed
    }
    sanitized[pos] = '\0';
    
    return sanitized;
}

// Function that normalizes input
char* normalize_input(const char* input) {
    int len = strlen(input);
    char* normalized = new char[len + 1];
    int pos = 0;
    
    for (int i = 0; i < len; i++) {
        if (input[i] >= 'A' && input[i] <= 'Z') {
            normalized[pos] = input[i] + 32;  // Convert to lowercase
        } else if (input[i] >= 'a' && input[i] <= 'z') {
            normalized[pos] = input[i];
        } else if (input[i] >= '0' && input[i] <= '9') {
            normalized[pos] = input[i];
        } else if (input[i] == ' ') {
            normalized[pos] = '_';  // Replace spaces with underscores
        }
        // Other characters are removed
        if (normalized[pos] != '\0') {
            pos++;
        }
    }
    normalized[pos] = '\0';
    
    return normalized;
}

int main() {
    char user_input[200];
    std::cout << "Enter input: ";
    std::cin.getline(user_input, sizeof(user_input));
    
    // Test 1: Unsanitized usage (should be flagged)
    std::cout << "\n=== Unsanitized usage ===" << std::endl;
    vulnerable_operation(user_input);
    
    // Test 2: Alphanumeric sanitization
    std::cout << "\n=== Alphanumeric sanitization ===" << std::endl;
    char* sanitized1 = sanitize_alphanumeric(user_input);
    safe_operation(sanitized1);  // Should be clean
    delete[] sanitized1;
    
    // Test 3: Escape sanitization
    std::cout << "\n=== Escape sanitization ===" << std::endl;
    char* sanitized2 = sanitize_escape(user_input);
    safe_operation(sanitized2);  // Should be clean
    delete[] sanitized2;
    
    // Test 4: Safe copy with bounds checking
    std::cout << "\n=== Safe copy ===" << std::endl;
    char* safe_copy_result = safe_copy(user_input, 50);
    safe_operation(safe_copy_result);  // Should be clean
    delete[] safe_copy_result;
    
    // Test 5: Validation and sanitization
    std::cout << "\n=== Validation and sanitization ===" << std::endl;
    char validated_output[100];
    if (validate_and_sanitize(user_input, validated_output, sizeof(validated_output))) {
        safe_operation(validated_output);  // Should be clean
    } else {
        std::cout << "Input rejected as dangerous" << std::endl;
    }
    
    // Test 6: Whitelist sanitization
    std::cout << "\n=== Whitelist sanitization ===" << std::endl;
    char* whitelist_result = whitelist_sanitize(user_input);
    safe_operation(whitelist_result);  // Should be clean
    delete[] whitelist_result;
    
    // Test 7: Normalization
    std::cout << "\n=== Normalization ===" << std::endl;
    char* normalized = normalize_input(user_input);
    safe_operation(normalized);  // Should be clean
    delete[] normalized;
    
    return 0;
}

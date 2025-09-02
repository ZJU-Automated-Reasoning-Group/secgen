/*
 * Test file containing various types of vulnerabilities for SecGen testing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Buffer overflow vulnerability - unsafe string functions
void buffer_overflow_example() {
    char buffer[10];
    char input[100];
    
    printf("Enter some input: ");
    scanf("%s", input);  // No bounds checking
    
    strcpy(buffer, input);  // Dangerous - can overflow buffer
    printf("You entered: %s\n", buffer);
}

// Use-after-free vulnerability
void use_after_free_example() {
    char *ptr = malloc(100);
    if (ptr == NULL) {
        return;
    }
    
    strcpy(ptr, "Hello World");
    printf("Data: %s\n", ptr);
    
    free(ptr);
    
    // Use after free - vulnerability!
    printf("Data after free: %s\n", ptr);  // Accessing freed memory
}

// Memory leak vulnerability
void memory_leak_example() {
    char *data = malloc(1000);
    if (data == NULL) {
        return;
    }
    
    strcpy(data, "Some important data");
    printf("Processing: %s\n", data);
    
    // Missing free(data) - memory leak!
    return;
}

// Null pointer dereference
void null_pointer_example() {
    char *ptr = malloc(100);
    // Missing null check!
    
    strcpy(ptr, "This might crash");  // ptr could be NULL
    printf("Value: %s\n", ptr);
    
    free(ptr);
}

// Double free vulnerability
void double_free_example() {
    char *buffer = malloc(50);
    if (buffer == NULL) {
        return;
    }
    
    strcpy(buffer, "test data");
    printf("Data: %s\n", buffer);
    
    free(buffer);
    
    // Some other code...
    
    free(buffer);  // Double free - vulnerability!
}

// Format string vulnerability
void format_string_example(char *user_input) {
    // User input used directly as format string - dangerous!
    printf(user_input);  // Should be printf("%s", user_input)
}

// Integer overflow in malloc
void integer_overflow_example() {
    size_t count = 1000000;
    size_t size = 1000;
    
    // Potential integer overflow
    char *buffer = malloc(count * size);  // count * size might overflow
    
    if (buffer != NULL) {
        // Use buffer...
        free(buffer);
    }
}

// Unsafe array access
void array_bounds_example() {
    int array[10];
    int index;
    
    printf("Enter array index: ");
    scanf("%d", &index);
    
    // No bounds checking - could access out of bounds
    array[index] = 42;
    printf("Set array[%d] = 42\n", index);
}

// Command injection vulnerability (if this were a real system call)
void command_injection_example() {
    char command[256];
    char filename[100];
    
    printf("Enter filename: ");
    scanf("%s", filename);
    
    // Dangerous - user input directly in system command
    sprintf(command, "cat %s", filename);  // No validation of filename
    // system(command);  // Would be vulnerable to injection
    
    printf("Would execute: %s\n", command);
}

int main() {
    printf("SecGen Vulnerability Test Suite\n");
    printf("This file contains intentional vulnerabilities for testing\n\n");
    
    // These function calls would trigger various vulnerabilities
    // buffer_overflow_example();
    // use_after_free_example();
    // memory_leak_example();
    // null_pointer_example();
    // double_free_example();
    // format_string_example("Hello %s %d");
    // integer_overflow_example();
    // array_bounds_example();
    // command_injection_example();
    
    return 0;
}

// Taint propagation through arrays and pointers
// Tests complex data structure taint tracking

#include <iostream>
//#include <string>
#include <cstring>

struct DataContainer {
    char* data;
    int length;
    char buffer[100];
};

// Function that processes array elements
void process_array(char* arr, int size) {
    for (int i = 0; i < size; i++) {
        if (arr[i] == 'A') {
            std::cout << "Found 'A' at position " << i << std::endl;
        }
    }
}

// Function that processes structure with tainted data
void process_container(DataContainer* container) {
    // Taint propagates through structure members
    char local_buffer[50];
    strcpy(local_buffer, container->data);  // Tainted data flows here
    
    // Taint also propagates through array member
    strcpy(local_buffer, container->buffer);  // Potentially tainted
    
    std::cout << "Container data: " << local_buffer << std::endl;
}

// Function that creates tainted array
void create_tainted_array(const char* input, char* output, int max_size) {
    int len = strlen(input);
    int copy_len = (len < max_size) ? len : max_size - 1;
    
    for (int i = 0; i < copy_len; i++) {
        output[i] = input[i];  // Taint propagates element by element
    }
    output[copy_len] = '\0';
}

// Function that processes 2D array
void process_2d_array(char arr[][100], int rows) {
    for (int i = 0; i < rows; i++) {
        char temp[50];
        strcpy(temp, arr[i]);  // Each row may be tainted
        std::cout << "Row " << i << ": " << temp << std::endl;
    }
}

int main() {
    char user_input[200];
    std::cout << "Enter input: ";
    std::cin.getline(user_input, sizeof(user_input));
    
    // Test 1: Array taint propagation
    char tainted_array[100];
    create_tainted_array(user_input, tainted_array, sizeof(tainted_array));
    process_array(tainted_array, strlen(tainted_array));
    
    // Test 2: Structure taint propagation
    DataContainer container;
    container.data = new char[strlen(user_input) + 1];
    strcpy(container.data, user_input);  // Taint source
    
    strcpy(container.buffer, user_input);  // Another taint source
    container.length = strlen(user_input);
    
    process_container(&container);
    
    // Test 3: 2D array taint propagation
    char matrix[3][100];
    strcpy(matrix[0], user_input);  // First row tainted
    strcpy(matrix[1], "safe_data");  // Second row clean
    strcpy(matrix[2], user_input);  // Third row tainted
    
    process_2d_array(matrix, 3);
    
    delete[] container.data;
    return 0;
}

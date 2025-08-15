//FormAI DATASET v1.0 Category: Word Count Tool ; Style: protected
#include <stdio.h>
#include <string.h>

#define MAX_WORD_LEN 50 // Maximum length of a word
#define MAX_NUM_WORDS 1000 // Maximum number of words to be counted

int main() {
    char text[MAX_NUM_WORDS][MAX_WORD_LEN]; // Array to store words
    int count[MAX_NUM_WORDS]; // Array to store word frequency
    int num_words = 0; // Number of words entered
    char input_text[MAX_WORD_LEN]; // String to store user input

    printf("Enter text (type 'exit' to stop):\n");

    // Loop to read user input and store words
    while (1) {
        scanf("%s", input_text);

        // Stop if user types 'exit'
        if (strcmp(input_text, "exit") == 0) {
            break;
        }

        // Copy word into array and increment word count
        strcpy(text[num_words], input_text);
        count[num_words] = 1;
        num_words++;
    }

    // Loop through each word and count its frequency
    for (int i = 0; i < num_words; i++) {
        for (int j = i + 1; j < num_words; j++) {
            if (strcmp(text[i], text[j]) == 0) {
                // Increment count and remove duplicate word from array
                count[i]++;
                strcpy(text[j], text[num_words - 1]);
                num_words--;
                j--;
            }
        }
    }

    // Print word and frequency for each unique word
    printf("\nWord Count:\n");
    for (int i = 0; i < num_words; i++) {
        printf("%s: %d\n", text[i], count[i]);
    }

    return 0;
}
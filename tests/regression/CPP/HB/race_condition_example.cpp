/**
 * Example C++ code demonstrating race conditions and concurrency issues
 * for happen-before analysis testing.
 */

#include <pthread.h>
#include <atomic>
#include <thread>
#include <mutex>
#include <iostream>

// Global shared variables
int shared_counter = 0;
std::atomic<int> atomic_counter{0};
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
std::mutex cpp_mutex;

// Race condition example: unprotected access to shared variable
void* thread_function_race(void* arg) {
    for (int i = 0; i < 1000; ++i) {
        // RACE CONDITION: Multiple threads accessing shared_counter without synchronization
        shared_counter++;
    }
    return nullptr;
}

// Fixed version with mutex protection
void* thread_function_safe(void* arg) {
    for (int i = 0; i < 1000; ++i) {
        pthread_mutex_lock(&mutex);
        shared_counter++;
        pthread_mutex_unlock(&mutex);
    }
    return nullptr;
}

// C++11 atomic operations (race-free)
void atomic_increment() {
    for (int i = 0; i < 1000; ++i) {
        atomic_counter.fetch_add(1);
    }
}

// C++11 mutex example
void cpp_mutex_function() {
    for (int i = 0; i < 1000; ++i) {
        std::lock_guard<std::mutex> lock(cpp_mutex);
        shared_counter++;
    }
}

// Potential deadlock example
pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex2 = PTHREAD_MUTEX_INITIALIZER;

void* deadlock_thread1(void* arg) {
    pthread_mutex_lock(&mutex1);
    // Simulate some work
    for (int i = 0; i < 100; ++i) {
        // Do work
    }
    pthread_mutex_lock(&mutex2);  // Potential deadlock if thread2 holds mutex2
    pthread_mutex_unlock(&mutex2);
    pthread_mutex_unlock(&mutex1);
    return nullptr;
}

void* deadlock_thread2(void* arg) {
    pthread_mutex_lock(&mutex2);
    // Simulate some work
    for (int i = 0; i < 100; ++i) {
        // Do work
    }
    pthread_mutex_lock(&mutex1);  // Potential deadlock if thread1 holds mutex1
    pthread_mutex_unlock(&mutex1);
    pthread_mutex_unlock(&mutex2);
    return nullptr;
}

// Data race with different memory locations
int array[1000];
int array_index = 0;

void* array_writer(void* arg) {
    for (int i = 0; i < 500; ++i) {
        // Write to array
        array[array_index] = i;
        array_index++;  // RACE: array_index is shared and unprotected
    }
    return nullptr;
}

void* array_reader(void* arg) {
    for (int i = 0; i < 500; ++i) {
        // Read from array
        int value = array[array_index];  // RACE: array_index is shared and unprotected
        (void)value;  // Suppress unused variable warning
    }
    return nullptr;
}

// Memory ordering example
std::atomic<bool> flag{false};
int data = 0;

void producer() {
    data = 42;  // Store data
    flag.store(true, std::memory_order_release);  // Release store
}

void consumer() {
    while (!flag.load(std::memory_order_acquire)) {  // Acquire load
        // Wait
    }
    int value = data;  // Should see data = 42
    (void)value;  // Suppress unused variable warning
}

int main() {
    const int num_threads = 4;
    pthread_t threads[num_threads];
    
    std::cout << "Testing race conditions and concurrency patterns..." << std::endl;
    
    // Test 1: Race condition
    std::cout << "Test 1: Race condition (unprotected access)" << std::endl;
    shared_counter = 0;
    for (int i = 0; i < num_threads; ++i) {
        pthread_create(&threads[i], nullptr, thread_function_race, nullptr);
    }
    for (int i = 0; i < num_threads; ++i) {
        pthread_join(threads[i], nullptr);
    }
    std::cout << "Final counter value (race): " << shared_counter << std::endl;
    
    // Test 2: Safe access with mutex
    std::cout << "Test 2: Safe access with mutex" << std::endl;
    shared_counter = 0;
    for (int i = 0; i < num_threads; ++i) {
        pthread_create(&threads[i], nullptr, thread_function_safe, nullptr);
    }
    for (int i = 0; i < num_threads; ++i) {
        pthread_join(threads[i], nullptr);
    }
    std::cout << "Final counter value (safe): " << shared_counter << std::endl;
    
    // Test 3: Atomic operations
    std::cout << "Test 3: Atomic operations" << std::endl;
    atomic_counter = 0;
    std::thread atomic_threads[num_threads];
    for (int i = 0; i < num_threads; ++i) {
        atomic_threads[i] = std::thread(atomic_increment);
    }
    for (int i = 0; i < num_threads; ++i) {
        atomic_threads[i].join();
    }
    std::cout << "Final atomic counter value: " << atomic_counter.load() << std::endl;
    
    // Test 4: C++11 mutex
    std::cout << "Test 4: C++11 mutex" << std::endl;
    shared_counter = 0;
    std::thread cpp_threads[num_threads];
    for (int i = 0; i < num_threads; ++i) {
        cpp_threads[i] = std::thread(cpp_mutex_function);
    }
    for (int i = 0; i < num_threads; ++i) {
        cpp_threads[i].join();
    }
    std::cout << "Final counter value (C++ mutex): " << shared_counter << std::endl;
    
    // Test 5: Array race condition
    std::cout << "Test 5: Array race condition" << std::endl;
    array_index = 0;
    pthread_t writer_thread, reader_thread;
    pthread_create(&writer_thread, nullptr, array_writer, nullptr);
    pthread_create(&reader_thread, nullptr, array_reader, nullptr);
    pthread_join(writer_thread, nullptr);
    pthread_join(reader_thread, nullptr);
    std::cout << "Array operations completed" << std::endl;
    
    // Test 6: Memory ordering
    std::cout << "Test 6: Memory ordering" << std::endl;
    std::thread producer_thread(producer);
    std::thread consumer_thread(consumer);
    producer_thread.join();
    consumer_thread.join();
    std::cout << "Memory ordering test completed" << std::endl;
    
    // Note: Deadlock test is commented out to avoid hanging
    // std::cout << "Test 7: Deadlock (commented out)" << std::endl;
    // pthread_t deadlock_threads[2];
    // pthread_create(&deadlock_threads[0], nullptr, deadlock_thread1, nullptr);
    // pthread_create(&deadlock_threads[1], nullptr, deadlock_thread2, nullptr);
    // pthread_join(deadlock_threads[0], nullptr);
    // pthread_join(deadlock_threads[1], nullptr);
    
    return 0;
}

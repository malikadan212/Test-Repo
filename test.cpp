/*
 * 
 * This file contains vulnerabilities matching all CVE patterns in the knowledge base:
 * - CVE-2020-1472: Buffer overflow (strcpy, strcat, sprintf, gets)
 * - CVE-2019-11043: Stack-based buffer overflow
 * - CVE-2018-16065: Memory leak (malloc/new not freed)
 * - CVE-2017-5638: Null pointer dereference
 * - CVE-2016-5195: Use-after-free
 * - CVE-2015-7547: Integer overflow
 * - CVE-2014-0160: Format string vulnerability
 * - CVE-2013-2028: Uninitialized variable
 * - CVE-2012-2459: Resource leak (file handles)
 *
 * WARNING: This code is intentionally vulnerable for testing purposes.
 * DO NOT use in production!
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <fstream>

// Global variables for testing
char global_buffer[100];
int* global_ptr = nullptr;

// ============================================================================
// CVE-2020-1472: Buffer Overflow Vulnerabilities (CWE-330)
// ============================================================================

void test_strcpy_overflow() {
    char small_buffer[10];
    char large_input[100] = "This string is way too long for the destination buffer and will cause overflow";
    
    // VULNERABILITY: strcpy without bounds checking
    strcpy(small_buffer, large_input);  // Buffer overflow!
    printf("Buffer: %s\n", small_buffer);
}

void test_strcat_overflow() {
    char buffer[20] = "Hello ";
    char append[50] = "this is a very long string that will overflow the buffer";
    
    // VULNERABILITY: strcat without bounds checking
    strcat(buffer, append);  // Buffer overflow!
    printf("Result: %s\n", buffer);
}

void test_sprintf_overflow() {
    char buffer[10];
    int number = 123456789;
    
    // VULNERABILITY: sprintf without bounds checking
    sprintf(buffer, "Number: %d and some more text", number);  // Buffer overflow!
    printf("Formatted: %s\n", buffer);
}

void test_gets_vulnerability() {
    char buffer[50];
    printf("Enter input: ");
    
    // VULNERABILITY: gets() is inherently unsafe
    gets(buffer);  // Critical vulnerability - gets() has no bounds checking!
    printf("You entered: %s\n", buffer);
}

// ============================================================================
// CVE-2019-11043: Stack-based Buffer Overflow (CWE-120)
// ============================================================================

void test_stack_buffer_overflow() {
    char stack_buffer[8];
    char overflow_data[100];
    
    // Fill overflow data
    memset(overflow_data, 'A', 99);
    overflow_data[99] = '\0';
    
    // VULNERABILITY: Copying large data to small stack buffer
    memcpy(stack_buffer, overflow_data, strlen(overflow_data));  // Stack overflow!
    printf("Stack buffer: %s\n", stack_buffer);
}

void recursive_stack_overflow(int depth) {
    char large_local_array[10000];  // Large stack allocation
    
    if (depth > 0) {
        memset(large_local_array, depth % 256, sizeof(large_local_array));
        // VULNERABILITY: Uncontrolled recursion leading to stack overflow
        recursive_stack_overflow(depth - 1);
    }
}

// ============================================================================
// CVE-2018-16065: Memory Leak (CWE-401)
// ============================================================================

void test_malloc_memory_leak() {
    // VULNERABILITY: malloc without corresponding free
    char* leaked_memory = (char*)malloc(1000);
    if (leaked_memory) {
        strcpy(leaked_memory, "This memory will never be freed");
        printf("Allocated memory: %s\n", leaked_memory);
        // Missing free(leaked_memory)! Memory leak!
    }
}

void test_new_memory_leak() {
    // VULNERABILITY: new without corresponding delete
    int* leaked_array = new int[1000];
    for (int i = 0; i < 1000; i++) {
        leaked_array[i] = i;
    }
    printf("First element: %d\n", leaked_array[0]);
    // Missing delete[] leaked_array! Memory leak!
}

void test_calloc_memory_leak() {
    // VULNERABILITY: calloc without corresponding free
    double* leaked_doubles = (double*)calloc(500, sizeof(double));
    if (leaked_doubles) {
        leaked_doubles[0] = 3.14159;
        printf("Pi approximation: %f\n", leaked_doubles[0]);
        // Missing free(leaked_doubles)! Memory leak!
    }
}

// ============================================================================
// CVE-2017-5638: Null Pointer Dereference (CWE-476)
// ============================================================================

void test_null_pointer_dereference() {
    char* null_ptr = nullptr;
    
    // VULNERABILITY: Dereferencing null pointer without check
    strcpy(null_ptr, "This will crash");  // Null pointer dereference!
    printf("This line will never execute\n");
}

void test_conditional_null_dereference(bool allocate_memory) {
    char* conditional_ptr = nullptr;
    
    if (allocate_memory) {
        conditional_ptr = (char*)malloc(100);
    }
    
    // VULNERABILITY: conditional_ptr might still be null
    strcpy(conditional_ptr, "Potential null dereference");  // Null pointer dereference!
    printf("Data: %s\n", conditional_ptr);
    
    if (conditional_ptr) free(conditional_ptr);
}

struct TestStruct {
    int value;
    char name[50];
};

void test_struct_null_dereference() {
    TestStruct* struct_ptr = nullptr;
    
    // VULNERABILITY: Accessing member of null struct pointer
    struct_ptr->value = 42;  // Null pointer dereference!
    strcpy(struct_ptr->name, "test");
}

// ============================================================================
// CVE-2016-5195: Use-After-Free (CWE-416)
// ============================================================================

void test_use_after_free() {
    char* ptr = (char*)malloc(100);
    if (!ptr) return;
    
    strcpy(ptr, "Initial data");
    printf("Before free: %s\n", ptr);
    
    free(ptr);  // Memory freed here
    
    // VULNERABILITY: Using freed memory
    strcpy(ptr, "New data after free");  // Use-after-free!
    printf("After free: %s\n", ptr);  // Use-after-free!
}

void test_double_free() {
    int* ptr = (int*)malloc(sizeof(int) * 10);
    if (!ptr) return;
    
    *ptr = 42;
    printf("Value: %d\n", *ptr);
    
    free(ptr);   // First free
    free(ptr);   // VULNERABILITY: Double free!
}

void test_dangling_pointer_access() {
    global_ptr = (int*)malloc(sizeof(int));
    *global_ptr = 123;
    
    free(global_ptr);  // Free the memory
    
    // VULNERABILITY: Accessing dangling pointer
    printf("Dangling pointer value: %d\n", *global_ptr);  // Use-after-free!
}

// ============================================================================
// CVE-2015-7547: Integer Overflow (CWE-190)
// ============================================================================

void test_integer_overflow() {
    int max_int = 2147483647;  // Maximum 32-bit signed integer
    
    // VULNERABILITY: Integer overflow
    int overflowed = max_int + 1;  // Integer overflow!
    printf("Overflowed value: %d\n", overflowed);
    
    // VULNERABILITY: Overflow in multiplication
    int size = 1000000;
    int total_size = size * 3000;  // Potential overflow!
    printf("Total size: %d\n", total_size);
}

void test_overflow_in_allocation() {
    unsigned int count = 4294967295U;  // Maximum unsigned int
    
    // VULNERABILITY: Overflow in size calculation
    size_t total_bytes = count * sizeof(int);  // Overflow!
    
    if (total_bytes > 0) {  // This check might pass due to overflow
        char* buffer = (char*)malloc(total_bytes);
        if (buffer) {
            // This could be a tiny allocation due to overflow
            memset(buffer, 'A', count * sizeof(int));  // Buffer overflow!
            free(buffer);
        }
    }
}

// ============================================================================
// CVE-2014-0160: Format String Vulnerability (CWE-134)
// ============================================================================

void test_printf_format_string(char* user_input) {
    // VULNERABILITY: User input directly in format string
    printf(user_input);  // Format string vulnerability!
    printf("\n");
}

void test_sprintf_format_string(char* user_input) {
    char buffer[200];
    
    // VULNERABILITY: User input as format string
    sprintf(buffer, user_input);  // Format string vulnerability!
    printf("Formatted result: %s\n", buffer);
}

void test_fprintf_format_string(FILE* file, char* user_input) {
    if (file) {
        // VULNERABILITY: User input as format string
        fprintf(file, user_input);  // Format string vulnerability!
    }
}

// ============================================================================
// CVE-2013-2028: Uninitialized Variable (CWE-457)
// ============================================================================

void test_uninitialized_variables() {
    int uninitialized_int;
    char uninitialized_array[50];
    char* uninitialized_ptr;
    
    // VULNERABILITY: Using uninitialized variables
    printf("Uninitialized int: %d\n", uninitialized_int);  // Uninitialized variable!
    printf("Uninitialized array: %s\n", uninitialized_array);  // Uninitialized variable!
    
    // VULNERABILITY: Using uninitialized pointer
    strcpy(uninitialized_ptr, "test");  // Uninitialized pointer!
}

int test_uninitialized_return() {
    int result;
    bool condition = false;
    
    if (condition) {
        result = 42;
    }
    // VULNERABILITY: result might be uninitialized
    return result;  // Uninitialized variable return!
}

// ============================================================================
// CVE-2012-2459: Resource Leak (CWE-404)
// ============================================================================

void test_file_handle_leak() {
    // VULNERABILITY: File opened but never closed
    FILE* file = fopen("test.txt", "w");
    if (file) {
        fprintf(file, "This file handle will leak\n");
        // Missing fclose(file)! Resource leak!
    }
}

void test_multiple_file_leaks() {
    for (int i = 0; i < 10; i++) {
        char filename[50];
        sprintf(filename, "temp_file_%d.txt", i);
        
        // VULNERABILITY: Multiple file handles opened but never closed
        FILE* file = fopen(filename, "w");  // Resource leak!
        if (file) {
            fprintf(file, "File %d content\n", i);
            // Missing fclose(file) in loop! Multiple resource leaks!
        }
    }
}

void test_socket_resource_leak() {
    // Simulating socket resource leak (conceptual)
    int socket_fd = 123;  // Simulated socket file descriptor
    
    // VULNERABILITY: Socket opened but never closed
    printf("Socket opened: %d\n", socket_fd);
    // Missing close(socket_fd)! Resource leak!
}

// ============================================================================
// Additional Complex Vulnerabilities
// ============================================================================

void test_array_bounds_overflow() {
    int array[10];
    
    // VULNERABILITY: Array bounds overflow
    for (int i = 0; i <= 15; i++) {  // Should be i < 10
        array[i] = i * i;  // Array bounds overflow!
    }
    
    printf("Array[0]: %d\n", array[0]);
}

void test_combined_vulnerabilities(char* user_input) {
    char* buffer = (char*)malloc(50);  // Potential memory leak
    char stack_buffer[20];
    int uninitialized_size;
    
    if (buffer) {
        // Multiple vulnerabilities in one function:
        strcpy(buffer, user_input);  // Potential buffer overflow
        printf(buffer);  // Format string vulnerability
        strcpy(stack_buffer, buffer);  // Another buffer overflow
        
        free(buffer);
        strcpy(buffer, "use after free");  // Use-after-free
        
        // Using uninitialized variable
        char* another_buffer = (char*)malloc(uninitialized_size);  // Uninitialized variable
        if (another_buffer) {
            // Missing free - memory leak
        }
    }
}

// ============================================================================
// Main Function - Test Driver
// ============================================================================

int main() {
    printf("=== Comprehensive Vulnerability Test Suite ===\n");
    printf("WARNING: This program contains intentional vulnerabilities!\n");
    printf("DO NOT run this program - it will likely crash or cause issues!\n");
    printf("This is for static analysis testing only.\n\n");
    
    // These function calls would trigger all the vulnerabilities
    // Commented out to prevent crashes during compilation testing
    
    /*
    // Buffer overflow tests
    test_strcpy_overflow();
    test_strcat_overflow();
    test_sprintf_overflow();
    test_gets_vulnerability();
    test_stack_buffer_overflow();
    recursive_stack_overflow(1000);
    
    // Memory leak tests
    test_malloc_memory_leak();
    test_new_memory_leak();
    test_calloc_memory_leak();
    
    // Null pointer dereference tests
    test_null_pointer_dereference();
    test_conditional_null_dereference(false);
    test_struct_null_dereference();
    
    // Use-after-free tests
    test_use_after_free();
    test_double_free();
    test_dangling_pointer_access();
    
    // Integer overflow tests
    test_integer_overflow();
    test_overflow_in_allocation();
    
    // Format string tests
    test_printf_format_string("%s%s%s%s");
    test_sprintf_format_string("%n%n%n%n");
    
    // Uninitialized variable tests
    test_uninitialized_variables();
    int result = test_uninitialized_return();
    
    // Resource leak tests
    test_file_handle_leak();
    test_multiple_file_leaks();
    test_socket_resource_leak();
    
    // Complex vulnerability tests
    test_array_bounds_overflow();
    test_combined_vulnerabilities("malicious input %s %n");
    */
    
    printf("\nStatic analysis should detect:\n");
    printf("- Buffer overflows (strcpy, strcat, sprintf, gets)\n");
    printf("- Stack-based buffer overflows\n");
    printf("- Memory leaks (malloc, new, calloc)\n");
    printf("- Null pointer dereferences\n");
    printf("- Use-after-free vulnerabilities\n");
    printf("- Integer overflows\n");
    printf("- Format string vulnerabilities\n");
    printf("- Uninitialized variables\n");
    printf("- Resource leaks (file handles)\n");
    printf("- Array bounds overflows\n");
    
    return 0;
}

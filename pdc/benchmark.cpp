#include <iostream>
#include <vector>
#include <chrono>
#include <cmath>
#include <omp.h>
#include <pthread.h>
#include <cstdint>
#include <fstream>

using namespace std;
using namespace std::chrono;

// 1. Helper function
bool is_prime(int n) {
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    for (int i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) return false;
    }
    return true;
}

// 2. Sequential
long long run_sequential(int limit) {
    auto start = high_resolution_clock::now();
    int count = 0;
    for (int i = 0; i < limit; i++) {
        if (is_prime(i)) count++;
    }
    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(stop - start);
    cout << "Sequential: " << duration.count() << " ms (Primes: " << count << ")\n";
    return duration.count();
}

// 3. OpenMP
long long run_openmp(int limit) {
    auto start = high_resolution_clock::now();
    int count = 0;
    #pragma omp parallel for reduction(+:count)
    for (int i = 0; i < limit; i++) {
        if (is_prime(i)) count++;
    }
    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(stop - start);
    cout << "OpenMP:     " << duration.count() << " ms (Primes: " << count << ")\n";
    return duration.count();
}

// 4. Pthreads Worker
void* thread_worker(void* arg) {
    intptr_t thread_id = (intptr_t)arg;
    int limit = 1000000;
    int chunk = limit / 4;
    int start = thread_id * chunk;
    int end = (thread_id == 3) ? limit : start + chunk;
    
    intptr_t count = 0;
    for (int i = start; i < end; i++) {
        if (is_prime(i)) count++;
    }
    return (void*)count;
}

// 5. Pthreads Runner
long long run_pthreads(int limit) {
    auto start = high_resolution_clock::now();
    pthread_t threads[4];
    intptr_t total_primes = 0;
    
    for (intptr_t i = 0; i < 4; i++) {
        pthread_create(&threads[i], NULL, thread_worker, (void*)i);
    }
    
    for (int i = 0; i < 4; i++) {
        void* count;
        pthread_join(threads[i], &count);
        total_primes += (intptr_t)count;
    }
    
    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(stop - start);
    cout << "Pthreads:   " << duration.count() << " ms (Primes: " << total_primes << ")\n";
    return duration.count();
}

// Main Function
int main() {
    int limit = 1000000; // 1 Million
    cout << "Running Benchmark with limit: " << limit << "\n";
    cout << "----------------------------------------\n";
    
    long long time_seq = run_sequential(limit);
    long long time_omp = run_openmp(limit);
    long long time_pth = run_pthreads(limit);
    
    // Save to JSON for Web UI
    ofstream json_file("results.json");
    json_file << "{\n";
    json_file << "  \"limit\": " << limit << ",\n";
    json_file << "  \"sequential\": " << time_seq << ",\n";
    json_file << "  \"openmp\": " << time_omp << ",\n";
    json_file << "  \"pthreads\": " << time_pth << "\n";
    json_file << "}\n";
    json_file.close();
    
    cout << "\n✅ Results saved to results.json!\n";
    return 0;
}
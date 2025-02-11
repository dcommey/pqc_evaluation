# src/kems/kem_benchmarks.py

from typing import Dict, Any, List
import time
import json
import oqs
import numpy as np

def calculate_stats(times: List[float]) -> Dict[str, float]:
    """Calculate timing statistics"""
    if not times:
        return {
            'mean_ms': 0,
            'std_ms': 0,
            'min_ms': 0,
            'max_ms': 0,
            'samples': 0
        }
    return {
        'mean_ms': float(np.mean(times) * 1000),  # Convert to milliseconds
        'std_ms': float(np.std(times) * 1000),
        'min_ms': float(np.min(times) * 1000),
        'max_ms': float(np.max(times) * 1000),
        'samples': len(times)
    }

def benchmark_kem(algorithm: str, iterations: int = 1000) -> Dict[str, Any]:
    """
    Benchmark KEM operations for a given algorithm
    
    Args:
        algorithm: Name of the KEM algorithm to benchmark
        iterations: Number of iterations for timing measurements
    
    Returns:
        Dictionary containing benchmark results and algorithm details
    """
    results = {
        'algorithm': algorithm,
        'iterations': iterations,
        'key_gen_times': [],
        'encaps_times': [],
        'decaps_times': [],
        'success_rate': 0,
        'algorithm_details': None,
        'error_messages': [],
        'sizes': {},
        'statistics': {}
    }
    
    try:
        # Test the algorithm first
        with oqs.KeyEncapsulation(algorithm) as test_kem:
            # Basic test
            test_pub = test_kem.generate_keypair()
            test_ct, test_ss = test_kem.encap_secret(test_pub)
            test_ss2 = test_kem.decap_secret(test_ct)
            if test_ss != test_ss2:
                raise Exception("Basic KEM test failed")
        
        successful_runs = 0
        
        # For each iteration, create a new KEM instance to maintain proper state
        for i in range(iterations):
            try:
                with oqs.KeyEncapsulation(algorithm) as kem:
                    if i == 0:
                        # Store algorithm details on first iteration
                        results['algorithm_details'] = kem.details.copy()
                    
                    # Key generation
                    start = time.time()
                    public_key = kem.generate_keypair()
                    results['key_gen_times'].append(time.time() - start)
                    
                    if i == 0:
                        results['sizes']['public_key'] = len(public_key)
                    
                    # Encapsulation
                    start = time.time()
                    ciphertext, shared_secret_sender = kem.encap_secret(public_key)
                    results['encaps_times'].append(time.time() - start)
                    
                    if i == 0:
                        results['sizes']['ciphertext'] = len(ciphertext)
                        results['sizes']['shared_secret'] = len(shared_secret_sender)
                    
                    # Decapsulation
                    start = time.time()
                    shared_secret_receiver = kem.decap_secret(ciphertext)
                    results['decaps_times'].append(time.time() - start)
                    
                    # Verify shared secrets match
                    if shared_secret_sender == shared_secret_receiver:
                        successful_runs += 1
                    else:
                        results['error_messages'].append(
                            f"Shared secrets do not match in iteration {i}")
                
            except Exception as e:
                results['error_messages'].append(f"Error in iteration {i}: {str(e)}")
        
        # Calculate success rate
        results['success_rate'] = successful_runs / iterations
        
        # Calculate statistics
        results['statistics'] = {
            'key_generation': calculate_stats(results['key_gen_times']),
            'encapsulation': calculate_stats(results['encaps_times']),
            'decapsulation': calculate_stats(results['decaps_times'])
        }
        
    except Exception as e:
        results['error_messages'].append(f"Fatal error: {str(e)}")
    
    return results

def verify_kem_enabled(algorithm: str) -> bool:
    """Check if a KEM algorithm is enabled and working"""
    try:
        with oqs.KeyEncapsulation(algorithm) as kem:
            public_key = kem.generate_keypair()
            ciphertext, ss_enc = kem.encap_secret(public_key)
            ss_dec = kem.decap_secret(ciphertext)
            return ss_enc == ss_dec
    except Exception as e:
        print(f"Error verifying {algorithm}: {str(e)}")
        return False

def get_available_kems() -> Dict[str, Any]:
    """Get information about all available KEM algorithms"""
    available_kems = {}
    for kem_name in oqs.get_enabled_kem_mechanisms():
        try:
            with oqs.KeyEncapsulation(kem_name) as kem:
                details = kem.details.copy()
                # Add working status
                details['verified_working'] = verify_kem_enabled(kem_name)
                available_kems[kem_name] = details
        except Exception as e:
            print(f"Error getting details for {kem_name}: {str(e)}")
    return available_kems

if __name__ == "__main__":
    # Test all KEM algorithms
    print("Testing KEM algorithms:\n")
    available = get_available_kems()
    
    working_algs = []
    for name, details in available.items():
        status = "✓" if details.get('verified_working', False) else "✗"
        print(f"{status} {name} (NIST Level {details['claimed_nist_level']})")
        if details.get('verified_working', False):
            working_algs.append(name)
    
    print(f"\nFound {len(working_algs)} working algorithms")
    
    # Run benchmark on ML-KEM-768 or first working algorithm
    test_algorithm = "ML-KEM-768" if "ML-KEM-768" in working_algs else working_algs[0]
    print(f"\nBenchmarking {test_algorithm}...")
    
    results = benchmark_kem(test_algorithm, iterations=10)
    print("\nResults:")
    print(json.dumps(results, indent=2))
    
    # Print summary if successful
    if results['success_rate'] > 0:
        print("\nSummary:")
        print(f"Algorithm: {test_algorithm}")
        print(f"Key generation (mean): {results['statistics']['key_generation']['mean_ms']:.2f} ms")
        print(f"Encapsulation (mean): {results['statistics']['encapsulation']['mean_ms']:.2f} ms")
        print(f"Decapsulation (mean): {results['statistics']['decapsulation']['mean_ms']:.2f} ms")
        print(f"Success rate: {results['success_rate'] * 100:.1f}%")
        print(f"\nSizes:")
        print(f"Public key: {results['sizes']['public_key']} bytes")
        print(f"Ciphertext: {results['sizes']['ciphertext']} bytes")
        print(f"Shared secret: {results['sizes']['shared_secret']} bytes")
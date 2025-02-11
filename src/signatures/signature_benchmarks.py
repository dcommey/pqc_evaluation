# src/signatures/signature_benchmarks.py

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

def benchmark_signature(algorithm: str, message_sizes: List[int], iterations: int = 1000) -> Dict[str, Any]:
    """
    Benchmark signature operations for a given algorithm
    
    Args:
        algorithm: Name of the signature algorithm to benchmark
        message_sizes: List of message sizes to test (in bytes)
        iterations: Number of iterations for timing measurements
    
    Returns:
        Dictionary containing benchmark results and algorithm details
    """
    results = {
        'algorithm': algorithm,
        'iterations': iterations,
        'message_sizes': message_sizes,
        'key_gen_times': [],
        'sign_times': {},
        'verify_times': {},
        'success_rate': {},
        'algorithm_details': None,
        'error_messages': [],
        'sizes': {},
        'statistics': {}
    }
    
    # Initialize timing lists for each message size
    for size in message_sizes:
        results['sign_times'][size] = []
        results['verify_times'][size] = []
        results['success_rate'][size] = 0
    
    try:
        # First test if the algorithm works
        with oqs.Signature(algorithm) as test_sig:
            test_pub = test_sig.generate_keypair()
            test_msg = b"test"
            test_sig_ = test_sig.sign(test_msg)
            if not test_sig.verify(test_msg, test_sig_, test_pub):
                raise Exception("Basic signature test failed")
        
        # Main benchmarking
        with oqs.Signature(algorithm) as sig:
            results['algorithm_details'] = sig.details.copy()
            
            # Measure key generation time
            for i in range(iterations):
                if i == 0:
                    # Keep the first keypair for signing/verification
                    start = time.time()
                    public_key = sig.generate_keypair()
                    results['key_gen_times'].append(time.time() - start)
                    results['sizes']['public_key'] = len(public_key)
                else:
                    # Just measure timing for subsequent generations
                    start = time.time()
                    sig.generate_keypair()  # Discard the result
                    results['key_gen_times'].append(time.time() - start)
            
            # Test each message size
            for msg_size in message_sizes:
                successful_verifications = 0
                message = b'x' * msg_size
                
                # Create new signature instance for verification
                with oqs.Signature(algorithm) as verify_sig:
                    # Need to generate keypair again to maintain correct state
                    verify_pub = verify_sig.generate_keypair()
                    
                    for i in range(iterations):
                        try:
                            # Signing
                            start = time.time()
                            signature = verify_sig.sign(message)
                            sign_time = time.time() - start
                            results['sign_times'][msg_size].append(sign_time)
                            
                            # Record signature size on first iteration
                            if i == 0:
                                results['sizes'][f'signature_{msg_size}'] = len(signature)
                            
                            # Verification
                            start = time.time()
                            is_valid = verify_sig.verify(message, signature, verify_pub)
                            verify_time = time.time() - start
                            
                            if is_valid:
                                successful_verifications += 1
                                results['verify_times'][msg_size].append(verify_time)
                            else:
                                results['error_messages'].append(
                                    f"Verification failed for message size {msg_size}, iteration {i}")
                            
                        except Exception as e:
                            results['error_messages'].append(
                                f"Error in iteration {i} with message size {msg_size}: {str(e)}")
                
                # Calculate success rate for this message size
                results['success_rate'][msg_size] = successful_verifications / iterations
            
            # Calculate statistics
            results['statistics'] = {
                'key_generation': calculate_stats(results['key_gen_times']),
                'signing': {
                    size: calculate_stats(times)
                    for size, times in results['sign_times'].items()
                },
                'verification': {
                    size: calculate_stats(times)
                    for size, times in results['verify_times'].items()
                }
            }
            
    except Exception as e:
        results['error_messages'].append(f"Fatal error: {str(e)}")
    
    return results

def verify_sig_enabled(algorithm: str) -> bool:
    """Check if a signature algorithm is enabled and working"""
    try:
        with oqs.Signature(algorithm) as sig:
            # Full test of the signature algorithm
            public_key = sig.generate_keypair()
            message = b"test message"
            signature = sig.sign(message)
            return sig.verify(message, signature, public_key)
    except Exception as e:
        print(f"Error verifying {algorithm}: {str(e)}")
        return False

def get_available_sigs() -> Dict[str, Any]:
    """Get information about all available signature algorithms"""
    available_sigs = {}
    for sig_name in oqs.get_enabled_sig_mechanisms():
        try:
            with oqs.Signature(sig_name) as sig:
                details = sig.details.copy()
                # Add working status
                details['verified_working'] = verify_sig_enabled(sig_name)
                available_sigs[sig_name] = details
        except Exception as e:
            print(f"Error getting details for {sig_name}: {str(e)}")
    return available_sigs

if __name__ == "__main__":
    # Test all signature algorithms
    print("Testing signature algorithms:\n")
    available = get_available_sigs()
    
    working_algs = []
    for name, details in available.items():
        status = "✓" if details.get('verified_working', False) else "✗"
        print(f"{status} {name} (NIST Level {details['claimed_nist_level']})")
        if details.get('verified_working', False):
            working_algs.append(name)
    
    print(f"\nFound {len(working_algs)} working algorithms")
    
    # Run benchmark on ML-DSA-65 or first working algorithm
    test_algorithm = "ML-DSA-65" if "ML-DSA-65" in working_algs else working_algs[0]
    print(f"\nBenchmarking {test_algorithm}...")
    
    results = benchmark_signature(test_algorithm, [1024, 10240], iterations=10)
    print("\nResults:")
    print(json.dumps(results, indent=2))
    
    # Print summary if successful
    if results['success_rate'][1024] > 0:
        print("\nSummary:")
        print(f"Algorithm: {test_algorithm}")
        print(f"Key generation (mean): {results['statistics']['key_generation']['mean_ms']:.2f} ms")
        for size in [1024, 10240]:
            print(f"\nMessage size: {size} bytes")
            print(f"Signing (mean): {results['statistics']['signing'][size]['mean_ms']:.2f} ms")
            print(f"Verification (mean): {results['statistics']['verification'][size]['mean_ms']:.2f} ms")
            print(f"Success rate: {results['success_rate'][size] * 100:.1f}%")
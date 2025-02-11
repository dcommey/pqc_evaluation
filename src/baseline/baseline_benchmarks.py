# src/baseline/baseline_benchmarks.py

import os
import time
import json
import numpy as np
from typing import Dict, Any, List
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

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

def benchmark_classical_kem(algorithm: str, key_size: int, iterations: int = 1000) -> Dict[str, Any]:
    """Benchmark classical key exchange operations"""
    results = {
        'algorithm': f"{algorithm}-{key_size}",
        'iterations': iterations,
        'key_gen_times': [],
        'encaps_times': [],
        'decaps_times': [],
        'success_rate': 0,
        'algorithm_details': {
            'name': f"{algorithm}-{key_size}",
            'type': 'KEM',
            'key_size': key_size,
            'is_classical': True
        },
        'error_messages': [],
        'sizes': {},
        'statistics': {}
    }
    
    try:
        successful_runs = 0
        max_size = 190 if key_size == 2048 else 318 if key_size == 3072 else 446  # Max message size for RSA-OAEP
        
        for i in range(iterations):
            try:
                if algorithm == 'RSA':
                    # Key generation
                    start = time.time()
                    private_key = rsa.generate_private_key(
                        public_exponent=65537,
                        key_size=key_size
                    )
                    results['key_gen_times'].append(time.time() - start)
                    public_key = private_key.public_key()
                    
                    # Record key sizes on first iteration
                    if i == 0:
                        results['sizes'] = {
                            'public_key': len(public_key.public_bytes(
                                encoding=serialization.Encoding.DER,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                            )),
                            'private_key': len(private_key.private_bytes(
                                encoding=serialization.Encoding.DER,
                                format=serialization.PrivateFormat.PKCS8,
                                encryption_algorithm=serialization.NoEncryption()
                            ))
                        }
                    
                    # Simulate encapsulation with encryption
                    shared_secret = os.urandom(32)  # 256-bit shared secret
                    message = os.urandom(max_size)  # Use appropriate size for RSA-OAEP
                    
                    start = time.time()
                    ciphertext = public_key.encrypt(
                        message,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    results['encaps_times'].append(time.time() - start)
                    
                    if i == 0:
                        results['sizes']['ciphertext'] = len(ciphertext)
                        results['sizes']['shared_secret'] = len(shared_secret)
                    
                    # Decapsulation (decryption)
                    start = time.time()
                    decrypted = private_key.decrypt(
                        ciphertext,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    results['decaps_times'].append(time.time() - start)
                    
                    if decrypted == message:
                        successful_runs += 1
                        
                elif algorithm == 'ECDH':
                    curves = {
                        256: ec.SECP256R1(),
                        384: ec.SECP384R1(),
                        521: ec.SECP521R1()
                    }
                    curve = curves[key_size]
                    
                    # Key generation
                    start = time.time()
                    private_key = ec.generate_private_key(curve)
                    results['key_gen_times'].append(time.time() - start)
                    public_key = private_key.public_key()
                    
                    # Record key sizes on first iteration
                    if i == 0:
                        results['sizes'] = {
                            'public_key': len(public_key.public_bytes(
                                encoding=serialization.Encoding.DER,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                            )),
                            'private_key': len(private_key.private_bytes(
                                encoding=serialization.Encoding.DER,
                                format=serialization.PrivateFormat.PKCS8,
                                encryption_algorithm=serialization.NoEncryption()
                            ))
                        }
                    
                    # Key exchange
                    peer_private = ec.generate_private_key(curve)
                    peer_public = peer_private.public_key()
                    
                    # Encapsulation
                    start = time.time()
                    shared_key = private_key.exchange(ec.ECDH(), peer_public)
                    results['encaps_times'].append(time.time() - start)
                    
                    # Decapsulation
                    start = time.time()
                    peer_shared = peer_private.exchange(ec.ECDH(), public_key)
                    results['decaps_times'].append(time.time() - start)
                    
                    if i == 0:
                        results['sizes']['shared_secret'] = len(shared_key)
                        results['sizes']['ciphertext'] = len(peer_public.public_bytes(
                            encoding=serialization.Encoding.DER,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        ))
                    
                    if shared_key == peer_shared:
                        successful_runs += 1
                
            except Exception as e:
                results['error_messages'].append(f"Error in iteration {i}: {str(e)}")
        
        # Calculate success rate
        results['success_rate'] = successful_runs / iterations
        
        # Calculate statistics
        if len(results['key_gen_times']) > 0:
            results['statistics'] = {
                'key_generation': calculate_stats(results['key_gen_times']),
                'encapsulation': calculate_stats(results['encaps_times']),
                'decapsulation': calculate_stats(results['decaps_times'])
            }
        
    except Exception as e:
        results['error_messages'].append(f"Fatal error: {str(e)}")
    
    return results

def benchmark_classical_signature(algorithm: str, key_size: int, message_sizes: List[int], 
                                iterations: int = 1000) -> Dict[str, Any]:
    """Benchmark classical signature operations"""
    results = {
        'algorithm': f"{algorithm}-{key_size}",
        'iterations': iterations,
        'message_sizes': message_sizes,
        'key_gen_times': [],
        'sign_times': {},
        'verify_times': {},
        'success_rate': {},
        'algorithm_details': {
            'name': f"{algorithm}-{key_size}",
            'type': 'Signature',
            'key_size': key_size,
            'is_classical': True
        },
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
        for size in message_sizes:
            successful_verifications = 0
            message = b'x' * size
            
            for i in range(iterations):
                try:
                    if algorithm == 'RSA':
                        # Key generation
                        start = time.time()
                        private_key = rsa.generate_private_key(
                            public_exponent=65537,
                            key_size=key_size
                        )
                        results['key_gen_times'].append(time.time() - start)
                        public_key = private_key.public_key()
                        
                        # Record key sizes on first iteration
                        if i == 0 and size == message_sizes[0]:
                            results['sizes'] = {
                                'public_key': len(public_key.public_bytes(
                                    encoding=serialization.Encoding.DER,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                                )),
                                'private_key': len(private_key.private_bytes(
                                    encoding=serialization.Encoding.DER,
                                    format=serialization.PrivateFormat.PKCS8,
                                    encryption_algorithm=serialization.NoEncryption()
                                ))
                            }
                        
                        # Signing
                        start = time.time()
                        signature = private_key.sign(
                            message,
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256()
                        )
                        results['sign_times'][size].append(time.time() - start)
                        
                        if i == 0:
                            results['sizes'][f'signature_{size}'] = len(signature)
                        
                        # Verification
                        start = time.time()
                        try:
                            public_key.verify(
                                signature,
                                message,
                                padding.PSS(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    salt_length=padding.PSS.MAX_LENGTH
                                ),
                                hashes.SHA256()
                            )
                            results['verify_times'][size].append(time.time() - start)
                            successful_verifications += 1
                        except InvalidSignature:
                            results['error_messages'].append(
                                f"Invalid signature for size {size}, iteration {i}")
                    
                    elif algorithm == 'ECDSA':
                        # Map key size to curve
                        curves = {
                            256: ec.SECP256R1(),
                            384: ec.SECP384R1(),
                            521: ec.SECP521R1()
                        }
                        curve = curves[key_size]
                        
                        # Key generation
                        start = time.time()
                        private_key = ec.generate_private_key(curve)
                        results['key_gen_times'].append(time.time() - start)
                        public_key = private_key.public_key()
                        
                        # Record key sizes on first iteration
                        if i == 0 and size == message_sizes[0]:
                            results['sizes'] = {
                                'public_key': len(public_key.public_bytes(
                                    encoding=serialization.Encoding.DER,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                                )),
                                'private_key': len(private_key.private_bytes(
                                    encoding=serialization.Encoding.DER,
                                    format=serialization.PrivateFormat.PKCS8,
                                    encryption_algorithm=serialization.NoEncryption()
                                ))
                            }
                        
                        # Signing
                        start = time.time()
                        signature = private_key.sign(
                            message,
                            ec.ECDSA(hashes.SHA256())
                        )
                        results['sign_times'][size].append(time.time() - start)
                        
                        if i == 0:
                            results['sizes'][f'signature_{size}'] = len(signature)
                        
                        # Verification
                        start = time.time()
                        try:
                            public_key.verify(
                                signature,
                                message,
                                ec.ECDSA(hashes.SHA256())
                            )
                            results['verify_times'][size].append(time.time() - start)
                            successful_verifications += 1
                        except InvalidSignature:
                            results['error_messages'].append(
                                f"Invalid signature for size {size}, iteration {i}")
                    
                    elif algorithm == 'Ed25519':
                        # Key generation
                        start = time.time()
                        private_key = ed25519.Ed25519PrivateKey.generate()
                        results['key_gen_times'].append(time.time() - start)
                        public_key = private_key.public_key()
                        
                        # Record key sizes on first iteration
                        if i == 0 and size == message_sizes[0]:
                            results['sizes'] = {
                                'public_key': len(public_key.public_bytes(
                                    encoding=serialization.Encoding.DER,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                                )),
                                'private_key': len(private_key.private_bytes(
                                    encoding=serialization.Encoding.DER,
                                    format=serialization.PrivateFormat.PKCS8,
                                    encryption_algorithm=serialization.NoEncryption()
                                ))
                            }
                        
                        # Signing
                        start = time.time()
                        signature = private_key.sign(message)
                        results['sign_times'][size].append(time.time() - start)
                        
                        if i == 0:
                            results['sizes'][f'signature_{size}'] = len(signature)
                        
                        # Verification
                        start = time.time()
                        try:
                            public_key.verify(signature, message)
                            results['verify_times'][size].append(time.time() - start)
                            successful_verifications += 1
                        except InvalidSignature:
                            results['error_messages'].append(
                                f"Invalid signature for size {size}, iteration {i}")
                    
                except Exception as e:
                    results['error_messages'].append(
                        f"Error for size {size}, iteration {i}: {str(e)}")
            
            # Calculate success rate for this message size
            results['success_rate'][size] = successful_verifications / iterations
        
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

def get_baseline_algorithms() -> Dict[str, List[int]]:
    """Get list of baseline algorithms and their key sizes"""
    return {
        'KEM': {
            'RSA': [2048, 3072, 4096],
            'ECDH': [256, 384, 521]  # P-256, P-384, P-521
        },
        'Signatures': {
            'RSA': [2048, 3072, 4096],
            'ECDSA': [256, 384, 521],  # P-256, P-384, P-521
            'Ed25519': [256]  # Fixed size
        }
    }

def benchmark_baselines(iterations: int = 1000, msg_sizes: List[int] = [1024, 10240]) -> Dict[str, Any]:
    """Run benchmarks for classical algorithms"""
    results = {
        'kems': {},
        'signatures': {},
        'error_messages': []
    }
    
    algorithms = get_baseline_algorithms()
    
    # Benchmark KEMs
    print("\nBenchmarking classical KEMs...")
    for alg_name, key_sizes in algorithms['KEM'].items():
        for key_size in key_sizes:
            print(f"\nTesting {alg_name}-{key_size}...")
            try:
                kem_result = benchmark_classical_kem(alg_name, key_size, iterations)
                if kem_result['success_rate'] > 0:
                    results['kems'][f"{alg_name}-{key_size}"] = kem_result
                    print(f"✓ Success rate: {kem_result['success_rate']*100:.1f}%")
                else:
                    print("✗ Failed: All operations failed")
            except Exception as e:
                print(f"✗ Error: {str(e)}")
                results['error_messages'].append(f"Error benchmarking {alg_name}-{key_size}: {str(e)}")
    
    # Benchmark Signatures
    print("\nBenchmarking classical signatures...")
    for alg_name, key_sizes in algorithms['Signatures'].items():
        for key_size in key_sizes:
            print(f"\nTesting {alg_name}-{key_size}...")
            try:
                sig_result = benchmark_classical_signature(alg_name, key_size, msg_sizes, iterations)
                if any(sig_result['success_rate'][size] > 0 for size in msg_sizes):
                    results['signatures'][f"{alg_name}-{key_size}"] = sig_result
                    print(f"✓ Success rates: " + 
                          ", ".join(f"{size}B: {rate*100:.1f}%" 
                                   for size, rate in sig_result['success_rate'].items()))
                else:
                    print("✗ Failed: All operations failed")
            except Exception as e:
                print(f"✗ Error: {str(e)}")
                results['error_messages'].append(f"Error benchmarking {alg_name}-{key_size}: {str(e)}")
    
    return results

if __name__ == "__main__":
    # Test baseline benchmarks
    print("Running baseline benchmarks...")
    results = benchmark_baselines(iterations=10)  # Small number for testing
    
    # Save results
    with open('baseline_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    # Print summary
    print("\nResults summary:")
    print("\nKEMs:")
    for name, data in results['kems'].items():
        print(f"\n{name}:")
        print(f"Key generation: {data['statistics']['key_generation']['mean_ms']:.2f} ms")
        print(f"Encapsulation: {data['statistics']['encapsulation']['mean_ms']:.2f} ms")
        print(f"Decapsulation: {data['statistics']['decapsulation']['mean_ms']:.2f} ms")
        print(f"Success rate: {data['success_rate']*100:.1f}%")
    
    print("\nSignatures:")
    for name, data in results['signatures'].items():
        print(f"\n{name}:")
        print(f"Key generation: {data['statistics']['key_generation']['mean_ms']:.2f} ms")
        for size in data['statistics']['signing']:
            print(f"\nMessage size: {size} bytes")
            print(f"Signing: {data['statistics']['signing'][size]['mean_ms']:.2f} ms")
            print(f"Verification: {data['statistics']['verification'][size]['mean_ms']:.2f} ms")
            print(f"Success rate: {data['success_rate'][size]*100:.1f}%")
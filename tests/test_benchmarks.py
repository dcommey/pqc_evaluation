#!/usr/bin/env python3
"""Test script for KEM and signature benchmarking"""
import json
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.kems.kem_benchmarks import benchmark_kem, verify_kem_enabled, get_available_kems
from src.signatures.signature_benchmarks import benchmark_signature, verify_sig_enabled, get_available_sigs

def test_kem_benchmarks():
    print("\nTesting KEM benchmarking:")
    print("-" * 50)
    
    # Get available KEMs
    print("\nAvailable KEMs:")
    available_kems = get_available_kems()
    for name, details in available_kems.items():
        print(f"- {name} (NIST Level {details['claimed_nist_level']})")
    
    # Test with ML-KEM-768
    test_kem = "ML-KEM-768"
    if verify_kem_enabled(test_kem):
        print(f"\nBenchmarking {test_kem} (10 iterations)...")
        results = benchmark_kem(test_kem, iterations=10)
        print(json.dumps(results, indent=2))
    else:
        print(f"{test_kem} is not enabled")

def test_signature_benchmarks():
    print("\nTesting signature benchmarking:")
    print("-" * 50)
    
    # Get available signatures
    print("\nAvailable signatures:")
    available_sigs = get_available_sigs()
    for name, details in available_sigs.items():
        print(f"- {name} (NIST Level {details['claimed_nist_level']})")
    
    # Test with ML-DSA-65
    test_sig = "ML-DSA-65"
    if verify_sig_enabled(test_sig):
        print(f"\nBenchmarking {test_sig} (10 iterations)...")
        results = benchmark_signature(test_sig, [1024, 10240], iterations=10)
        print(json.dumps(results, indent=2))
    else:
        print(f"{test_sig} is not enabled")

if __name__ == "__main__":
    test_kem_benchmarks()
    test_signature_benchmarks()
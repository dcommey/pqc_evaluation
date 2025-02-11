# scripts/run_benchmarks.py

#!/usr/bin/env python3
import argparse
import json
import sys
import os
import time
from pathlib import Path
from datetime import datetime

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from src.kems.kem_benchmarks import benchmark_kem, get_available_kems
from src.signatures.signature_benchmarks import benchmark_signature, get_available_sigs
from src.baseline.baseline_benchmarks import (
    benchmark_classical_kem, 
    benchmark_classical_signature, 
    get_baseline_algorithms
)

def get_platform_info():
    """Get platform information in a cross-platform way"""
    uname = os.uname()
    return {
        'system': uname.sysname,
        'node': uname.nodename,
        'release': uname.release,
        'version': uname.version,
        'machine': uname.machine
    }

def save_metrics(results_dir: Path, results: dict, category: str):
    """Save metrics in a structured format"""
    metrics_file = results_dir / f"{category}_metrics.json"
    
    # Add timestamp and platform info
    metrics = {
        'timestamp': datetime.now().isoformat(),
        'platform': get_platform_info(),
        'results': results
    }
    
    with open(metrics_file, 'w') as f:
        json.dump(metrics, f, indent=2)

def run_baseline_benchmarks(results_dir: Path, iterations: int = 1000):
    """Run classical cryptography baseline benchmarks"""
    baseline_dir = results_dir / 'baseline'
    baseline_dir.mkdir(parents=True, exist_ok=True)
    
    # Get baseline algorithms
    baseline_algs = get_baseline_algorithms()
    all_results = {'kems': {}, 'signatures': {}}
    
    # Run classical KEM benchmarks
    print("\nRunning baseline KEM benchmarks...")
    for alg_name, key_sizes in baseline_algs['KEM'].items():
        for key_size in key_sizes:
            print(f"\nBenchmarking {alg_name}-{key_size}...")
            try:
                results = benchmark_classical_kem(alg_name, key_size, iterations)
                if results['success_rate'] > 0:
                    all_results['kems'][f"{alg_name}-{key_size}"] = results
                    print(f"✓ Success rate: {results['success_rate']*100:.1f}%")
                else:
                    print("✗ Failed: All operations failed")
            except Exception as e:
                print(f"✗ Error: {str(e)}")
    
    # Run classical signature benchmarks
    print("\nRunning baseline signature benchmarks...")
    message_sizes = [1024, 10240, 102400, 1048576]  # 1KB, 10KB, 100KB, 1MB
    
    for alg_name, key_sizes in baseline_algs['Signatures'].items():
        for key_size in key_sizes:
            print(f"\nBenchmarking {alg_name}-{key_size}...")
            try:
                results = benchmark_classical_signature(alg_name, key_size, message_sizes, iterations)
                if any(results['success_rate'][size] > 0 for size in message_sizes):
                    all_results['signatures'][f"{alg_name}-{key_size}"] = results
                    print(f"✓ Success rates: " + 
                          ", ".join(f"{size}B: {rate*100:.1f}%" 
                                   for size, rate in results['success_rate'].items()))
                else:
                    print("✗ Failed: All operations failed")
            except Exception as e:
                print(f"✗ Error: {str(e)}")
    
    # Save all baseline results
    save_metrics(baseline_dir, all_results, 'baseline')
    return all_results

def run_pqc_benchmarks(results_dir: Path, iterations: int = 1000):
    """Run post-quantum cryptography benchmarks"""
    pqc_dir = results_dir / 'pqc'
    pqc_dir.mkdir(parents=True, exist_ok=True)
    
    all_results = {'kems': {}, 'signatures': {}}
    
    # Run KEM benchmarks
    print("\nRunning PQC KEM benchmarks...")
    available_kems = get_available_kems()
    for alg_name in sorted(available_kems.keys()):
        print(f"\nBenchmarking {alg_name}...")
        try:
            results = benchmark_kem(alg_name, iterations)
            if results['success_rate'] > 0:
                all_results['kems'][alg_name] = results
                print(f"✓ Success rate: {results['success_rate']*100:.1f}%")
            else:
                print("✗ Failed: All operations failed")
        except Exception as e:
            print(f"✗ Error: {str(e)}")
    
    # Run signature benchmarks
    print("\nRunning PQC signature benchmarks...")
    available_sigs = get_available_sigs()
    message_sizes = [1024, 10240, 102400, 1048576]  # 1KB, 10KB, 100KB, 1MB
    
    for alg_name in sorted(available_sigs.keys()):
        print(f"\nBenchmarking {alg_name}...")
        try:
            results = benchmark_signature(alg_name, message_sizes, iterations)
            if any(results['success_rate'][size] > 0 for size in message_sizes):
                all_results['signatures'][alg_name] = results
                print(f"✓ Success rates: " + 
                      ", ".join(f"{size}B: {rate*100:.1f}%" 
                               for size, rate in results['success_rate'].items()))
            else:
                print("✗ Failed: All operations failed")
        except Exception as e:
            print(f"✗ Error: {str(e)}")
    
    # Save all PQC results
    save_metrics(pqc_dir, all_results, 'pqc')
    return all_results

def save_raw_data(results_dir: Path, name: str, data: dict):
    """Save raw data in JSON format"""
    raw_dir = results_dir / 'raw_data'
    raw_dir.mkdir(parents=True, exist_ok=True)
    timestamp = int(time.time())
    
    with open(raw_dir / f'{name}_{timestamp}.json', 'w') as f:
        json.dump(data, f, indent=2)

def main():
    parser = argparse.ArgumentParser(description='Run cryptographic benchmarks')
    parser.add_argument('--platform', choices=['macos', 'ubuntu', 'raspberry'],
                      required=True, help='Platform to run benchmarks on')
    parser.add_argument('--iterations', type=int, default=1000,
                      help='Number of iterations for each benchmark')
    parser.add_argument('--skip-baseline', action='store_true',
                      help='Skip classical cryptography baseline benchmarks')
    parser.add_argument('--skip-pqc', action='store_true',
                      help='Skip post-quantum cryptography benchmarks')
    parser.add_argument('--quick-test', action='store_true',
                      help='Run with only 10 iterations for testing')
    args = parser.parse_args()
    
    # Create results directory with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    results_dir = project_root / 'results' / args.platform / timestamp
    results_dir.mkdir(parents=True, exist_ok=True)
    
    # Save experiment configuration
    config = {
        'platform': args.platform,
        'iterations': 10 if args.quick_test else args.iterations,
        'skip_baseline': args.skip_baseline,
        'skip_pqc': args.skip_pqc,
        'timestamp': timestamp,
        'platform_info': get_platform_info()
    }
    with open(results_dir / 'experiment_config.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    # Run benchmarks
    if not args.skip_baseline:
        print("\nRunning baseline benchmarks...")
        baseline_results = run_baseline_benchmarks(results_dir, 
                                                10 if args.quick_test else args.iterations)
        save_raw_data(results_dir, 'baseline', baseline_results)
    
    if not args.skip_pqc:
        print("\nRunning post-quantum benchmarks...")
        pqc_results = run_pqc_benchmarks(results_dir, 
                                       10 if args.quick_test else args.iterations)
        save_raw_data(results_dir, 'pqc', pqc_results)
    
    print(f"\nResults saved in: {results_dir}")

if __name__ == '__main__':
    main()
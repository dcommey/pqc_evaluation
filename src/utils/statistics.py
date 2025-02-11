# src/utils/statistics.py

from typing import List, Dict
import numpy as np
from collections import defaultdict

def calculate_timing_stats(times: List[float]) -> Dict[str, float]:
    """Calculate timing statistics"""
    if not times:
        return {
            'mean': 0,
            'median': 0,
            'std': 0,
            'min': 0,
            'max': 0,
            'count': 0
        }
    
    return {
        'mean': float(np.mean(times)),
        'median': float(np.median(times)),
        'std': float(np.std(times)),
        'min': float(np.min(times)),
        'max': float(np.max(times)),
        'count': len(times)
    }

def add_timing_stats(results: Dict) -> Dict:
    """Add timing statistics to benchmark results"""
    stats = defaultdict(dict)
    
    # Key generation stats
    if 'key_gen_times' in results:
        stats['key_generation'] = calculate_timing_stats(results['key_gen_times'])
    
    # KEM stats
    if 'encaps_times' in results:
        stats['encapsulation'] = calculate_timing_stats(results['encaps_times'])
    if 'decaps_times' in results:
        stats['decapsulation'] = calculate_timing_stats(results['decaps_times'])
    
    # Signature stats for each message size
    if 'sign_times' in results:
        stats['signing'] = {
            size: calculate_timing_stats(times)
            for size, times in results['sign_times'].items()
        }
    if 'verify_times' in results:
        stats['verification'] = {
            size: calculate_timing_stats(times)
            for size, times in results['verify_times'].items()
        }
    
    results['statistics'] = dict(stats)
    return results
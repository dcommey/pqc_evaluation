# src/config/algorithms.py

# KEM Algorithms
KEM_ALGORITHMS = {
    'BIKE': ['BIKE-L1', 'BIKE-L3', 'BIKE-L5'],
    
    'Classic-McEliece': [
        'Classic-McEliece-348864', 'Classic-McEliece-348864f',
        'Classic-McEliece-460896', 'Classic-McEliece-460896f',
        'Classic-McEliece-6688128', 'Classic-McEliece-6688128f',
        'Classic-McEliece-6960119', 'Classic-McEliece-6960119f',
        'Classic-McEliece-8192128', 'Classic-McEliece-8192128f'
    ],
    
    'HQC': ['HQC-128', 'HQC-192', 'HQC-256'],
    
    'Kyber': ['Kyber512', 'Kyber768', 'Kyber1024'],
    
    'ML-KEM': ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'],
    
    'NTRU-Prime': ['sntrup761'],
    
    'FrodoKEM': [
        'FrodoKEM-640-AES', 'FrodoKEM-640-SHAKE',
        'FrodoKEM-976-AES', 'FrodoKEM-976-SHAKE',
        'FrodoKEM-1344-AES', 'FrodoKEM-1344-SHAKE'
    ]
}

# Signature Algorithms
SIGNATURE_ALGORITHMS = {
    'Dilithium': ['Dilithium2', 'Dilithium3', 'Dilithium5'],
    
    'ML-DSA': ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'],
    
    'Falcon': ['Falcon-512', 'Falcon-1024', 'Falcon-padded-512', 'Falcon-padded-1024'],
    
    'SPHINCS+-SHA2': [
        'SPHINCS+-SHA2-128f-simple', 'SPHINCS+-SHA2-128s-simple',
        'SPHINCS+-SHA2-192f-simple', 'SPHINCS+-SHA2-192s-simple',
        'SPHINCS+-SHA2-256f-simple', 'SPHINCS+-SHA2-256s-simple'
    ],
    
    'SPHINCS+-SHAKE': [
        'SPHINCS+-SHAKE-128f-simple', 'SPHINCS+-SHAKE-128s-simple',
        'SPHINCS+-SHAKE-192f-simple', 'SPHINCS+-SHAKE-192s-simple',
        'SPHINCS+-SHAKE-256f-simple', 'SPHINCS+-SHAKE-256s-simple'
    ],
    
    'MAYO': ['MAYO-1', 'MAYO-2', 'MAYO-3', 'MAYO-5'],
    
    'CROSS-RSDP': [
        'cross-rsdp-128-balanced', 'cross-rsdp-128-fast', 'cross-rsdp-128-small',
        'cross-rsdp-192-balanced', 'cross-rsdp-192-fast', 'cross-rsdp-192-small',
        'cross-rsdp-256-balanced', 'cross-rsdp-256-fast', 'cross-rsdp-256-small'
    ],
    
    'CROSS-RSDPG': [
        'cross-rsdpg-128-balanced', 'cross-rsdpg-128-fast', 'cross-rsdpg-128-small',
        'cross-rsdpg-192-balanced', 'cross-rsdpg-192-fast', 'cross-rsdpg-192-small',
        'cross-rsdpg-256-balanced', 'cross-rsdpg-256-fast', 'cross-rsdpg-256-small'
    ]
}

# Classical Baseline Algorithms
BASELINE_ALGORITHMS = {
    'KEM': {
        'RSA': ['RSA-2048', 'RSA-3072', 'RSA-4096'],
        'ECDH': ['P-256', 'P-384', 'P-521']
    },
    'Signatures': {
        'RSA': ['RSA-2048', 'RSA-3072', 'RSA-4096'],
        'ECDSA': ['P-256', 'P-384', 'P-521'],
        'Ed25519': ['Ed25519']
    }
}

# Version Information
VERSION_INFO = {
    'liboqs': '0.12.1-dev',
    'liboqs_python': '0.12.0',
    'oqs_version': '0.12.0'
}
#!/usr/bin/env python3
"""
Basic test script to check liboqs installation and explore available functions
"""
import oqs
import inspect

def explore_oqs():
    """Explore the oqs module"""
    print("\n1. Module attributes and functions:")
    print("-" * 50)
    for name, obj in inspect.getmembers(oqs):
        if not name.startswith('_'): 
            print(f"{name}: {type(obj)}")
    
    print("\n2. Testing KeyEncapsulation:")
    print("-" * 50)
    try:
        # Try to create a KEM instance
        kem = oqs.KeyEncapsulation("ML-KEM-768")
        print("\nKEM details:")
        print(f"details: {kem.details}")
        print(f"name: {kem.name}")
        print("\nKEM methods:")
        for name, obj in inspect.getmembers(kem):
            if not name.startswith('_'):
                print(f"{name}: {type(obj)}")
    except Exception as e:
        print(f"Error testing KEM: {str(e)}")
    
    print("\n3. Testing Signature:")
    print("-" * 50)
    try:
        # Try to create a Signature instance
        sig = oqs.Signature("ML-DSA-65")
        print("\nSignature details:")
        print(f"details: {sig.details}")
        print(f"name: {sig.name}")
        print("\nSignature methods:")
        for name, obj in inspect.getmembers(sig):
            if not name.startswith('_'):
                print(f"{name}: {type(obj)}")
    except Exception as e:
        print(f"Error testing Signature: {str(e)}")

if __name__ == "__main__":
    print("Testing liboqs installation...")
    print(f"OQS Module location: {oqs.__file__}")
    explore_oqs()
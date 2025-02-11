#!/usr/bin/env python3
"""Minimal test to understand the exact API behavior"""
import oqs

def test_signature():
    """Test signature API"""
    print("\nTesting Signature API...")
    
    with oqs.Signature("ML-DSA-65") as sig:
        print("\n1. Details:")
        print(sig.details)
        
        print("\n2. Testing keypair generation:")
        public_key = sig.generate_keypair()
        print(f"Public key length: {len(public_key)}")
        print(f"Type: {type(public_key)}")
        
        print("\n3. Testing signing:")
        message = b"test message"
        signature = sig.sign(message)
        print(f"Signature length: {len(signature)}")
        print(f"Type: {type(signature)}")
        
        print("\n4. Testing verification:")
        result = sig.verify(message, signature, public_key)
        print(f"Verification result: {result}")
        print(f"Type: {type(result)}")

def test_kem():
    """Test KEM API"""
    print("\nTesting KEM API...")
    
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        print("\n1. Details:")
        print(kem.details)
        
        print("\n2. Testing keypair generation:")
        public_key = kem.generate_keypair()
        print(f"Public key length: {len(public_key)}")
        print(f"Type: {type(public_key)}")
        
        print("\n3. Testing encapsulation:")
        ciphertext, shared_secret = kem.encap_secret(public_key)
        print(f"Ciphertext length: {len(ciphertext)}")
        print(f"Shared secret length: {len(shared_secret)}")
        
        print("\n4. Testing decapsulation:")
        decapped_secret = kem.decap_secret(ciphertext)
        print(f"Decapped secret length: {len(decapped_secret)}")
        print(f"Secrets match: {shared_secret == decapped_secret}")

if __name__ == "__main__":
    print("Testing liboqs version:", oqs.oqs_version())
    test_signature()
    test_kem()
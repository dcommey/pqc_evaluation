#!/usr/bin/env python3
"""Quick test of OQS algorithms"""
import oqs
import json

def test_single_kem():
    """Test a single KEM operation"""
    algorithm = "ML-KEM-768"
    print(f"\nTesting KEM: {algorithm}")
    
    try:
        with oqs.KeyEncapsulation(algorithm) as kem:
            print("Algorithm details:", json.dumps(kem.details, indent=2))
            
            # Generate keypair
            public_key, secret_key = kem.generate_keypair()
            print(f"\nGenerated keypair: {len(public_key)} bytes (public), {len(secret_key)} bytes (secret)")
            
            # Encapsulate
            ciphertext, shared_secret_sender = kem.encap_secret(public_key)
            print(f"Encapsulation: {len(ciphertext)} bytes (ciphertext), {len(shared_secret_sender)} bytes (shared secret)")
            
            # Decapsulate
            shared_secret_receiver = kem.decap_secret(ciphertext)
            print("Shared secrets match:", shared_secret_sender == shared_secret_receiver)
    
    except Exception as e:
        print(f"Error: {str(e)}")

def test_single_signature():
    """Test a single signature operation"""
    algorithm = "ML-DSA-65"
    print(f"\nTesting Signature: {algorithm}")
    
    try:
        with oqs.Signature(algorithm) as sig:
            print("Algorithm details:", json.dumps(sig.details, indent=2))
            
            # Generate keypair
            public_key, secret_key = sig.generate_keypair()
            print(f"\nGenerated keypair: {len(public_key)} bytes (public), {len(secret_key)} bytes (secret)")
            
            # Sign a message
            message = b"Test message"
            signature = sig.sign(message)
            print(f"Signature size: {len(signature)} bytes")
            
            # Verify
            is_valid = sig.verify(message, signature, public_key)
            print("Signature valid:", is_valid)
    
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    print("liboqs version:", oqs.oqs_version())
    print("Available KEMs:", oqs.get_enabled_kem_mechanisms())
    print("Available signatures:", oqs.get_enabled_sig_mechanisms())
    
    test_single_kem()
    test_single_signature()
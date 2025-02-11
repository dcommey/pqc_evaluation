#!/usr/bin/env python3
"""Debug test of OQS algorithms"""
import oqs

def debug_kem():
    """Debug KEM operation"""
    algorithm = "ML-KEM-768"
    print(f"\nDebugging KEM: {algorithm}")
    
    try:
        with oqs.KeyEncapsulation(algorithm) as kem:
            # Test key generation
            print("\nTesting generate_keypair():")
            keypair = kem.generate_keypair()
            print(f"Type: {type(keypair)}")
            print(f"Value: {keypair}")
            
            # Test encapsulation
            print("\nTesting encap_secret():")
            encap_result = kem.encap_secret(keypair)
            print(f"Type: {type(encap_result)}")
            print(f"Value: {encap_result}")
            
            # Test decapsulation
            if isinstance(encap_result, tuple):
                print("\nTesting decap_secret():")
                decap_result = kem.decap_secret(encap_result[0])
                print(f"Type: {type(decap_result)}")
                print(f"Value: {decap_result}")
    
    except Exception as e:
        print(f"Error: {str(e)}")

def debug_signature():
    """Debug signature operation"""
    algorithm = "ML-DSA-65"
    print(f"\nDebugging Signature: {algorithm}")
    
    try:
        with oqs.Signature(algorithm) as sig:
            # Test key generation
            print("\nTesting generate_keypair():")
            keypair = sig.generate_keypair()
            print(f"Type: {type(keypair)}")
            print(f"Value: {keypair}")
            
            # Test signing
            message = b"Test message"
            print("\nTesting sign():")
            signature = sig.sign(message)
            print(f"Type: {type(signature)}")
            print(f"Value length: {len(signature)}")
            
            # Test verification
            print("\nTesting verify():")
            result = sig.verify(message, signature, keypair)
            print(f"Type: {type(result)}")
            print(f"Value: {result}")
    
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    print("liboqs version:", oqs.oqs_version())
    debug_kem()
    debug_signature()
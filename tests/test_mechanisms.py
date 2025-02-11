#!/usr/bin/env python3
import oqs

def print_version_info():
    print("Version Information:")
    print("-" * 50)
    print(f"liboqs version: {oqs.oqs_version()}")
    print(f"liboqs-python version: {oqs.oqs_python_version()}")
    print(f"OQS_VERSION: {oqs.OQS_VERSION}\n")

def test_kem_mechanisms():
    print("KEM Mechanisms:")
    print("-" * 50)
    print("\nEnabled KEMs:")
    enabled_kems = oqs.get_enabled_kem_mechanisms()
    for kem in enabled_kems:
        print(f"\nTesting {kem}:")
        try:
            with oqs.KeyEncapsulation(kem) as kem_obj:
                print(f"Details: {kem_obj.details}")
        except Exception as e:
            print(f"Error: {str(e)}")
    
    print("\nAll Supported KEMs:")
    print(oqs.get_supported_kem_mechanisms())

def test_signature_mechanisms():
    print("\nSignature Mechanisms:")
    print("-" * 50)
    print("\nEnabled Signatures:")
    enabled_sigs = oqs.get_enabled_sig_mechanisms()
    for sig in enabled_sigs:
        print(f"\nTesting {sig}:")
        try:
            with oqs.Signature(sig) as sig_obj:
                print(f"Details: {sig_obj.details}")
        except Exception as e:
            print(f"Error: {str(e)}")
    
    print("\nAll Supported Signatures:")
    print(oqs.get_supported_sig_mechanisms())

if __name__ == "__main__":
    print_version_info()
    test_kem_mechanisms()
    test_signature_mechanisms()
#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from webauthn import generate_registration_options
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AttestationConveyancePreference
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier

def test_minimal():
    print("Testing minimal WebAuthn options generation...")
    
    # Test with a simple string user_id
    user_id = "test_user_id_string"
    print(f"user_id: {user_id} (type: {type(user_id)})")
    
    try:
        options = generate_registration_options(
            rp_id="localhost",
            rp_name="Test App",
            user_id=user_id,  # This should be a string
            user_name="test_user",
            user_display_name="Test User",
            supported_pub_key_algs=[
                COSEAlgorithmIdentifier.ECDSA_SHA_256,
                COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
            ],
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.REQUIRED
            ),
            timeout=60000
        )
        print("✅ WebAuthn options generated successfully!")
        return True
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_minimal() 
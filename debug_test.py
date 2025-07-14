#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, config_instance
from models import db, User
from webauthn import generate_registration_options
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AttestationConveyancePreference
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from config import Config

def test_user_creation():
    with app.app_context():
        print("Testing user creation...")
        
        # Create a user
        user = User.create_user("test_user", "Test User")
        print(f"User created: {user}")
        print(f"user.user_id type: {type(user.user_id)}")
        print(f"user.user_id value: {repr(user.user_id)}")
        
        # Debug parameters
        rp_id = Config.get_webauthn_rp_id()
        rp_name = config_instance.WEBAUTHN_RP_NAME
        print(f"rp_id: {rp_id} (type: {type(rp_id)})")
        print(f"rp_name: {rp_name} (type: {type(rp_name)})")
        print(f"user_name: {user.user_name} (type: {type(user.user_name)})")
        print(f"user_display_name: {user.display_name} (type: {type(user.display_name)})")
        
        # Test WebAuthn options generation - pass user_id as string
        try:
            options = generate_registration_options(
                rp_id=rp_id,
                rp_name=rp_name,
                user_id=user.user_id,  # Pass as string, not bytes!
                user_name=user.user_name,
                user_display_name=user.display_name,
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
            print("WebAuthn options generated successfully!")
            return True
        except Exception as e:
            print(f"Error generating WebAuthn options: {e}")
            import traceback
            traceback.print_exc()
            return False

if __name__ == "__main__":
    test_user_creation() 
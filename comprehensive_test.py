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

def test_comprehensive():
    with app.app_context():
        print("Testing comprehensive WebAuthn flow...")
        
        # Create a user (exactly like the app does)
        user = User.create_user("test_user", "Test User")
        db.session.add(user)
        db.session.flush()
        
        print(f"User created: {user}")
        print(f"user.user_id: {repr(user.user_id)} (type: {type(user.user_id)})")
        
        # Get the same parameters the app uses
        rp_id = Config.get_webauthn_rp_id()
        rp_name = config_instance.WEBAUTHN_RP_NAME
        
        print(f"rp_id: {repr(rp_id)} (type: {type(rp_id)})")
        print(f"rp_name: {repr(rp_name)} (type: {type(rp_name)})")
        
        # Test the exact same call the app makes
        try:
            options = generate_registration_options(
                rp_id=rp_id,
                rp_name=rp_name,
                user_id=user.user_id,  # This should be a string
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
            print("✅ WebAuthn options generated successfully!")
            return True
        except Exception as e:
            print(f"❌ Error: {e}")
            import traceback
            traceback.print_exc()
            return False

if __name__ == "__main__":
    test_comprehensive() 
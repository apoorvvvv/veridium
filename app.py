from flask import Flask, request, jsonify, session, render_template_string
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room
from webauthn import generate_registration_options, verify_registration_response
from webauthn import generate_authentication_options, verify_authentication_response
from webauthn import options_to_json
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,  # Add this import
    AuthenticatorTransport,
    AttestationConveyancePreference,  # Add for "none"
    AuthenticationCredential
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
import json
import base64
import qrcode
import io
import os
import uuid
from datetime import datetime, timedelta
import secrets
from collections import namedtuple
from webauthn.helpers import parse_registration_credential_json, parse_authentication_credential_json
from webauthn.helpers.exceptions import InvalidRegistrationResponse, InvalidAuthenticationResponse
import binascii

print("*** RUNNING UPDATED APP.PY WITH STRING USER_ID FIX ***")

from config import Config
from models import db, User, Credential, Challenge, CrossDeviceSession
from security import init_security, require_rate_limit, require_webauthn_security

app = Flask(__name__)
app.config.from_object(Config)

# Configure Flask sessions for authentication
app.secret_key = os.environ.get('SECRET_KEY', 'fallback_for_local')
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Create config instance for WebAuthn properties
config_instance = Config()

# Initialize extensions
db.init_app(app)

# --- CORS and SocketIO Setup ---
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Ensure CORS supports credentials and uses correct origins
CORS(app, origins=config_instance.CORS_ORIGINS, supports_credentials=True)

# SocketIO: set async_mode and allowed origins from config
socketio = SocketIO(
    app,
    cors_allowed_origins=config_instance.CORS_ORIGINS,
    async_mode=config_instance.SOCKETIO_ASYNC_MODE,
)

# Print CORS/SocketIO config for debugging
print(f"[DEBUG] CORS_ORIGINS: {config_instance.CORS_ORIGINS}")
print(f"[DEBUG] SOCKETIO_ASYNC_MODE: {config_instance.SOCKETIO_ASYNC_MODE}")

# Initialize security
init_security(app)

# Create tables
with app.app_context():
    db.create_all()

# Add teardown handler for auto-commit on successful requests
@app.teardown_request
def shutdown_session(exception=None):
    if exception:
        db.session.rollback()
        app.logger.error(f"Request failed, rolled back session: {exception}")
    else:
        try:
            db.session.commit()  # Auto-commit on successful request
            app.logger.debug("Auto-committed session on successful request")
        except Exception as e:
            app.logger.error(f"Auto-commit failed: {e}")
    db.session.remove()  # Close session

# HTML template with improved UI
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Veridium - Passwordless Biometric Authentication</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://unpkg.com/@simplewebauthn/browser@9.0.0/dist/bundle/index.umd.js"></script>
    <style>
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; min-height: 100vh; margin: 0; }
        .container { max-width: 400px; margin: 40px auto; background: rgba(0,0,0,0.2); border-radius: 16px; padding: 32px 24px; box-shadow: 0 8px 32px rgba(0,0,0,0.2); }
        h1 { margin-bottom: 16px; }
        .status { margin: 20px 0; padding: 15px; border-radius: 8px; }
        .info { background: rgba(255,255,255,0.1); }
        .success { background: rgba(76,175,80,0.2); }
        .error { background: rgba(244,67,54,0.2); }
        .loading { background: rgba(255,255,255,0.1); }
        input, button { width: 100%; padding: 12px; margin: 8px 0; border-radius: 6px; border: none; font-size: 16px; }
        button { background: #4CAF50; color: white; cursor: pointer; }
        button:disabled { background: #ccc; cursor: not-allowed; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Veridium Login</h1>
        <input id="usernameInput" type="text" placeholder="Enter your username" autocomplete="username" />
        <button id="loginButton">Login with Biometrics</button>
        <div id="status" class="status info">Ready for login.</div>
        <div id="fallback" style="display:none;">
            <p>If your browser does not support cross-device login, <b>scan the QR code below</b> with your mobile device or use manual fallback.</p>
            <!-- Insert your custom QR/manual fallback UI here -->
        </div>
    </div>
    <script>
    function showStatus(message, type = 'info') {
        const status = document.getElementById('status');
        status.textContent = message;
        status.className = `status ${type}`;
    }
    function showCustomQRLogin() {
        document.getElementById('fallback').style.display = 'block';
        showStatus('Fallback: Use QR/manual login below.', 'info');
    }
    async function startWebAuthnLogin(username) {
        if (!username) {
            showStatus('❌ Please enter username', 'error');
            return;
        }
        showStatus('Requesting authentication options...', 'loading');
        const resp = await fetch('/api/begin_authentication', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ username })
        });
        if (!resp.ok) {
            showStatus('❌ Failed to get options: ' + resp.statusText, 'error');
            return;
        }
        const options = await resp.json();
        try {
            showStatus('Prompting for biometrics or cross-device...', 'loading');
            const assertion = await navigator.credentials.get({ publicKey: options });
            // Convert assertion to JSON for backend
            const credential = {};
            Object.keys(assertion).forEach(k => {
                credential[k] = assertion[k];
            });
            credential.id = assertion.id;
            credential.type = assertion.type;
            credential.rawId = btoa(String.fromCharCode(...new Uint8Array(assertion.rawId)));
            credential.response = {};
            Object.keys(assertion.response).forEach(k => {
                credential.response[k] = assertion.response[k];
            });
            credential.response.authenticatorData = btoa(String.fromCharCode(...new Uint8Array(assertion.response.authenticatorData)));
            credential.response.clientDataJSON = btoa(String.fromCharCode(...new Uint8Array(assertion.response.clientDataJSON)));
            credential.response.signature = btoa(String.fromCharCode(...new Uint8Array(assertion.response.signature)));
            if (assertion.response.userHandle) {
                credential.response.userHandle = btoa(String.fromCharCode(...new Uint8Array(assertion.response.userHandle)));
            }
            // Send to backend
            const verifyResp = await fetch('/api/verify_authentication', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({
                    credential: credential,
                    challenge_id: options.challenge_id
                })
            });
            if (!verifyResp.ok) {
                showStatus('❌ Verification failed: ' + verifyResp.statusText, 'error');
                return;
            }
            const verifyResult = await verifyResp.json();
            if (verifyResult.verified) {
                showStatus('✅ Login successful!', 'success');
                // Redirect or update UI as needed
                setTimeout(() => { window.location.href = '/dashboard'; }, 1500);
            } else {
                showStatus('❌ Login failed: ' + (verifyResult.error || 'Unknown error'), 'error');
            }
        } catch (err) {
            console.error('WebAuthn error:', err);
            showStatus('❌ WebAuthn error: ' + err.message, 'error');
            if (err.name === 'NotSupportedError' || err.name === 'NotAllowedError') {
                showCustomQRLogin();
            }
        }
    }
    document.getElementById('loginButton').addEventListener('click', () => {
        const username = document.getElementById('usernameInput').value;
        startWebAuthnLogin(username);
    });
    </script>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/test')
def test():
    return jsonify({'status': 'ok', 'message': 'Test endpoint working'})

@app.route('/api/users')
def list_users():
    """Debug endpoint to list all users in the database"""
    try:
        # Test database connection first
        db.engine.connect()
        app.logger.info("✅ Database connection successful")
        
        users = User.query.all()
        user_list = []
        for user in users:
            user_data = {
                'user_name': user.user_name,
                'user_id': user.user_id,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'credentials_count': len(user.credentials)
            }
            user_list.append(user_data)
        
        return jsonify({
            'database_connection': 'success',
            'users': user_list,
            'total_users': len(user_list)
        })
    except Exception as e:
        app.logger.error(f"Error listing users: {e}")
        return jsonify({'error': str(e), 'database_connection': 'failed'}), 500

@app.route('/api/db-test')
def test_database():
    """Test database connection and basic operations"""
    try:
        # Test connection
        connection = db.engine.connect()
        connection.close()
        
        # Test query
        user_count = User.query.count()
        cred_count = Credential.query.count()
        
        return jsonify({
            'status': 'success',
            'database_url': str(db.engine.url).replace('://', '://***:***@'),  # Hide credentials
            'user_count': user_count,
            'credential_count': cred_count,
            'connection_test': 'passed'
        })
    except Exception as e:
        app.logger.error(f"Database test failed: {e}")
        return jsonify({
            'status': 'failed',
            'error': str(e),
            'connection_test': 'failed'
        }), 500

def urlsafe_b64encode_no_padding(b: bytes) -> str:
    """Convert bytes to base64-url-safe string without padding"""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def base64url_to_bytes(s: str) -> bytes:
    """Convert base64url string to bytes, handling padding"""
    # Add padding if needed
    padding = 4 - len(s) % 4
    if padding != 4:
        s += '=' * padding
    return base64.urlsafe_b64decode(s)

@app.route('/api/begin_registration', methods=['POST'])
@require_rate_limit(limit=10, window=300)  # 10 registrations per 5 minutes
@require_webauthn_security()
def begin_registration():
    try:
        data = request.get_json()
        username = data.get('username', 'veridium_user')
        display_name = data.get('displayName', 'Veridium User')
        
        # Create a new user
        user = User.create_user(username, display_name)
        app.logger.info(f"Created user: {user.user_name} with user_id: {user.user_id}")
        
        db.session.add(user)
        db.session.flush()  # Get the user ID
        app.logger.info(f"User added to session, ID: {user.id}")
        
        # Decode stored str to bytes for the library (should be 32 bytes)
        import base64
        user_id_bytes = base64.urlsafe_b64decode(user.user_id + '==')  # Add padding if needed
        assert len(user_id_bytes) == 32, f"user_id_bytes is {len(user_id_bytes)} bytes, expected 32"
        
        # Generate registration options with attestation="none"
        options = generate_registration_options(
            rp_id=Config.get_webauthn_rp_id(),
            rp_name=config_instance.WEBAUTHN_RP_NAME,
            user_id=user_id_bytes,  # Pass as bytes
            user_name=user.user_name,
            user_display_name=user.display_name,
            supported_pub_key_algs=[
                COSEAlgorithmIdentifier.ECDSA_SHA_256,
                COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
            ],
            attestation=AttestationConveyancePreference.NONE,  # Fix: Skip attestationObject requirement
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.REQUIRED
            ),
            timeout=60000
        )
        
        # Store the challenge
        challenge = Challenge.create_challenge(
            challenge_bytes=options.challenge,
            challenge_type='registration',
            user_id=user.id
        )
        db.session.add(challenge)
        db.session.commit()
        
        # Convert to JSON-serializable format using webauthn helper
        options_json = json.loads(options_to_json(options))
        options_json['challenge_id'] = challenge.id
        
        return jsonify(options_json)
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/api/verify_registration', methods=['POST'])
@require_rate_limit(limit=10, window=300)  # 10 verifications per 5 minutes
@require_webauthn_security()
def verify_registration():
    try:
        data = request.get_json()
        credential_json = data.get('credential')
        challenge_id = data.get('challenge_id')
        
        # Get and validate challenge
        challenge = Challenge.query.filter_by(id=challenge_id).first()
        if not challenge or not challenge.is_valid():
            app.logger.error(f"Invalid challenge ID {challenge_id}")
            return jsonify({'verified': False, 'error': 'Invalid or expired challenge'})
        
        # Get user
        user = User.query.filter_by(id=challenge.user_id).first()
        if not user:
            app.logger.error(f"User not found for challenge {challenge_id}")
            return jsonify({'verified': False, 'error': 'User not found'})
        
        # Parse the JSON dict to the required struct (handles base64 decoding internally)
        credential = parse_registration_credential_json(credential_json)
        
        # Verify the registration - success if no exception
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge.challenge,  # Pass as bytes
            expected_origin=config_instance.WEBAUTHN_RP_ORIGIN,
            expected_rp_id=Config.get_webauthn_rp_id(),
            require_user_verification=True
        )
        
        # No need for if verification.verified - success is indicated by no exception
        # Extract and store credential data with proper transport handling
        transports_list = credential_json.get('response', {}).get('transports', [])
        if isinstance(transports_list, list):
            # Store as list of strings for consistency
            transports_json = [str(t) for t in transports_list]
        else:
            transports_json = []
        
            cred = Credential(
                user_id=user.id,
                credential_id=verification.credential_id,
                public_key=verification.credential_public_key,
                sign_count=verification.sign_count,
            transports=transports_json  # Store as list of strings
            )
            db.session.add(cred)
            
            challenge.used = True
        
        # Explicit commit with error handling
        try:
            db.session.commit()
            app.logger.info(f"✅ Database commit successful for user {user.user_name}")
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"❌ Database commit failed: {e}")
            return jsonify({'error': f'Database error: {str(e)}', 'verified': False}), 500
        
        # Verify user was actually saved to database
        saved_user = User.query.filter_by(user_name=user.user_name).first()
        if saved_user:
            app.logger.info(f"✅ User verified in database: {saved_user.user_name} (ID: {saved_user.id})")
        else:
            app.logger.error(f"❌ User NOT found in database after commit: {user.user_name}")
            return jsonify({'error': 'User not persisted after registration', 'verified': False}), 500
        
        # Verify credential was saved
        saved_cred = Credential.query.filter_by(credential_id=verification.credential_id).first()
        if saved_cred:
            app.logger.info(f"✅ Credential verified in database: {saved_cred.credential_id.hex()[:8]}...")
        else:
            app.logger.error(f"❌ Credential NOT found in database after commit")
            return jsonify({'error': 'Credential not persisted after registration', 'verified': False}), 500
            
            app.logger.info(f"Registration success for user {user.user_id}")
            return jsonify({
                'verified': True,
                'user_id': user.user_id,
            'user_name': user.user_name,  # Add user_name to response
                'credential_id': base64.urlsafe_b64encode(verification.credential_id).decode('utf-8')
            })
            
    except InvalidRegistrationResponse as e:
        db.session.rollback()
        app.logger.error(f"Registration verification failed: {e}")
        return jsonify({'error': str(e), 'verified': False}), 400
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Unexpected error: {e}")
        return jsonify({'error': str(e), 'verified': False}), 500

# GROK'S IMPLEMENTATION - BEGIN AUTHENTICATION
@app.route('/api/begin_authentication', methods=['POST'])
def begin_authentication():
    try:
        data = request.get_json()
        app.logger.info(f"Begin auth request: {data}")

        username = data.get('username')  # Assume frontend sends username for lookup
        app.logger.info(f"Looking up user with username: {username}")

        # List all users for debugging
        all_users = User.query.all()
        app.logger.info(f"All users in database: {[u.user_name for u in all_users]}")

        # Fetch user and their stored credentials
        user = User.query.filter_by(user_name=username).first()
        if not user:
            app.logger.warning(f"User not found for username: {username}")
            # Log all available users for debugging
            all_users = User.query.all()
            available_users = [u.user_name for u in all_users]
            app.logger.info(f"Available users: {available_users}")
            return jsonify({
                'error': 'User not found',
                'verified': False,
                'requested_username': username,
                'available_users': available_users
            }), 400

        # Get allowed credentials (list of dicts with id as base64url)
        allowed_credentials = []
        app.logger.info(f"Processing {len(user.credentials)} credentials for user {username}")

        for cred in user.credentials:
            try:
                transports = cred.transports if cred.transports else []
                if isinstance(transports, str):
                    try:
                        transports = json.loads(transports)
                    except json.JSONDecodeError:
                        transports = []
                if not isinstance(transports, list):
                    transports = []
                TRANSPORT_MAP = {
                    "usb": AuthenticatorTransport.USB,
                    "nfc": AuthenticatorTransport.NFC,
                    "ble": AuthenticatorTransport.BLE,
                    "internal": AuthenticatorTransport.INTERNAL,
                    "cable": AuthenticatorTransport.CABLE,
                    "hybrid": AuthenticatorTransport.HYBRID,
                }
                transport_enums = []
                for transport_item in transports:
                    if isinstance(transport_item, str):
                        transport_enum = TRANSPORT_MAP.get(transport_item.lower())
                        if transport_enum:
                            transport_enums.append(transport_enum)
                    elif isinstance(transport_item, AuthenticatorTransport):
                        transport_enums.append(transport_item)
                # Always include HYBRID for caBLE support
                if AuthenticatorTransport.HYBRID not in transport_enums:
                    transport_enums.append(AuthenticatorTransport.HYBRID)
                descriptor = PublicKeyCredentialDescriptor(
                    id=cred.credential_id,
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                    transports=transport_enums if transport_enums else None
                )
                allowed_credentials.append(descriptor)
            except Exception as e:
                app.logger.error(f"Error processing credential {cred.credential_id.hex()[:8]}: {e}")
                continue

        # Generate challenge
        challenge = os.urandom(32)
        challenge_id = str(uuid.uuid4())
        session[f'challenge_{challenge_id}'] = challenge  # Store challenge by ID
        app.logger.info(f"Stored challenge {challenge_id} in session")

        # Generate options
        try:
            options = generate_authentication_options(
                rp_id=Config.get_webauthn_rp_id(),
                challenge=challenge,
                timeout=60000,  # 60 seconds
                user_verification=UserVerificationRequirement.REQUIRED,  # For biometrics
                allow_credentials=allowed_credentials if allowed_credentials else None
            )
            app.logger.info(f"Successfully generated authentication options")
        except Exception as e:
            import traceback
            app.logger.error(f"Error generating authentication options: {e}")
            app.logger.error(f"Full traceback: {traceback.format_exc()}")
            raise

        # Convert to JSON-friendly (library has options_to_json helper if needed)
        options_json = json.loads(options_to_json(options))
        options_json['challenge_id'] = challenge_id  # Add for frontend to send back

        app.logger.info(f"Generated auth options for user {username} with {len(allowed_credentials)} credentials")

        # Log the final allowed_credentials for debugging (as suggested by Grok)
        for i, cred_desc in enumerate(allowed_credentials):
            transport_values = [t.value for t in cred_desc.transports] if cred_desc.transports else None
            app.logger.info(f"Credential {i}: id={cred_desc.id.hex()[:8]}..., transports={transport_values}")

        return jsonify(options_json), 200
        
    except Exception as e:
        app.logger.error(f"Begin authentication error: {e}")
        return jsonify({'error': str(e), 'verified': False}), 500

# ORIGINAL VERIFY AUTHENTICATION ENDPOINT (COMMENTED OUT FOR GROK'S VERSION)
# @app.route('/api/verify_authentication', methods=['POST'])
# @require_rate_limit(limit=20, window=300)  # 20 verifications per 5 minutes
# @require_webauthn_security()
# def verify_authentication():
#     print("[VERIFY_AUTH] incoming cookies:", request.cookies)
#     print("[VERIFY_AUTH] session cookie:", request.cookies.get('session', 'NOT_FOUND'))
#     try:
#         data = request.get_json()
#         credential_json = data.get('credential')
#         user_id = data.get('user_id')
#         challenge_id = data.get('challenge_id')
#         
#         # Get and validate challenge
#         challenge = Challenge.query.filter_by(id=challenge_id).first()
#         if not challenge or not challenge.is_valid():
#             app.logger.error(f"Invalid challenge ID {challenge_id}")
#             return jsonify({'verified': False, 'error': 'Invalid or expired challenge'})
#         
#         # Get user and credential
#         user = User.query.filter_by(user_id=user_id).first()
#         if not user:
#             app.logger.error(f"User not found for challenge {challenge_id}")
#             return jsonify({'verified': False, 'error': 'User not found'})
#         
#         credential_id = base64.urlsafe_b64decode(credential_json.get('id', ''))
#         db_credential = Credential.query.filter_by(credential_id=credential_id).first()
#         if not db_credential:
#             app.logger.error(f"Credential not found for user {user.user_id}")
#             return jsonify({'verified': False, 'error': 'Credential not found'})
#         
#         # Parse the JSON dict to the required struct (handles base64 decoding internally)
#         credential = parse_authentication_credential_json(credential_json)
#         
#         # Verify the authentication - success if no exception
#         verification = verify_authentication_response(
#             credential=credential,
#             expected_challenge=challenge.challenge,  # Pass as bytes
#             expected_origin=config_instance.WEBAUTHN_RP_ORIGIN,
#             expected_rp_id=Config.get_webauthn_rp_id(),
#             credential_public_key=db_credential.public_key,
#             credential_current_sign_count=db_credential.sign_count,
#             require_user_verification=True
#         )
#         
#         # No need for if verification.verified - success is indicated by no exception
#         db_credential.sign_count = verification.new_sign_count
#         db_credential.last_used = datetime.utcnow()
#         user.last_login = datetime.utcnow()
#         challenge.used = True
#         db.session.commit()
#         
#         app.logger.info(f"Authentication success for user {user.user_id}")
#         return jsonify({
#             'verified': True,
#             'user_id': user.user_id,
#             'last_login': user.last_login.isoformat()
#         })
#             
#     except InvalidAuthenticationResponse as e:
#         db.session.rollback()
#         app.logger.error(f"Authentication verification failed: {e}")
#         return jsonify({'error': str(e), 'verified': False}), 400
#     except Exception as e:
#         db.session.rollback()
#         app.logger.error(f"Unexpected error: {e}")
#         return jsonify({'error': str(e), 'verified': False}), 500

# GROK'S IMPLEMENTATION - VERIFY AUTHENTICATION
@app.route('/api/verify_authentication', methods=['POST'])
def verify_authentication():
    try:
        data = request.get_json()
        app.logger.info(f"Verify auth request: challenge_id={data.get('challenge_id')}")
        
        credential = data.get('credential')  # From SimpleWebAuthn startAuthentication
        challenge_id = data.get('challenge_id')
        
        # Get stored challenge
        stored_challenge = session.get(f'challenge_{challenge_id}')
        if not stored_challenge:
            app.logger.warning(f"Challenge not found in session: {challenge_id}")
            return jsonify({'error': 'Challenge not found', 'verified': False}), 400
        
        # Parse credential JSON to struct (use library helper if available)
        auth_credential = parse_authentication_credential_json(credential)
        
        # Fetch stored credential data for this cred_id (decode id from base64url)
        cred_id_bytes = base64url_to_bytes(credential['id'])
        db_credential = Credential.query.filter_by(credential_id=cred_id_bytes).first()
        if not db_credential:
            return jsonify({'error': 'Credential not found', 'verified': False}), 400
        
        # Type assertions for debugging
        assert isinstance(db_credential.credential_id, bytes), f"Invalid stored cred_id type: {type(db_credential.credential_id)}"
        assert isinstance(db_credential.public_key, bytes), f"Invalid public_key type: {type(db_credential.public_key)}"
        assert isinstance(db_credential.sign_count, int), f"Invalid sign_count type: {type(db_credential.sign_count)}"
        
        # Get user
        user = User.query.filter_by(id=db_credential.user_id).first()
        if not user:
            return jsonify({'error': 'User not found', 'verified': False}), 400
        
        # Verify - success if no exception
        verified_authentication = verify_authentication_response(
            credential=auth_credential,
            expected_challenge=stored_challenge,
            expected_rp_id=Config.get_webauthn_rp_id(),
            expected_origin=config_instance.WEBAUTHN_RP_ORIGIN,
            credential_public_key=db_credential.public_key,  # bytes
            credential_current_sign_count=db_credential.sign_count,  # int
            require_user_verification=True  # Matches options
        )
        
        # Extract and update
        new_sign_count = verified_authentication.new_sign_count
        db_credential.sign_count = new_sign_count  # Update in DB to prevent replays
        db_credential.last_used = datetime.utcnow()
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        # Optional: Get user_handle (user_id bytes) for confirmation from the input credential
        user_handle = auth_credential.response.user_handle  # bytes or None
        
        if user_handle:
            # Convert stored user.user_id to bytes if it's str (base64url-encoded)
            stored_user_id_bytes = user.user_id
            if isinstance(stored_user_id_bytes, str):
                try:
                    stored_user_id_bytes = base64.urlsafe_b64decode(stored_user_id_bytes + '==')  # Add padding if needed, decode to bytes
                except (binascii.Error, ValueError) as e:
                    app.logger.error(f"Invalid base64url for stored user_id: {e}")
                    raise ValueError("Stored user_id decoding failed - potential data issue")
            
            # For security, verify it matches the expected user's stored user_id_bytes
            if user_handle != stored_user_id_bytes:
                raise ValueError("User handle mismatch - potential security issue")
            user_id = user_handle  # Use it if needed
        else:
            # If None, fall back to your looked-up user (assume user.user_id is bytes here)
            user_id = user.user_id if isinstance(user.user_id, bytes) else base64.urlsafe_b64decode(user.user_id + '==')
        
        # Success response
        return jsonify({
            'verified': True,
            'user_id': base64.urlsafe_b64encode(user_id).decode('utf-8').rstrip('=') if user_id else None
        }), 200
    
    except InvalidAuthenticationResponse as e:
        app.logger.error(f"Authentication verification failed: {e}")
        return jsonify({'error': str(e), 'verified': False}), 400
    except Exception as e:
        app.logger.error(f"Unexpected error: {e}")
        return jsonify({'error': str(e), 'verified': False}), 500

@app.route('/api/verify_cross_device_auth', methods=['POST'])
def verify_cross_device_auth():
    try:
        data = request.get_json()
        credential = data.get('credential')
        challenge_id = data.get('challenge_id')
        
        # Get stored challenge
        stored_challenge_data = session.get(f'cross_device_challenge_{challenge_id}')
        if not stored_challenge_data:
            return jsonify({'success': False, 'error': 'Challenge not found'}), 400
        
        stored_challenge = stored_challenge_data['challenge']
        session_id = stored_challenge_data['session_id']
        
        # Parse credential
        auth_credential = parse_authentication_credential_json(credential)
        
        # Find credential in database
        cred_id_bytes = base64url_to_bytes(credential['id'])
        db_credential = Credential.query.filter_by(credential_id=cred_id_bytes).first()
        if not db_credential:
            return jsonify({'success': False, 'error': 'Credential not found'}), 400
        
        # Get user
        user = User.query.filter_by(id=db_credential.user_id).first()
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 400
        
        # Verify authentication
        verified_authentication = verify_authentication_response(
            credential=auth_credential,
            expected_challenge=stored_challenge,
            expected_rp_id=Config.get_webauthn_rp_id(),
            expected_origin=config_instance.WEBAUTHN_RP_ORIGIN,
            credential_public_key=db_credential.public_key,
            credential_current_sign_count=db_credential.sign_count,
            require_user_verification=True
        )
        
        # Update credential
        db_credential.sign_count = verified_authentication.new_sign_count
        db_credential.last_used = datetime.utcnow()
        user.last_login = datetime.utcnow()
        
        # Update cross-device session
        session_obj = CrossDeviceSession.query.filter_by(session_id=session_id).first()
        if session_obj:
            session_obj.authenticate(user.user_id)
        
        db.session.commit()
        
        # Emit success to desktop via WebSocket
        socketio.emit('session_authenticated', {
            'session_id': session_id,
            'user_id': user.user_id,
            'user_name': user.user_name
        }, room=session_id)
        
        # Clean up session
        session.pop(f'cross_device_challenge_{challenge_id}', None)
        
        return jsonify({
            'success': True,
            'user_id': user.user_id,
            'user_name': user.user_name,
            'message': 'Cross-device authentication successful'
        })
        
    except InvalidAuthenticationResponse as e:
        app.logger.error(f"Cross-device authentication verification failed: {e}")
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        app.logger.error(f"Cross-device authentication error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/generate_qr', methods=['POST'])
def generate_qr():
    try:
        # Create a new cross-device session with minimal data
        session_id = secrets.token_urlsafe(32)
        session_data = {
            'session_id': session_id,
            'rp_id': Config.get_webauthn_rp_id(),
            'timestamp': datetime.utcnow().isoformat(),
            'expires_at': (datetime.utcnow() + timedelta(minutes=5)).isoformat()  # 5 minute expiry
        }
        
        # Store session data in database
        session_obj = CrossDeviceSession.create_session(
            qr_data=json.dumps(session_data),
            desktop_session_id=session.get('session_id')
        )
        db.session.add(session_obj)
        db.session.commit()
        
        # Generate QR code with a clickable URL instead of JSON data
        # This will open the Veridium app when scanned with phone camera
        qr_url = f"{config_instance.WEBAUTHN_RP_ORIGIN}/auth?session_id={session_id}&rp_id={Config.get_webauthn_rp_id()}"
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_url)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_str = base64.b64encode(img_buffer.getvalue()).decode()
        
        return jsonify({
            'session_id': session_id,
            'qr_image': f'data:image/png;base64,{img_str}',
            'expires_at': session_obj.expires_at.isoformat()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/api/authenticate_qr', methods=['POST'])
def authenticate_qr():
    try:
        data = request.get_json()
        session_id = data.get('session_id')
        
        # Find the session
        session_obj = CrossDeviceSession.query.filter_by(session_id=session_id).first()
        if not session_obj or not session_obj.is_valid():
            return jsonify({'success': False, 'error': 'Invalid or expired session'})
        
        # Parse session data
        session_data = json.loads(session_obj.qr_data)
        
        # Generate authentication options for biometric prompt
        challenge = os.urandom(32)
        challenge_id = str(uuid.uuid4())
        session[f'challenge_{challenge_id}'] = challenge
        
        # Get all users for discoverable credentials (resident keys)
        all_users = User.query.all()
        allowed_credentials = []
        
        for user in all_users:
            for cred in user.credentials:
                try:
                    descriptor = PublicKeyCredentialDescriptor(
                        id=cred.credential_id,
                        type=PublicKeyCredentialType.PUBLIC_KEY,
                        transports=[AuthenticatorTransport.HYBRID, AuthenticatorTransport.INTERNAL]
                    )
                    allowed_credentials.append(descriptor)
                except Exception as e:
                    app.logger.error(f"Error processing credential: {e}")
                    continue
        
        # Generate authentication options
        options = generate_authentication_options(
            rp_id=Config.get_webauthn_rp_id(),
            challenge=challenge,
            timeout=60000,
            user_verification=UserVerificationRequirement.REQUIRED,
            allow_credentials=allowed_credentials if allowed_credentials else None
        )
        
        # Store challenge for verification
        session[f'cross_device_challenge_{challenge_id}'] = {
            'challenge': challenge,
            'session_id': session_id,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Convert to JSON
        options_json = json.loads(options_to_json(options))
        options_json['challenge_id'] = challenge_id
        
        return jsonify({
            'success': True,
            'auth_options': options_json,
            'message': 'Biometric authentication required'
        })
        
    except Exception as e:
        app.logger.error(f"QR authentication error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/auth')
def handle_qr_auth():
    """Handle QR code URL when scanned - automatically start cross-device authentication"""
    session_id = request.args.get('session_id')
    rp_id = request.args.get('rp_id')
    
    if not session_id:
        return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Veridium - Invalid QR Code</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 20px; }
                .error { color: #d32f2f; }
            </style>
        </head>
        <body>
            <h1>🔐 Veridium</h1>
            <p class="error">Invalid QR code. Please scan a valid Veridium QR code.</p>
        </body>
        </html>
        ''')
    
    # Find the session
    session_obj = CrossDeviceSession.query.filter_by(session_id=session_id).first()
    if not session_obj or not session_obj.is_valid():
        return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Veridium - Expired QR Code</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 20px; }
                .error { color: #d32f2f; }
            </style>
        </head>
        <body>
            <h1>🔐 Veridium</h1>
            <p class="error">QR code has expired. Please generate a new one on your desktop.</p>
        </body>
        </html>
        ''')
    
    # Return a page that automatically starts biometric authentication
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Veridium - Biometric Authentication</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <script src="https://unpkg.com/@simplewebauthn/browser@9.0.0/dist/bundle/index.umd.js"></script>
        <style>
            body { 
                font-family: Arial, sans-serif; 
                text-align: center; 
                padding: 20px; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                min-height: 100vh;
                margin: 0;
                display: flex;
                flex-direction: column;
                justify-content: center;
            }
            .container { max-width: 400px; margin: 0 auto; }
            .status { margin: 20px 0; padding: 15px; border-radius: 8px; }
            .info { background: rgba(255,255,255,0.1); }
            .success { background: rgba(76,175,80,0.2); }
            .error { background: rgba(244,67,54,0.2); }
            .loading { background: rgba(255,255,255,0.1); }
            button { 
                background: #4CAF50; 
                color: white; 
                border: none; 
                padding: 12px 24px; 
                border-radius: 6px; 
                font-size: 16px; 
                cursor: pointer; 
                margin: 10px;
            }
            button:disabled { background: #ccc; cursor: not-allowed; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Veridium</h1>
            <p>Complete biometric authentication to log in on your desktop</p>
            
            <div id="status" class="status info">
                Preparing authentication...
            </div>
            
            <button id="authButton" onclick="startAuth()" style="display: none;">
                Start Biometric Authentication
            </button>
        </div>

        <script>
            const sessionId = '{{ session_id }}';
            let authOptions = null;

            async function showStatus(message, type = 'info') {
                const status = document.getElementById('status');
                status.textContent = message;
                status.className = `status ${type}`;
            }

            async function startAuth() {
                try {
                    showStatus('Starting biometric authentication...', 'loading');
                    document.getElementById('authButton').disabled = true;

                    // Step 1: Get authentication options
                    const authResponse = await fetch('/api/authenticate_qr', {
                        method: 'POST',
                        credentials: 'include',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ session_id: sessionId })
                    });
                    
                    const authResult = await authResponse.json();
                    
                    if (!authResult.success) {
                        showStatus('❌ Authentication setup failed: ' + (authResult.error || 'Unknown error'), 'error');
                        return;
                    }
                    
                    authOptions = authResult.auth_options;
                    showStatus('Please complete biometric authentication...', 'loading');
                    
                    // Step 2: Trigger biometric authentication
                    const assertion = await SimpleWebAuthnBrowser.startAuthentication(authOptions);
                    
                    // Step 3: Verify the authentication
                    const verifyResponse = await fetch('/api/verify_cross_device_auth', {
                        method: 'POST',
                        credentials: 'include',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            credential: assertion,
                            challenge_id: authOptions.challenge_id
                        })
                    });
                    
                    const verifyResult = await verifyResponse.json();
                    
                    if (verifyResult.success) {
                        showStatus('✅ Authentication successful! Your desktop will be logged in automatically.', 'success');
                        // Close the page after a few seconds
                        setTimeout(() => {
                            window.close();
                        }, 3000);
                    } else {
                        showStatus('❌ Authentication failed: ' + (verifyResult.error || 'Unknown error'), 'error');
                        document.getElementById('authButton').disabled = false;
                    }
                } catch (error) {
                    console.error('Authentication error:', error);
                    showStatus('❌ Authentication error: ' + error.message, 'error');
                    document.getElementById('authButton').disabled = false;
                }
            }

            // Auto-start authentication when page loads
            window.addEventListener('load', () => {
                setTimeout(() => {
                    document.getElementById('authButton').style.display = 'inline-block';
                    showStatus('Click the button below to start biometric authentication', 'info');
                }, 1000);
            });
        </script>
    </body>
    </html>
    ''', session_id=session_id)

@app.route('/qr/<session_id>')
def qr_redirect(session_id):
    """Legacy QR redirect - now handled by in-app scanning"""
    return jsonify({
        'error': 'This endpoint is deprecated. Please use the main app to scan QR codes.',
        'message': 'QR codes should be scanned directly in the Veridium app'
    }), 400

@socketio.on('join_session')
def handle_join_session(data):
    session_id = data['session_id']
    join_room(session_id)
    emit('joined', {'session_id': session_id})

if __name__ == '__main__':
    import os
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_ENV') == 'development'
    socketio.run(app, debug=debug, host=host, port=port) 
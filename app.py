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
    AuthenticationCredential,
    ResidentKeyRequirement
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
    <style>
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; min-height: 100vh; margin: 0; display: flex; flex-direction: column; justify-content: center; align-items: center; }
        .container { background: rgba(0,0,0,0.3); border-radius: 16px; padding: 40px 32px; box-shadow: 0 8px 32px rgba(0,0,0,0.2); max-width: 400px; margin: 40px auto; }
        h1 { margin-bottom: 24px; }
        button { background: #4CAF50; color: white; border: none; padding: 16px 32px; border-radius: 8px; font-size: 18px; margin: 16px 0; cursor: pointer; width: 100%; transition: background 0.2s; }
        button:hover { background: #388e3c; }
        #status { margin: 16px 0; padding: 12px; border-radius: 6px; background: rgba(255,255,255,0.1); color: #fff; min-height: 32px; font-size: 15px; }
        #debug { margin: 10px 0; padding: 10px; background: rgba(0,0,0,0.15); border-radius: 6px; font-size: 13px; word-break: break-all; }
        #current-user { margin-top: 30px; font-size: 16px; color: #fff; background: rgba(0,0,0,0.18); padding: 10px 0; border-radius: 6px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Veridium</h1>
        <div id="status">Ready for passwordless authentication.</div>
        <div id="debug"></div>
        <button id="signupButton">Sign Up with Biometrics</button>
        <button id="loginButton">Login with Biometrics</button>
    </div>
    <div id="current-user"></div>
    <script>
    function loadScript(url, callback) {
        const script = document.createElement('script');
        script.src = url;
        script.onload = callback;
        script.onerror = () => console.error('SimpleWebAuthn script load failed');
        document.head.appendChild(script);
    }
    loadScript('https://unpkg.com/@simplewebauthn/browser@13.1.2/dist/bundle/index.umd.js', () => {
        function setStatus(msg) {
            document.getElementById('status').textContent = msg;
        }
        function setDebug(obj) {
            document.getElementById('debug').textContent = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
        }
        function setCurrentUser(user) {
            document.getElementById('current-user').textContent = user ? `Current User: ${user}` : 'Not logged in.';
        }
        function getCurrentUser() {
            return localStorage.getItem('veridium_username') || '';
        }
        setCurrentUser(getCurrentUser());

        async function handleSignup() {
            setDebug('');
            try {
                setStatus('Requesting registration options...');
                const optionsResp = await fetch('/api/begin_registration', { method: 'POST' });
                const options = await optionsResp.json();
                setDebug({ step: 'begin_registration', options });
                setStatus('Prompting for biometrics...');
                const credential = await SimpleWebAuthnBrowser.startRegistration(options);
                setDebug({ step: 'startRegistration', credential });
                setStatus('Verifying registration...');
                const verifyResp = await fetch('/api/verify_registration', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ credential, challenge_id: options.challenge_id })
                });
                const result = await verifyResp.json();
                setDebug({ step: 'verify_registration', result });
                if (result.verified) {
                    setStatus('✅ Signup successful! You can now log in.');
                    const userLabel = 'user_' + Date.now();
                    localStorage.setItem('veridium_username', userLabel);
                    setCurrentUser(userLabel);
                } else {
                    setStatus('❌ Signup failed: ' + (result.error || 'Unknown error'));
                }
            } catch (err) {
                setStatus('❌ Signup failed: ' + err.message);
                setDebug(err.stack || err);
            }
        }
        async function handleLogin() {
            setDebug('');
            try {
                setStatus('Requesting authentication options...');
                const optionsResp = await fetch('/api/begin_authentication', { method: 'POST' });
                const options = await optionsResp.json();
                setDebug({ step: 'begin_authentication', options });
                setStatus('Prompting for biometrics...');
                const assertion = await SimpleWebAuthnBrowser.startAuthentication(options);
                setDebug({ step: 'startAuthentication', assertion });
                setStatus('Verifying login...');
                const verifyResp = await fetch('/api/verify_authentication', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ credential: assertion, challenge_id: options.challenge_id })
                });
                const result = await verifyResp.json();
                setDebug({ step: 'verify_authentication', result });
                if (result.verified) {
                    setStatus('✅ Login successful!');
                    const userLabel = 'user_' + Date.now();
                    localStorage.setItem('veridium_username', userLabel);
                    setCurrentUser(userLabel);
                } else {
                    setStatus('❌ Login failed: ' + (result.error || 'Unknown error'));
                }
            } catch (err) {
                setStatus('❌ Login failed: ' + err.message);
                setDebug(err.stack || err);
            }
        }
        document.getElementById('signupButton').addEventListener('click', handleSignup);
        document.getElementById('loginButton').addEventListener('click', handleLogin);
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
def begin_registration():
    try:
        user_id_bytes = os.urandom(32)
        challenge = os.urandom(32)
        challenge_id = str(uuid.uuid4())
        session[f'challenge_{challenge_id}'] = challenge
        session[f'user_id_{challenge_id}'] = user_id_bytes
        options = generate_registration_options(
            rp_id=Config.get_webauthn_rp_id(),
            rp_name="Veridium",
            user_id=user_id_bytes,
            user_name="biometric_user",
            user_display_name="Veridium User",
            challenge=challenge,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED
            ),
            timeout=60000,
            attestation="none"
        )
        options_json = json.loads(options_to_json(options))
        options_json['challenge_id'] = challenge_id
        return jsonify(options_json), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/verify_registration', methods=['POST'])
def verify_registration():
    data = request.get_json()
    credential = data.get('credential')
    challenge_id = data.get('challenge_id')
    stored_challenge = session.get(f'challenge_{challenge_id}')
    stored_user_id = session.get(f'user_id_{challenge_id}')
    if not stored_challenge or not stored_user_id:
        return jsonify({'error': 'Invalid session'}), 400
    try:
        verified_registration = verify_registration_response(
            credential=credential,
            expected_challenge=stored_challenge,
            expected_rp_id=Config.get_webauthn_rp_id(),
            expected_origin=config_instance.WEBAUTHN_RP_ORIGIN
        )
        # Create user with auto-generated ID
        user = User(user_id=stored_user_id)
        db.session.add(user)
        db.session.commit()
        # Store credential linked to user
        credential_model = Credential(
            user_id=user.id,
            credential_id=verified_registration.credential_id,
            public_key=verified_registration.credential_public_key,
            sign_count=verified_registration.sign_count
        )
        db.session.add(credential_model)
        db.session.commit()
        # Clean up session
        session.pop(f'challenge_{challenge_id}')
        session.pop(f'user_id_{challenge_id}')
        return jsonify({'verified': True}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/api/begin_authentication', methods=['POST'])
def begin_authentication():
    challenge = os.urandom(32)
    challenge_id = str(uuid.uuid4())
    session[f'challenge_{challenge_id}'] = challenge
    options = generate_authentication_options(
        rp_id=Config.get_webauthn_rp_id(),
        challenge=challenge,
        user_verification=UserVerificationRequirement.REQUIRED,
        timeout=60000
    )
    options_json = json.loads(options_to_json(options))
    options_json['challenge_id'] = challenge_id
    return jsonify(options_json), 200

@app.route('/api/verify_authentication', methods=['POST'])
def verify_authentication():
    data = request.get_json()
    credential = data.get('credential')
    challenge_id = data.get('challenge_id')
    stored_challenge = session.get(f'challenge_{challenge_id}')
    if not stored_challenge:
        return jsonify({'error': 'Invalid session'}), 400
    try:
        auth_credential = parse_authentication_credential_json(credential)
        verified_auth = verify_authentication_response(
            credential=auth_credential,
            expected_challenge=stored_challenge,
            expected_rp_id=Config.get_webauthn_rp_id(),
            expected_origin=config_instance.WEBAUTHN_RP_ORIGIN,
            credential_public_key=None,  # Not needed for discoverable
            credential_current_sign_count=None,
            require_user_verification=True
        )
        user_handle = auth_credential.response.user_handle
        if user_handle:
            user = User.query.filter_by(user_id=user_handle).first()
            if not user:
                return jsonify({'error': 'User not found'}), 400
            # Proceed with login (set session, etc.)
        else:
            return jsonify({'error': 'No user handle'}), 400
        # Clean up session
        session.pop(f'challenge_{challenge_id}')
        return jsonify({'verified': True}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Optional: Magic link endpoint stub for future cross-device
@app.route('/api/send_magic_link', methods=['POST'])
def send_magic_link():
    # TODO: Implement magic link logic (email/SMS)
    return jsonify({'sent': True}), 200

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
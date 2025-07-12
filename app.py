from flask import Flask, request, jsonify, session, render_template_string
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room
from webauthn import generate_registration_options, verify_registration_response
from webauthn import generate_authentication_options, verify_authentication_response
from webauthn import options_to_json
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    AuthenticatorTransport
)
from webauthn.helpers.structs import AuthenticatorSelectionCriteria
# COSEAlgorithmIdentifier not needed - using numeric values directly
import json
import base64
import qrcode
import io
from datetime import datetime
import secrets

from config import Config
from models import db, User, Credential, Challenge, CrossDeviceSession
from security import init_security, require_rate_limit, require_webauthn_security

app = Flask(__name__)
app.config.from_object(Config)

# Create config instance for WebAuthn properties
config_instance = Config()

# Initialize extensions
db.init_app(app)
CORS(app, origins=app.config['CORS_ORIGINS'])
socketio = SocketIO(
    app, 
    cors_allowed_origins=app.config['CORS_ORIGINS'],
    async_mode=app.config['SOCKETIO_ASYNC_MODE']
)

# Initialize security
init_security(app)

# Create tables
with app.app_context():
    db.create_all()

# HTML template with improved UI
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Veridium - Biometric Authentication</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 800px; 
            margin: 0 auto; 
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: white;
        }
        .container {
            background: rgba(255, 255, 255, 0.1);
            padding: 30px;
            border-radius: 15px;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }
        h1 { 
            text-align: center; 
            font-size: 2.5em; 
            margin-bottom: 30px;
            text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.3);
        }
        .subtitle {
            text-align: center;
            font-size: 1.2em;
            margin-bottom: 40px;
            opacity: 0.9;
        }
        button { 
            background: linear-gradient(45deg, #FF6B6B, #FF8E8E);
            color: white; 
            border: none; 
            padding: 15px 30px; 
            font-size: 16px; 
            border-radius: 25px;
            cursor: pointer; 
            margin: 10px;
            width: 200px;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(255, 107, 107, 0.3);
        }
        button:hover { 
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(255, 107, 107, 0.4);
        }
        button:disabled {
            background: #ccc;
            cursor: not-allowed;
            transform: none;
        }
        .button-group {
            text-align: center;
            margin: 30px 0;
        }
        .section {
            margin: 30px 0;
            padding: 20px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
        }
        .user-info {
            background: rgba(0, 255, 0, 0.1);
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
        }
        .error {
            background: rgba(255, 0, 0, 0.2);
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
        }
        .success {
            background: rgba(0, 255, 0, 0.2);
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
        }
        .qr-section {
            text-align: center;
            margin: 20px 0;
        }
        #qr-code {
            background: white;
            padding: 20px;
            border-radius: 10px;
            display: inline-block;
            margin: 20px;
        }
        .device-info {
            font-size: 0.9em;
            opacity: 0.8;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Veridium</h1>
        <p class="subtitle">Passwordless Biometric Authentication</p>
        
        <div class="section">
            <h3>📱 Mobile Authentication</h3>
            <div class="button-group">
                <button onclick="register()">Sign Up with Biometrics</button>
                <button onclick="login()">Login with Biometrics</button>
            </div>
        </div>
        
        <div class="section">
            <h3>🖥️ Desktop Cross-Device</h3>
            <div class="button-group">
                <button onclick="generateQR()">Generate QR for Login</button>
                <button onclick="scanQR()">Scan QR (Mobile)</button>
            </div>
            <div class="qr-section" id="qr-section" style="display: none;">
                <div id="qr-code"></div>
                <p>Scan this QR code with your mobile device</p>
            </div>
        </div>
        
        <div id="status"></div>
        
        <div class="device-info">
            <p><strong>Device Support:</strong></p>
            <p>• iOS: Face ID, Touch ID (Safari)</p>
            <p>• Android: Fingerprint, Face Unlock (Chrome)</p>
            <p>• Desktop: Cross-device via QR code</p>
        </div>
    </div>

    <script src="https://unpkg.com/@simplewebauthn/browser@9/dist/bundle/index.umd.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <script>
        const socket = io();
        let currentUser = localStorage.getItem('veridium_user_id');
        
        function showStatus(message, type = 'info') {
            const statusDiv = document.getElementById('status');
            statusDiv.innerHTML = `<div class="${type}">${message}</div>`;
            setTimeout(() => statusDiv.innerHTML = '', 5000);
        }
        
        async function register() {
            try {
                showStatus('Starting registration...', 'info');
                
                const optionsResp = await fetch('/api/begin_registration', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        username: 'veridium_user_' + Date.now(),
                        displayName: 'Veridium User'
                    })
                });
                
                if (!optionsResp.ok) throw new Error('Registration failed');
                
                const options = await optionsResp.json();
                showStatus('Please complete biometric authentication...', 'info');
                
                const credential = await SimpleWebAuthnBrowser.startRegistration(options);
                
                const verifyResp = await fetch('/api/verify_registration', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        credential: credential,
                        challenge_id: options.challenge_id
                    })
                });
                
                const result = await verifyResp.json();
                
                if (result.verified) {
                    localStorage.setItem('veridium_user_id', result.user_id);
                    currentUser = result.user_id;
                    showStatus(`✅ Registration successful! User ID: ${result.user_id}`, 'success');
                } else {
                    showStatus('❌ Registration failed: ' + (result.error || 'Unknown error'), 'error');
                }
            } catch (error) {
                let errorMsg = error.message;
                if (errorMsg.includes('not supported on sites with TLS certificate errors')) {
                    errorMsg = 'WebAuthn blocked due to certificate error. Please use HTTP: http://192.168.29.237:5001';
                }
                showStatus('❌ Registration error: ' + errorMsg, 'error');
            }
        }
        
        async function login() {
            if (!currentUser) {
                currentUser = prompt('Enter your User ID (from registration):');
                if (!currentUser) return;
            }
            
            try {
                showStatus('Starting authentication...', 'info');
                
                const optionsResp = await fetch('/api/begin_authentication', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({user_id: currentUser})
                });
                
                if (!optionsResp.ok) throw new Error('Authentication setup failed');
                
                const options = await optionsResp.json();
                showStatus('Please complete biometric authentication...', 'info');
                
                const assertion = await SimpleWebAuthnBrowser.startAuthentication(options);
                
                const verifyResp = await fetch('/api/verify_authentication', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        credential: assertion,
                        user_id: currentUser,
                        challenge_id: options.challenge_id
                    })
                });
                
                const result = await verifyResp.json();
                
                if (result.verified) {
                    showStatus('✅ Authentication successful!', 'success');
                } else {
                    showStatus('❌ Authentication failed: ' + (result.error || 'Unknown error'), 'error');
                }
            } catch (error) {
                let errorMsg = error.message;
                if (errorMsg.includes('not supported on sites with TLS certificate errors')) {
                    errorMsg = 'WebAuthn blocked due to certificate error. Please use HTTP: http://192.168.29.237:5001';
                }
                showStatus('❌ Authentication error: ' + errorMsg, 'error');
            }
        }
        
        async function generateQR() {
            try {
                const response = await fetch('/api/generate_qr', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'}
                });
                
                const result = await response.json();
                
                if (result.qr_image) {
                    document.getElementById('qr-code').innerHTML = `<img src="${result.qr_image}" alt="QR Code" style="max-width: 200px;">`;
                    document.getElementById('qr-section').style.display = 'block';
                    
                    // Listen for authentication completion
                    socket.emit('join_session', {session_id: result.session_id});
                    showStatus('QR code generated. Waiting for mobile authentication...', 'info');
                } else {
                    showStatus('❌ Failed to generate QR code', 'error');
                }
            } catch (error) {
                showStatus('❌ QR generation error: ' + error.message, 'error');
            }
        }
        
        async function scanQR() {
            const sessionId = prompt('Enter session ID from QR code (for testing):');
            if (!sessionId || !currentUser) {
                showStatus('❌ Need session ID and user ID', 'error');
                return;
            }
            
            try {
                const response = await fetch('/api/authenticate_qr', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        session_id: sessionId,
                        user_id: currentUser
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showStatus('✅ QR authentication successful!', 'success');
                } else {
                    showStatus('❌ QR authentication failed: ' + (result.error || 'Unknown error'), 'error');
                }
            } catch (error) {
                showStatus('❌ QR authentication error: ' + error.message, 'error');
            }
        }
        
        // Socket.IO event handlers
        socket.on('session_authenticated', function(data) {
            showStatus('✅ Cross-device authentication successful!', 'success');
            document.getElementById('qr-section').style.display = 'none';
        });
        
        socket.on('session_expired', function(data) {
            showStatus('❌ Session expired. Please generate a new QR code.', 'error');
            document.getElementById('qr-section').style.display = 'none';
        });
        
        // Display current user if available
        if (currentUser) {
            showStatus(`Current User: ${currentUser}`, 'info');
        }
    </script>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

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
        db.session.add(user)
        db.session.flush()  # Get the user ID
        
        # Generate registration options
        options = generate_registration_options(
            rp_id=Config.get_webauthn_rp_id(),
            rp_name=config_instance.WEBAUTHN_RP_NAME,
            user_id=user.user_id.encode('utf-8'),
            user_name=user.user_name,
            user_display_name=user.display_name,
            supported_pub_key_algs=[
                -7,  # ES256
                -257,  # RS256
            ],
            attestation="none",  # Fix: Set 'none' attestation to bypass attestationObject requirement
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
        credential = data.get('credential')
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
        
        # Fix base64 padding
        def add_padding(b64_str):
            return b64_str + '=' * ((4 - len(b64_str) % 4) % 4)
        
        response = credential.get('response', {})
        
        # Log the credential structure for debugging
        app.logger.info(f"Credential keys: {list(credential.keys())}")
        app.logger.info(f"Response keys: {list(response.keys())}")
        
        if 'clientDataJSON' in response:
            client_data = add_padding(response['clientDataJSON'])
            response['clientDataJSON'] = base64.urlsafe_b64decode(client_data).decode('utf-8')
        if 'attestationObject' in response:
            att_obj = add_padding(response['attestationObject'])
            response['attestationObject'] = base64.urlsafe_b64decode(att_obj)
        else:
            app.logger.warning("attestationObject not found in response - this is expected with attestation='none'")
        if 'id' in credential:
            credential['id'] = add_padding(credential['id'])
        
        # Verify
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge.challenge,
            expected_origin=config_instance.WEBAUTHN_RP_ORIGIN,
            expected_rp_id=Config.get_webauthn_rp_id(),
            require_user_verification=True
        )
        
        if verification.verified:
            cred = Credential(
                user_id=user.id,
                credential_id=verification.credential_id,
                public_key=verification.credential_public_key,
                sign_count=verification.sign_count,
                transports=credential.get('response', {}).get('transports', [])
            )
            db.session.add(cred)
            
            challenge.used = True
            db.session.commit()
            
            app.logger.info(f"Registration success for user {user.user_id}")
            return jsonify({
                'verified': True,
                'user_id': user.user_id,
                'credential_id': base64.urlsafe_b64encode(verification.credential_id).decode('utf-8')
            })
        else:
            app.logger.error(f"Verification failed for {user.user_id}: NOT_FOUND")
            return jsonify({'verified': False, 'error': 'Verification failed - NOT_FOUND'})
            
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Registration error: {str(e)}")
        return jsonify({'verified': False, 'error': str(e)})

@app.route('/api/begin_authentication', methods=['POST'])
@require_rate_limit(limit=20, window=300)  # 20 auth attempts per 5 minutes
@require_webauthn_security()
def begin_authentication():
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        
        # Find user and their credentials
        user = User.query.filter_by(user_id=user_id).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        credentials = user.credentials
        if not credentials:
            return jsonify({'error': 'No credentials found for user'}), 404
        
        # Create allowed credentials list
        allowed_credentials = []
        for cred in credentials:
            allowed_credentials.append(PublicKeyCredentialDescriptor(
                id=cred.credential_id,
                type="public-key",
                transports=cred.transports or []
            ))
        
        # Generate authentication options
        options = generate_authentication_options(
            rp_id=Config.get_webauthn_rp_id(),
            allow_credentials=allowed_credentials,
            user_verification="required",  # This parameter name is correct for authentication
            timeout=60000
        )
        
        # Store the challenge
        challenge = Challenge.create_challenge(
            challenge_bytes=options.challenge,
            challenge_type='authentication',
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

@app.route('/api/verify_authentication', methods=['POST'])
@require_rate_limit(limit=20, window=300)  # 20 verifications per 5 minutes
@require_webauthn_security()
def verify_authentication():
    try:
        data = request.get_json()
        credential = data.get('credential')
        user_id = data.get('user_id')
        challenge_id = data.get('challenge_id')
        
        # Get and validate challenge
        challenge = Challenge.query.filter_by(id=challenge_id).first()
        if not challenge or not challenge.is_valid():
            app.logger.error(f"Invalid challenge ID {challenge_id}")
            return jsonify({'verified': False, 'error': 'Invalid or expired challenge'})
        
        # Get user and credential
        user = User.query.filter_by(user_id=user_id).first()
        if not user:
            app.logger.error(f"User not found for challenge {challenge_id}")
            return jsonify({'verified': False, 'error': 'User not found'})
        
        # Fix base64 padding
        def add_padding(b64_str):
            return b64_str + '=' * ((4 - len(b64_str) % 4) % 4)
        
        credential_id = base64.urlsafe_b64decode(add_padding(credential.get('id', '')))
        db_credential = Credential.query.filter_by(credential_id=credential_id).first()
        if not db_credential:
            app.logger.error(f"Credential not found for user {user.user_id}")
            return jsonify({'verified': False, 'error': 'Credential not found'})
        
        response = credential.get('response', {})
        if 'clientDataJSON' in response:
            client_data = add_padding(response['clientDataJSON'])
            response['clientDataJSON'] = base64.urlsafe_b64decode(client_data).decode('utf-8')
        if 'authenticatorData' in response:
            auth_data = add_padding(response['authenticatorData'])
            response['authenticatorData'] = base64.urlsafe_b64decode(auth_data)
        if 'signature' in response:
            signature = add_padding(response['signature'])
            response['signature'] = base64.urlsafe_b64decode(signature)
        
        # Verify
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge.challenge,
            expected_origin=config_instance.WEBAUTHN_RP_ORIGIN,
            expected_rp_id=Config.get_webauthn_rp_id(),
            credential_public_key=db_credential.public_key,
            credential_current_sign_count=db_credential.sign_count,
            require_user_verification=True
        )
        
        if verification.verified:
            db_credential.sign_count = verification.new_sign_count
            db_credential.last_used = datetime.utcnow()
            user.last_login = datetime.utcnow()
            challenge.used = True
            db.session.commit()
            
            app.logger.info(f"Authentication success for user {user.user_id}")
            return jsonify({
                'verified': True,
                'user_id': user.user_id,
                'last_login': user.last_login.isoformat()
            })
        else:
            app.logger.error(f"Authentication failed for {user.user_id}: NOT_FOUND")
            return jsonify({'verified': False, 'error': 'Authentication failed - NOT_FOUND'})
            
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Authentication error: {str(e)}")
        return jsonify({'verified': False, 'error': str(e)})

@app.route('/api/generate_qr', methods=['POST'])
def generate_qr():
    try:
        # Create a new cross-device session
        session_data = {
            'session_id': secrets.token_urlsafe(32),
            'origin': config_instance.WEBAUTHN_RP_ORIGIN,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        session_obj = CrossDeviceSession.create_session(
            qr_data=json.dumps(session_data),
            desktop_session_id=session.get('session_id')
        )
        db.session.add(session_obj)
        db.session.commit()
        
        # Generate QR code
        qr_data = f"{config_instance.WEBAUTHN_RP_ORIGIN}/qr/{session_obj.session_id}"
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_str = base64.b64encode(img_buffer.getvalue()).decode()
        
        return jsonify({
            'session_id': session_obj.session_id,
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
        user_id = data.get('user_id')
        
        # Find the session
        session_obj = CrossDeviceSession.query.filter_by(session_id=session_id).first()
        if not session_obj or not session_obj.is_valid():
            return jsonify({'success': False, 'error': 'Invalid or expired session'})
        
        # Find the user
        user = User.query.filter_by(user_id=user_id).first()
        if not user:
            return jsonify({'success': False, 'error': 'User not found'})
        
        # Authenticate the session
        session_obj.authenticate(user.user_id)
        db.session.commit()
        
        # Emit success to desktop
        socketio.emit('session_authenticated', {
            'session_id': session_id,
            'user_id': user.user_id
        }, room=session_id)
        
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/qr/<session_id>')
def qr_redirect(session_id):
    """Handle QR code scans from mobile devices"""
    session_obj = CrossDeviceSession.query.filter_by(session_id=session_id).first()
    if not session_obj or not session_obj.is_valid():
        return "Session expired or invalid", 400
    
    # Redirect to mobile auth page
    return render_template_string('''
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Veridium Mobile Auth</title>
        <style>
            body { font-family: sans-serif; padding: 20px; text-align: center; }
            button { padding: 15px 30px; font-size: 18px; background: #007AFF; color: white; border: none; border-radius: 8px; }
        </style>
    </head>
    <body>
        <h2>🔐 Veridium Authentication</h2>
        <p>Complete authentication on this mobile device</p>
        <button onclick="authenticate()">Authenticate</button>
        <div id="status"></div>
        <script>
            function authenticate() {
                // This would trigger the mobile biometric authentication
                // For now, simulate with user input
                const userId = prompt('Enter your User ID:');
                if (userId) {
                    fetch('/api/authenticate_qr', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            session_id: '{{ session_id }}',
                            user_id: userId
                        })
                    })
                    .then(r => r.json())
                    .then(data => {
                        if (data.success) {
                            document.getElementById('status').innerHTML = '<p style="color: green;">✅ Authentication successful!</p>';
                        } else {
                            document.getElementById('status').innerHTML = '<p style="color: red;">❌ Authentication failed</p>';
                        }
                    });
                }
            }
        </script>
    </body>
    </html>
    ''', session_id=session_id)

@socketio.on('join_session')
def handle_join_session(data):
    session_id = data['session_id']
    join_room(session_id)
    emit('joined', {'session_id': session_id})

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000) 
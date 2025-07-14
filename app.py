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
from datetime import datetime
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
        
        <!-- Camera Modal Overlay -->
        <div id="qrModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 1000; flex-direction: column; align-items: center; justify-content: center;">
            <video id="qrVideo" style="width: 80%; max-width: 400px; background: black;"></video>
            <canvas id="qrCanvas" style="display: none;"></canvas>
            <button onclick="closeQRModal()" style="margin-top: 10px; padding: 10px;">Cancel</button>
            <p id="qrStatus" style="color: white; margin-top: 10px;"></p>
        </div>
    </div>

    <script src="https://unpkg.com/@simplewebauthn/browser@9/dist/bundle/index.umd.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.min.js"></script>
    <script>
        // Explicitly set withCredentials and origin for Socket.IO
        const socket = io({
            withCredentials: true,
            // If you want to force the origin, uncomment and set below:
            // "extraHeaders": { "Origin": window.location.origin }
        });
        let currentUser = localStorage.getItem('veridium_username');
        
        // QR Scanner variables
        let videoElement, canvasElement, canvasContext, qrModal, qrStatus;
        let scanning = false;
        let stream = null;
        
        function showStatus(message, type = 'info') {
            const statusDiv = document.getElementById('status');
            statusDiv.innerHTML = `<div class="${type}">${message}</div>`;
            setTimeout(() => statusDiv.innerHTML = '', 5000);
        }
        
        // Initialize QR Scanner elements
        function initQRScanner() {
            qrModal = document.getElementById('qrModal');
            qrStatus = document.getElementById('qrStatus');
            videoElement = document.getElementById('qrVideo');
            canvasElement = document.getElementById('qrCanvas');
            canvasContext = canvasElement.getContext('2d');
        }
        
        // Debug logging functions for authentication tracking
        async function debugBeginAuthentication(payload) {
            const res = await fetch("/api/begin_authentication", {
                method: "POST",
                credentials: "include",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify(payload),
            });
            const text = await res.text();
            // Dump status, body, and current cookies into the DOM
            document.body.insertAdjacentHTML("beforeend", `
                <div style="padding:10px; border:2px solid orange; margin:10px; background: #fff3e6;">
                    <strong>BEGIN_AUTH:</strong><br>
                    status = ${res.status}<br>
                    request = <pre>${JSON.stringify(payload, null, 2)}</pre>
                    response = <pre>${text}</pre>
                    document.cookie = "${document.cookie}"
                </div>
            `);
            return JSON.parse(text);
        }

        async function debugVerifyAuthentication(credential, challengeId) {
            const res = await fetch("/api/verify_authentication", {
                method: "POST",
                credentials: "include",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({credential, challenge_id: challengeId}),
            });
            const text = await res.text();
            document.body.insertAdjacentHTML("beforeend", `
                <div style="padding:10px; border:2px solid green; margin:10px; background: #e6ffe6;">
                    <strong>VERIFY_AUTH:</strong><br>
                    status = ${res.status}<br>
                    challenge_id = ${challengeId}<br>
                    response = <pre>${text}</pre>
                    document.cookie = "${document.cookie}"
                </div>
            `);
            return JSON.parse(text);
        }
        
        async function register() {
            try {
                showStatus('Starting registration...', 'info');
                
                const res = await fetch("/api/begin_registration", {
                    method: "POST",
                    credentials: "include",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({
                    username: 'veridium_user_' + Date.now(),
                    displayName: 'Veridium User'
                    }),
                });
                
                if (!res.ok) {
                    const errorText = await res.text();
                    showStatus(`❌ Registration failed: ${errorText || 'Unknown error'}`, 'error');
                    console.error('Backend error:', errorText);
                    return;
                }
                
                const options = await res.json();
                showStatus('Please complete biometric authentication...', 'info');
                
                const credential = await SimpleWebAuthnBrowser.startRegistration(options);
                
                const verifyRes = await fetch("/api/verify_registration", {
                    method: "POST",
                    credentials: "include",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({credential, challenge_id: options.challenge_id}),
                });
                
                const result = await verifyRes.json();
                
                if (result.verified) {
                    // Store user_name instead of user_id for better UX
                    currentUser = result.user_name;
                    localStorage.setItem('veridium_username', currentUser);
                    // Clean up old storage
                    localStorage.removeItem('veridium_user_id');
                    console.log('Registered and stored username:', currentUser);
                    showStatus(`✅ Registration successful! Username: ${result.user_name}`, 'success');
                    
                    // Debug: Show registration details
                    document.body.insertAdjacentHTML("beforeend", `
                        <div style="padding:10px; border:2px solid green; margin:10px; background: #e6ffe6;">
                            <strong>REGISTRATION SUCCESS:</strong><br>
                            user_name: ${result.user_name}<br>
                            user_id: ${result.user_id}<br>
                            credential_id: ${result.credential_id}<br>
                            Stored in localStorage: ${localStorage.getItem('veridium_username')}
                        </div>
                    `);
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
            // Try to get stored username first
            let username = localStorage.getItem('veridium_username');
            
            // Handle legacy stored user_id
            const old_user_id = localStorage.getItem('veridium_user_id');
            if (old_user_id && !username) {
                // Migration: clean up old storage and prompt for re-registration
                localStorage.removeItem('veridium_user_id');
                showStatus('⚠️ Please re-register for improved login experience', 'error');
                return;
            }
            
            if (!username) {
                username = prompt('Enter your username (from registration):');
                if (!username) return;
            }
            
            currentUser = username;
            
            try {
                showStatus('Starting authentication...', 'info');
                
                // Use debug function for begin_authentication
                const options = await debugBeginAuthentication({username: currentUser});
                
                if (!options || options.error) {
                    showStatus(`❌ Authentication setup failed: ${options?.error || 'Unknown error'}`, 'error');
                    return;
                }
                
                showStatus('Please complete biometric authentication...', 'info');
                
                const assertion = await SimpleWebAuthnBrowser.startAuthentication(options);
                
                // Use debug function for verify_authentication
                const result = await debugVerifyAuthentication(assertion, options.challenge_id);
                
                if (result.verified) {
                    showStatus('✅ Authentication successful!', 'success');
                } else {
                    showStatus('❌ Authentication failed: ' + (result.error || 'Unknown error'), 'error');
                }
            } catch (error) {
                console.error('Auth setup failed details:', error.message, error.stack);
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
                    credentials: 'include', // <-- send/receive cookies
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
            if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
                showStatus('❌ Camera not supported in this browser', 'error');
                return;
            }

            if (!currentUser) {
                showStatus('❌ Need username', 'error');
                return;
            }

            // Show modal and start camera
            qrModal.style.display = 'flex';
            qrStatus.textContent = 'Opening camera...';

            try {
                stream = await navigator.mediaDevices.getUserMedia({
                    video: { facingMode: 'environment' }  // Rear camera on mobile
                });
                videoElement.srcObject = stream;
                await videoElement.play();  // Start playback

                // Set canvas size to match video
                canvasElement.width = videoElement.videoWidth;
                canvasElement.height = videoElement.videoHeight;

                scanning = true;
                qrStatus.textContent = 'Scanning QR code...';
                requestAnimationFrame(scanFrame);
            } catch (err) {
                qrStatus.textContent = '❌ Camera access denied or error: ' + err.message;
                console.error('getUserMedia error:', err);
            }
        }
        
        function scanFrame() {
            if (!scanning) return;

            // Draw current video frame to canvas
            canvasContext.drawImage(videoElement, 0, 0, canvasElement.width, canvasElement.height);
            const imageData = canvasContext.getImageData(0, 0, canvasElement.width, canvasElement.height);

            // Scan with jsQR
            const code = jsQR(imageData.data, imageData.width, imageData.height);

            if (code) {
                const sessionId = code.data;  // Extract session ID (assume QR is plain string; parse JSON if needed)
                qrStatus.textContent = '✅ QR detected: ' + sessionId;
                stopScanning();
                // Proceed with auth logic
                handleCrossDeviceAuth(sessionId);
            } else {
                requestAnimationFrame(scanFrame);  // Continue scanning
            }
        }

        function stopScanning() {
            scanning = false;
            if (stream) {
                stream.getTracks().forEach(track => track.stop());  // Release camera
                stream = null;
            }
            qrModal.style.display = 'none';
        }

        function closeQRModal() {
            stopScanning();
            showStatus('Scan cancelled', 'info');
        }

        async function handleCrossDeviceAuth(sessionId) {
            try {
                const response = await fetch('/api/authenticate_qr', {
                    method: 'POST',
                    credentials: 'include',
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
        
        // Initialize QR Scanner on page load
        initQRScanner();
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
                # Handle transports field - ensure it's a list with proper logging
                transports = cred.transports if cred.transports else []
                app.logger.info(f"Raw transports for cred_id {cred.credential_id.hex()[:8]}: {transports} (type: {type(transports)})")

                # First, normalize to list if str (as suggested by Grok)
                if isinstance(transports, str):
                    try:
                        transports = json.loads(transports)
                        app.logger.warning(f"Converted string transports to list for cred_id {cred.credential_id.hex()[:8]}: {transports}")
                    except json.JSONDecodeError:
                        app.logger.warning(f"Invalid transports JSON for cred_id {cred.credential_id.hex()[:8]} - treating as empty")
                        transports = []

                if not isinstance(transports, list):
                    app.logger.warning(f"Transports not a list for cred_id {cred.credential_id.hex()[:8]} - treating as empty")
                    transports = []

                # Define a mapping for all supported transport types
                TRANSPORT_MAP = {
                    "usb": AuthenticatorTransport.USB,
                    "nfc": AuthenticatorTransport.NFC,
                    "ble": AuthenticatorTransport.BLE,
                    "internal": AuthenticatorTransport.INTERNAL,
                    "cable": AuthenticatorTransport.CABLE,
                    "hybrid": AuthenticatorTransport.HYBRID,
                }

                # Build enums (as suggested by Grok)
                transport_enums = []
                for transport_item in transports:
                    if isinstance(transport_item, str):
                        transport_enum = TRANSPORT_MAP.get(transport_item.lower())
                        if transport_enum:
                            transport_enums.append(transport_enum)
                            app.logger.info(f"Added transport enum: {transport_enum} for '{transport_item}'")
                        else:
                            app.logger.warning(f"Skipping unknown transport string: {transport_item}")
                    else:
                        app.logger.warning(f"Skipping non-string transport item: {type(transport_item)}")
                        # If it's already an enum (rare), append it
                        if isinstance(transport_item, AuthenticatorTransport):
                            transport_enums.append(transport_item)
                            app.logger.info(f"Added existing transport enum: {transport_item}")

                app.logger.info(f"Built transport_enums types: {[type(t).__name__ for t in transport_enums]}")  # Should be ['AuthenticatorTransport', ...]

                # For serialization - add safety (as suggested by Grok)
                transport_values = []
                for t in transport_enums:
                    if isinstance(t, AuthenticatorTransport):
                        transport_values.append(t.value)
                    else:
                        app.logger.error(f"Invalid type in transport_enums: {type(t)} - skipping")

                app.logger.info(f"Safe transport values: {transport_values}")

                # Type assertions for debugging
                assert isinstance(cred.credential_id, bytes), f"Invalid cred_id type: {type(cred.credential_id)}"

                try:
                    app.logger.info(f"About to create PublicKeyCredentialDescriptor with transport_enums: {transport_enums}")
                    app.logger.info(f"transport_enums types: {[type(t) for t in transport_enums] if transport_enums else 'None'}")

                    descriptor = PublicKeyCredentialDescriptor(
                        id=cred.credential_id,  # id is bytes
                        type=PublicKeyCredentialType.PUBLIC_KEY, # Use enum
                        transports=transport_enums if transport_enums else None  # Use enum values or None
                    )

                    allowed_credentials.append(descriptor)
                    app.logger.info(f"Successfully created PublicKeyCredentialDescriptor for cred_id {cred.credential_id.hex()[:8]}")
                except Exception as e:
                    app.logger.error(f"Error processing credential {cred.credential_id.hex()[:8]}: {e}")
                    continue
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
    import os
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_ENV') == 'development'
    socketio.run(app, debug=debug, host=host, port=port) 
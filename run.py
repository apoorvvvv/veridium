#!/usr/bin/env python3
"""
Veridium - Passwordless Biometric Authentication Service
Startup script for development and production deployment
"""

import os
import ssl
import sys
from app import app, socketio

def setup_environment():
    """Set up environment variables for development"""
    # Set default environment variables if not present
    if not os.environ.get('SECRET_KEY'):
        os.environ['SECRET_KEY'] = 'dev-secret-key-change-in-production'
    
    # Auto-detect deployment environment
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5001))
    
    # Set WebAuthn configuration based on environment
    if os.environ.get('RENDER'):  # Render deployment
        base_url = f"https://{os.environ.get('RENDER_EXTERNAL_HOSTNAME', 'your-app.onrender.com')}"
        os.environ.setdefault('WEBAUTHN_RP_ID', os.environ.get('RENDER_EXTERNAL_HOSTNAME', 'your-app.onrender.com'))
        os.environ.setdefault('WEBAUTHN_RP_ORIGIN', base_url)
        os.environ.setdefault('CORS_ORIGINS', base_url)
    else:  # Local development
        if not os.environ.get('WEBAUTHN_RP_ID'):
            os.environ['WEBAUTHN_RP_ID'] = '192.168.29.237'
        
        if not os.environ.get('WEBAUTHN_RP_ORIGIN'):
            os.environ['WEBAUTHN_RP_ORIGIN'] = 'http://192.168.29.237:5001'
        
        if not os.environ.get('CORS_ORIGINS'):
            os.environ['CORS_ORIGINS'] = 'http://192.168.29.237:5001,http://localhost:5001,http://127.0.0.1:5001'
    
    if not os.environ.get('WEBAUTHN_RP_NAME'):
        os.environ['WEBAUTHN_RP_NAME'] = 'Veridium'

def create_ssl_context():
    """Create SSL context for HTTPS development server"""
    # Force HTTP mode for development to avoid WebAuthn issues
    # Render handles SSL automatically
    if os.environ.get('RENDER'):
        print("Running on Render - SSL handled automatically")
        return None
    else:
        print("Running in HTTP mode for development (WebAuthn compatibility)")
        return None

def main():
    """Main function to start the Veridium server"""
    print("🔐 Starting Veridium - Passwordless Biometric Authentication")
    print("=" * 60)
    
    # Setup environment
    setup_environment()
    
    # Configuration
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    # SSL context for HTTPS
    ssl_context = create_ssl_context()
    
    print(f"Host: {host}")
    print(f"Port: {port}")
    print(f"Debug Mode: {debug}")
    print(f"SSL: {'Enabled' if ssl_context else 'Disabled'}")
    print(f"WebAuthn RP ID: {os.environ.get('WEBAUTHN_RP_ID')}")
    print(f"WebAuthn Origin: {os.environ.get('WEBAUTHN_RP_ORIGIN')}")
    print("=" * 60)
    
    if ssl_context:
        print(f"🚀 Veridium is running at https://{host}:{port}")
        print("📱 Open in mobile Safari/Chrome for biometric authentication")
    else:
        print(f"🚀 Veridium is running at http://{host}:{port}")
        print("⚠️  HTTPS required for WebAuthn in production")
    
    print("\n🔑 Features:")
    print("• Passwordless biometric authentication")
    print("• Face ID, Touch ID, Fingerprint support")
    print("• Cross-device QR code authentication")
    print("• Real-time session synchronization")
    print("• Anti-phishing protection")
    
    print("\n📋 API Endpoints:")
    print("• POST /api/begin_registration - Start biometric registration")
    print("• POST /api/verify_registration - Verify registration")
    print("• POST /api/begin_authentication - Start authentication")
    print("• POST /api/verify_authentication - Verify authentication")
    print("• POST /api/generate_qr - Generate QR for cross-device")
    print("• POST /api/authenticate_qr - Authenticate via QR scan")
    
    print("\n" + "=" * 60)
    
    try:
        # Start the server
        socketio.run(
            app,
            host=host,
            port=port,
            debug=debug,
            ssl_context=ssl_context,
            use_reloader=debug,
            log_output=True
        )
    except KeyboardInterrupt:
        print("\n👋 Shutting down Veridium...")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main() 
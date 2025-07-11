import os
from datetime import timedelta

class Config:
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///veridium.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # WebAuthn configuration - auto-configured based on environment
    WEBAUTHN_RP_ID = os.environ.get('WEBAUTHN_RP_ID') or 'localhost'
    WEBAUTHN_RP_NAME = os.environ.get('WEBAUTHN_RP_NAME') or 'Veridium'
    WEBAUTHN_RP_ORIGIN = os.environ.get('WEBAUTHN_RP_ORIGIN') or 'http://localhost:5001'
    
    # Cross-device session configuration
    SESSION_TIMEOUT = timedelta(minutes=5)  # QR code session timeout
    
    # Security headers
    FORCE_HTTPS = os.environ.get('FORCE_HTTPS', 'false').lower() == 'true'
    
    # Rate limiting (for future monetization)
    RATE_LIMIT_ENABLED = True
    RATE_LIMIT_DEFAULT = "100 per hour"
    
    # CORS settings
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*').split(',')
    
    # SocketIO configuration
    SOCKETIO_ASYNC_MODE = 'threading'
    
    @staticmethod
    def get_webauthn_rp_id():
        """Get the WebAuthn Relying Party ID, removing protocol and port if present"""
        rp_origin = Config.WEBAUTHN_RP_ORIGIN
        if rp_origin.startswith('https://'):
            rp_origin = rp_origin[8:]
        elif rp_origin.startswith('http://'):
            rp_origin = rp_origin[7:]
        
        # Remove port if present
        if ':' in rp_origin:
            rp_origin = rp_origin.split(':')[0]
            
        return rp_origin 
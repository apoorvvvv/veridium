import os
from datetime import timedelta

class Config:
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///veridium.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # WebAuthn configuration - dynamically loaded from environment
    @property
    def WEBAUTHN_RP_ID(self):
        return os.environ.get('WEBAUTHN_RP_ID') or 'localhost'
    
    @property
    def WEBAUTHN_RP_NAME(self):
        return os.environ.get('WEBAUTHN_RP_NAME') or 'Veridium'
    
    @property  
    def WEBAUTHN_RP_ORIGIN(self):
        return os.environ.get('WEBAUTHN_RP_ORIGIN') or 'http://localhost:5001'
    
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
    
    @classmethod
    def get_webauthn_rp_id(cls):
        """Get the WebAuthn Relying Party ID, removing protocol and port if present"""
        # Create an instance to access properties
        instance = cls()
        rp_origin = instance.WEBAUTHN_RP_ORIGIN
        if rp_origin.startswith('https://'):
            rp_origin = rp_origin[8:]
        elif rp_origin.startswith('http://'):
            rp_origin = rp_origin[7:]
        
        # Remove port if present
        if ':' in rp_origin:
            rp_origin = rp_origin.split(':')[0]
            
        return rp_origin 
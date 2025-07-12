import os
from datetime import timedelta

class Config:
    def __init__(self):
        # Get host and port from environment
        self.HOST = os.environ.get('HOST', 'localhost')
        self.PORT = os.environ.get('PORT', '5001')
        
        # Calculate CORS origins
        origins = os.environ.get('CORS_ORIGINS', '').split(',')
        if origins == ['']:  # If CORS_ORIGINS is empty or just whitespace
            origins = []
        
        # Always include the current server origin
        current_origin = self.WEBAUTHN_RP_ORIGIN
        if current_origin not in origins:
            origins.append(current_origin)
        
        # For development, also include localhost variants
        if self.HOST != 'localhost':
            localhost_origins = [
                f"http://localhost:{self.PORT}",
                f"https://localhost:{self.PORT}"
            ]
            for origin in localhost_origins:
                if origin not in origins:
                    origins.append(origin)
        
        self.CORS_ORIGINS = origins
    
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///veridium.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # WebAuthn configuration - dynamically loaded from environment
    @property
    def WEBAUTHN_RP_ID(self):
        # Use HOST environment variable if set, otherwise fallback to localhost
        return self.HOST
    
    @property
    def WEBAUTHN_RP_NAME(self):
        return os.environ.get('WEBAUTHN_RP_NAME') or 'Veridium'
    
    @property  
    def WEBAUTHN_RP_ORIGIN(self):
        # Build origin from HOST and PORT environment variables
        protocol = 'https' if os.environ.get('FORCE_HTTPS', 'false').lower() == 'true' else 'http'
        return f"{protocol}://{self.HOST}:{self.PORT}"
    
    # Cross-device session configuration
    SESSION_TIMEOUT = timedelta(minutes=5)  # QR code session timeout
    
    # Security headers
    FORCE_HTTPS = os.environ.get('FORCE_HTTPS', 'false').lower() == 'true'
    
    # Rate limiting (for future monetization)
    RATE_LIMIT_ENABLED = True
    RATE_LIMIT_DEFAULT = "100 per hour"
    
    # SocketIO configuration
    SOCKETIO_ASYNC_MODE = os.environ.get('SOCKETIO_ASYNC_MODE', 'eventlet')
    
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
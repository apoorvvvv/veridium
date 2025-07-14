from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import uuid
import base64
import secrets

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(255), unique=True, nullable=False)  # WebAuthn user ID
    user_name = db.Column(db.String(255), nullable=False, default='veridium_user')
    display_name = db.Column(db.String(255), nullable=False, default='Veridium User')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationship to credentials
    credentials = db.relationship('Credential', back_populates='user', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.user_name}>'
    
    @classmethod
    def create_user(cls, user_name=None, display_name=None):
        """Create a new user with a unique WebAuthn user ID"""
        user_id_bytes = secrets.token_bytes(64)  # 64 random bytes for WebAuthn 2.1.0
        user_id_str = base64.urlsafe_b64encode(user_id_bytes).decode('utf-8').rstrip('=')  # base64url, no padding

        user = cls(
            user_id=user_id_str,
            user_name=user_name or 'veridium_user',
            display_name=display_name or 'Veridium User'
        )
        return user

class Credential(db.Model):
    __tablename__ = 'credentials'
    
    id = db.Column(db.String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(255), db.ForeignKey('users.id'), nullable=False)
    credential_id = db.Column(db.LargeBinary, nullable=False, unique=True)  # WebAuthn credential ID
    public_key = db.Column(db.LargeBinary, nullable=False)  # Public key bytes
    sign_count = db.Column(db.Integer, default=0)
    transports = db.Column(db.JSON)  # Authenticator transports
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime)
    
    # Relationship to user
    user = db.relationship('User', back_populates='credentials')
    
    def __repr__(self):
        return f'<Credential {self.credential_id.hex()[:8]}...>'
    
    @property
    def credential_id_b64(self):
        """Return credential ID as base64 string"""
        return base64.urlsafe_b64encode(self.credential_id).decode('utf-8')

class Challenge(db.Model):
    __tablename__ = 'challenges'
    
    id = db.Column(db.String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    challenge = db.Column(db.LargeBinary, nullable=False)
    challenge_type = db.Column(db.String(50), nullable=False)  # 'registration' or 'authentication'
    user_id = db.Column(db.String(255), nullable=True)  # For authentication challenges
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<Challenge {self.challenge_type} expires {self.expires_at}>'
    
    @classmethod
    def create_challenge(cls, challenge_bytes, challenge_type, user_id=None, expires_in_minutes=5):
        """Create a new challenge with expiration"""
        challenge = cls(
            challenge=challenge_bytes,
            challenge_type=challenge_type,
            user_id=user_id,
            expires_at=datetime.utcnow() + timedelta(minutes=expires_in_minutes)
        )
        return challenge
    
    def is_expired(self):
        """Check if challenge has expired"""
        return datetime.utcnow() > self.expires_at
    
    def is_valid(self):
        """Check if challenge is valid (not used and not expired)"""
        return not self.used and not self.is_expired()

class CrossDeviceSession(db.Model):
    __tablename__ = 'cross_device_sessions'
    
    id = db.Column(db.String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = db.Column(db.String(255), unique=True, nullable=False)
    qr_code_data = db.Column(db.Text, nullable=False)  # JSON data for QR code
    desktop_session_id = db.Column(db.String(255), nullable=True)  # Desktop browser session
    mobile_user_id = db.Column(db.String(255), nullable=True)  # User who authenticated on mobile
    status = db.Column(db.String(50), default='pending')  # pending, authenticated, expired
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    authenticated_at = db.Column(db.DateTime, nullable=True)
    
    def __repr__(self):
        return f'<CrossDeviceSession {self.session_id} status={self.status}>'
    
    @classmethod
    def create_session(cls, qr_data, desktop_session_id=None, expires_in_minutes=5):
        """Create a new cross-device session"""
        session_id = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8')
        
        session = cls(
            session_id=session_id,
            qr_code_data=qr_data,
            desktop_session_id=desktop_session_id,
            expires_at=datetime.utcnow() + timedelta(minutes=expires_in_minutes)
        )
        return session
    
    def is_expired(self):
        """Check if session has expired"""
        return datetime.utcnow() > self.expires_at
    
    def is_valid(self):
        """Check if session is valid (not expired)"""
        return not self.is_expired()
    
    def authenticate(self, user_id):
        """Mark session as authenticated"""
        self.mobile_user_id = user_id
        self.status = 'authenticated'
        self.authenticated_at = datetime.utcnow()

class APIKey(db.Model):
    __tablename__ = 'api_keys'
    
    id = db.Column(db.String(255), primary_key=True, default=lambda: str(uuid.uuid4()))
    key = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.String(255), nullable=True)  # Optional association with user
    rate_limit = db.Column(db.Integer, default=100)  # Requests per hour
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime)
    active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<APIKey {self.name}>'
    
    @classmethod
    def create_api_key(cls, name, user_id=None, rate_limit=100):
        """Create a new API key"""
        key = 'vr_' + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8')
        
        api_key = cls(
            key=key,
            name=name,
            user_id=user_id,
            rate_limit=rate_limit
        )
        return api_key 
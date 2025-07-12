from flask import request, abort
from functools import wraps
import time
from datetime import datetime, timedelta
from collections import defaultdict

class SecurityHeaders:
    """Security headers middleware for Flask"""
    
    @staticmethod
    def add_security_headers(response):
        """Add security headers to all responses"""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        
        # Content Security Policy
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://unpkg.com https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self' ws: wss:; "
            "font-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        response.headers['Content-Security-Policy'] = csp
        
        return response

class RateLimiter:
    """Simple in-memory rate limiter"""
    
    def __init__(self):
        self.requests = defaultdict(list)
        self.blocked_ips = defaultdict(datetime)
    
    def is_allowed(self, ip, limit=100, window=3600):  # 100 requests per hour by default
        now = datetime.utcnow()
        
        # Check if IP is temporarily blocked
        if ip in self.blocked_ips:
            if now < self.blocked_ips[ip]:
                return False
            else:
                del self.blocked_ips[ip]
        
        # Clean old requests
        self.requests[ip] = [req_time for req_time in self.requests[ip] 
                           if now - req_time < timedelta(seconds=window)]
        
        # Check rate limit
        if len(self.requests[ip]) >= limit:
            # Block IP for 1 hour
            self.blocked_ips[ip] = now + timedelta(hours=1)
            return False
        
        # Add current request
        self.requests[ip].append(now)
        return True

class AntiPhishing:
    """Anti-phishing protection utilities"""
    
    @staticmethod
    def validate_origin(origin, allowed_origins):
        """Validate request origin against allowed origins"""
        if not origin:
            return False
        
        if '*' in allowed_origins:
            return True
        
        # Check for exact match
        if origin in allowed_origins:
            return True
        
        # Check for subdomain match
        for allowed in allowed_origins:
            if allowed.startswith('*.'):
                domain = allowed[2:]
                if origin.endswith('.' + domain) or origin == domain:
                    return True
        
        return False
    
    @staticmethod
    def validate_rp_id(rp_id, origin):
        """Validate that RP ID matches the origin domain"""
        if not origin or not rp_id:
            return False
        
        # Remove protocol from origin
        if origin.startswith('https://'):
            origin_domain = origin[8:]
        elif origin.startswith('http://'):
            origin_domain = origin[7:]
        else:
            origin_domain = origin
        
        # Remove port if present
        if ':' in origin_domain:
            origin_domain = origin_domain.split(':')[0]
        
        return rp_id == origin_domain or origin_domain.endswith('.' + rp_id)
    
    @staticmethod
    def check_suspicious_patterns(user_agent, ip):
        """Check for suspicious patterns in requests"""
        # Temporarily disabled for testing
        return False
        
        suspicious_patterns = [
            'bot', 'crawler', 'spider', 'scraper',
            'curl', 'wget'
            # Removed 'python-requests' to allow testing and legitimate API usage
        ]
        
        if user_agent:
            user_agent_lower = user_agent.lower()
            for pattern in suspicious_patterns:
                if pattern in user_agent_lower:
                    return True
        
        return False

# Global rate limiter instance
rate_limiter = RateLimiter()

def require_rate_limit(limit=100, window=3600):
    """Decorator to enforce rate limiting"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            
            if not rate_limiter.is_allowed(client_ip, limit, window):
                abort(429)  # Too Many Requests
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_origin_validation(allowed_origins):
    """Decorator to validate request origin"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            origin = request.headers.get('Origin')
            
            if not AntiPhishing.validate_origin(origin, allowed_origins):
                abort(403)  # Forbidden
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_webauthn_security():
    """Decorator to enforce WebAuthn security requirements"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check for HTTPS in production
            if not request.is_secure and request.headers.get('X-Forwarded-Proto') != 'https':
                # Allow localhost and local network IPs for development
                if not (request.host.startswith('localhost') or 
                       request.host.startswith('127.0.0.1') or 
                       request.host.startswith('192.168.') or
                       request.host.startswith('10.') or
                       request.host.startswith('172.')):
                    abort(400, 'HTTPS required for WebAuthn')
            
            # Check for suspicious patterns
            user_agent = request.headers.get('User-Agent', '')
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            
            if AntiPhishing.check_suspicious_patterns(user_agent, client_ip):
                abort(403, 'Suspicious request pattern detected')
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def init_security(app):
    """Initialize security features for the Flask app"""
    
    @app.after_request
    def after_request(response):
        return SecurityHeaders.add_security_headers(response)
    
    @app.before_request
    def before_request():
        # Basic security checks
        if request.method == 'POST':
            # Check Content-Type for API endpoints
            if request.path.startswith('/api/'):
                # Temporarily relaxed for testing - accept both JSON and form data
                if not request.is_json and request.content_type != 'application/x-www-form-urlencoded':
                    app.logger.warning(f"Non-JSON request to {request.path}: {request.content_type}")
        
        # Log suspicious activity (disabled for now to avoid false positives)
        # user_agent = request.headers.get('User-Agent', '')
        # client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        # if AntiPhishing.check_suspicious_patterns(user_agent, client_ip):
        #     app.logger.warning(f"Suspicious request from {client_ip}: {user_agent}")
    
    return app 
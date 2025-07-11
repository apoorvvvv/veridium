import os

# Server socket
bind = f"0.0.0.0:{os.environ.get('PORT', 5001)}"
backlog = 2048

# Worker processes
workers = int(os.environ.get('WEB_CONCURRENCY', 4))
worker_class = "gevent"
worker_connections = 1000
timeout = 30
keepalive = 2

# Restart workers after this many requests, to help prevent memory leaks
max_requests = 1000
max_requests_jitter = 50

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Process naming
proc_name = 'veridium'

# Server mechanics
preload_app = True
daemon = False
pidfile = '/tmp/veridium.pid'
user = None
group = None
tmp_upload_dir = None

# SSL (disabled for Render as it handles SSL termination)
keyfile = None
certfile = None 
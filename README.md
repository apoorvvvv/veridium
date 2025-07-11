# 🔐 Veridium - Passwordless Biometric Authentication

A secure, passwordless authentication service that uses device-native biometrics (Face ID, Touch ID, fingerprint) for signup and login without requiring passwords, emails, or storing sensitive user data.

## ✨ Features

- **Passwordless Authentication**: No passwords, emails, or user data storage required
- **Biometric Security**: Uses WebAuthn (FIDO2) with mandatory biometric verification
- **Cross-Device Support**: QR code authentication for desktop via mobile
- **Real-time Sync**: WebSocket-based session synchronization
- **Anti-Phishing**: Built-in security measures and origin validation
- **Privacy-First**: Only stores public keys, biometrics stay on-device
- **Modern UI**: Beautiful, responsive interface with gradient design

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Modern browser with WebAuthn support:
  - **iOS**: Safari 14+ (for Face ID/Touch ID)
  - **Android**: Chrome 70+ (for fingerprint/face unlock)
  - **Desktop**: Chrome 67+, Firefox 60+, Edge 18+

### Installation

1. **Clone and Setup**:
   ```bash
   git clone <repository-url>
   cd veridium
   pip install -r requirements.txt
   ```

2. **Start the Server**:
   ```bash
   python run.py
   ```

3. **Access Veridium**:
   - Open `https://localhost:5000` in your browser
   - For mobile testing, use your device's IP address

### HTTPS Setup (Required for WebAuthn)

WebAuthn requires HTTPS in production. For development:

**Option 1: Self-signed certificates**
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

**Option 2: mkcert (recommended)**
```bash
# Install mkcert
brew install mkcert  # macOS
# or download from https://github.com/FiloSottile/mkcert

# Create local CA
mkcert -install

# Generate certificates
mkcert localhost 127.0.0.1 ::1
```

## 📱 Usage Guide

### Mobile Authentication (Primary Flow)

1. **Registration**:
   - Open Veridium on your mobile device
   - Tap "Sign Up with Biometrics"
   - Complete biometric authentication (Face ID/Touch ID/Fingerprint)
   - Save the generated User ID

2. **Login**:
   - Tap "Login with Biometrics"
   - Enter your User ID (or it will be remembered)
   - Complete biometric authentication

### Desktop Cross-Device Authentication

1. **Generate QR Code**:
   - Click "Generate QR for Login" on desktop
   - QR code appears with session ID

2. **Mobile Authentication**:
   - Scan QR code with your mobile device
   - Complete biometric authentication on mobile
   - Desktop session automatically authenticates

## 🔧 Configuration

### Environment Variables

Create a `.env` file or set environment variables:

```bash
# Required for production
SECRET_KEY=your-secret-key-here
WEBAUTHN_RP_ID=your-domain.com
WEBAUTHN_RP_NAME=Your App Name
WEBAUTHN_RP_ORIGIN=https://your-domain.com

# Database (optional, defaults to SQLite)
DATABASE_URL=sqlite:///veridium.db

# Security
CORS_ORIGINS=https://your-domain.com,https://app.your-domain.com
FORCE_HTTPS=true

# Rate limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_DEFAULT=100 per hour
```

### Development vs Production

**Development** (`run.py`):
- Defaults to `localhost:5000`
- Debug mode enabled
- Flexible CORS settings
- Auto-reload on changes

**Production** (deploy to Render/Heroku):
- HTTPS enforced
- Strict security headers
- Rate limiting enabled
- Environment-based configuration

## 🧪 Testing on Real Devices

### iOS Testing (Face ID/Touch ID)

1. **Setup**:
   - Ensure your Mac and iPhone are on the same network
   - Find your Mac's IP address: `ifconfig | grep inet`
   - Update `WEBAUTHN_RP_ORIGIN` to use your IP

2. **Test Registration**:
   - Open Safari on iPhone
   - Navigate to `https://YOUR_IP:5000`
   - Accept the self-signed certificate warning
   - Tap "Sign Up with Biometrics"
   - Face ID/Touch ID should prompt
   - Save the User ID displayed

3. **Test Login**:
   - Tap "Login with Biometrics"
   - Enter the User ID
   - Face ID/Touch ID should prompt again
   - Should show success message

### Android Testing (Fingerprint/Face Unlock)

1. **Setup**:
   - Enable Developer Options and USB Debugging
   - Use Chrome's remote debugging or find your computer's IP
   - Navigate to `https://YOUR_IP:5000`

2. **Test Authentication**:
   - Follow similar steps as iOS
   - Chrome will prompt for fingerprint/face unlock
   - Ensure biometric authentication is enabled on device

### Desktop Cross-Device Testing

1. **Setup Two Devices**:
   - Desktop: Open Veridium in browser
   - Mobile: Have Veridium open and registered user

2. **Test Flow**:
   - Desktop: Click "Generate QR for Login"
   - Mobile: Scan QR code or manually enter session ID
   - Mobile: Complete biometric authentication
   - Desktop: Should automatically show success

## 🛡️ Security Features

### WebAuthn Security
- **User Verification Required**: Forces biometric authentication
- **Public Key Cryptography**: No passwords stored
- **Challenge-Response**: Prevents replay attacks
- **Origin Validation**: Prevents phishing

### Additional Security
- **Rate Limiting**: Prevents brute force attacks
- **Security Headers**: CSP, HSTS, X-Frame-Options
- **HTTPS Enforcement**: Required for production
- **Session Timeout**: QR codes expire after 5 minutes
- **Suspicious Activity Detection**: Blocks automated requests

## 🔌 API Reference

### Registration

**POST** `/api/begin_registration`
```json
{
  "username": "user123",
  "displayName": "User Name"
}
```

**POST** `/api/verify_registration`
```json
{
  "credential": {...},
  "challenge_id": "challenge-uuid"
}
```

### Authentication

**POST** `/api/begin_authentication`
```json
{
  "user_id": "user-uuid"
}
```

**POST** `/api/verify_authentication`
```json
{
  "credential": {...},
  "user_id": "user-uuid",
  "challenge_id": "challenge-uuid"
}
```

### Cross-Device

**POST** `/api/generate_qr`
```json
{
  "session_id": "session-uuid",
  "qr_image": "data:image/png;base64,...",
  "expires_at": "2024-01-01T12:00:00Z"
}
```

**POST** `/api/authenticate_qr`
```json
{
  "session_id": "session-uuid",
  "user_id": "user-uuid"
}
```

## 🚢 Deployment

### Render (Recommended)

1. **Connect Repository**:
   - Connect your GitHub repository to Render
   - Choose "Web Service"

2. **Configuration**:
   ```bash
   # Build Command
   pip install -r requirements.txt
   
   # Start Command
   python run.py
   
   # Environment Variables
   WEBAUTHN_RP_ID=your-app.onrender.com
   WEBAUTHN_RP_NAME=Veridium
   WEBAUTHN_RP_ORIGIN=https://your-app.onrender.com
   SECRET_KEY=your-secret-key
   ```

### Heroku

1. **Create App**:
   ```bash
   heroku create your-app-name
   git push heroku main
   ```

2. **Set Environment Variables**:
   ```bash
   heroku config:set WEBAUTHN_RP_ID=your-app.herokuapp.com
   heroku config:set WEBAUTHN_RP_ORIGIN=https://your-app.herokuapp.com
   heroku config:set SECRET_KEY=your-secret-key
   ```

## 📊 Database Schema

### Users Table
- `id`: Primary key (UUID)
- `user_id`: WebAuthn user ID (base64)
- `user_name`: Display name
- `created_at`: Registration timestamp
- `last_login`: Last successful login

### Credentials Table
- `id`: Primary key (UUID)
- `user_id`: Foreign key to users
- `credential_id`: WebAuthn credential ID
- `public_key`: Public key bytes
- `sign_count`: Authentication counter
- `transports`: Supported transports

### Challenges Table
- `id`: Primary key (UUID)
- `challenge`: Challenge bytes
- `challenge_type`: 'registration' or 'authentication'
- `expires_at`: Expiration timestamp
- `used`: Whether challenge was used

## 🔮 Future Enhancements

### Planned Features
- [ ] Native mobile SDKs (iOS/Android)
- [ ] Enterprise SSO integration
- [ ] Bluetooth proximity verification
- [ ] Recovery mechanisms
- [ ] Multi-device management
- [ ] Analytics dashboard

### Monetization Hooks
- [ ] API key management
- [ ] Usage analytics
- [ ] Enterprise features
- [ ] Custom branding
- [ ] SLA guarantees

## 🐛 Troubleshooting

### Common Issues

**"User verification required but not performed"**
- Ensure biometric authentication is enabled on device
- Check that WebAuthn is supported in browser
- Verify HTTPS is being used

**"Invalid origin"**
- Check `WEBAUTHN_RP_ORIGIN` matches your domain
- Ensure no trailing slashes in origin
- Verify CORS settings allow your domain

**"Challenge expired"**
- Challenges expire after 5 minutes
- Ensure system clocks are synchronized
- Check for network delays

**Cross-device not working**
- Verify both devices are on same network
- Check WebSocket connection
- Ensure QR code hasn't expired

## 📝 License

MIT License - see LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📞 Support

For questions, issues, or contributions:
- Create an issue on GitHub
- Check the troubleshooting guide
- Review the API documentation

---

**Built with ❤️ using WebAuthn, Flask, and modern web standards.** 
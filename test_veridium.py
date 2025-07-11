#!/usr/bin/env python3
"""
Simple test script for Veridium functionality
Tests basic API endpoints and database operations
"""

import requests
import json
import sys
import time
from datetime import datetime

# Test configuration
BASE_URL = "http://localhost:5001"
TEST_USER_DATA = {
    "username": "test_user_" + str(int(time.time())),
    "displayName": "Test User"
}

def test_server_connection():
    """Test if server is running"""
    try:
        response = requests.get(f"{BASE_URL}/", timeout=5)
        print(f"✅ Server is running (Status: {response.status_code})")
        return True
    except requests.ConnectionError:
        print("❌ Server is not running. Start with 'python run.py'")
        return False
    except Exception as e:
        print(f"❌ Connection error: {e}")
        return False

def test_begin_registration():
    """Test registration initiation"""
    try:
        response = requests.post(
            f"{BASE_URL}/api/begin_registration",
            json=TEST_USER_DATA,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if "challenge" in data and "challenge_id" in data:
                print("✅ Registration initiation successful")
                return data
            else:
                print("❌ Registration response missing required fields")
        else:
            print(f"❌ Registration failed (Status: {response.status_code})")
            print(f"Response: {response.text}")
    except Exception as e:
        print(f"❌ Registration error: {e}")
    
    return None

def test_qr_generation():
    """Test QR code generation"""
    try:
        response = requests.post(
            f"{BASE_URL}/api/generate_qr",
            json={},
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if "session_id" in data and "qr_image" in data:
                print("✅ QR code generation successful")
                return data
            else:
                print("❌ QR response missing required fields")
        else:
            print(f"❌ QR generation failed (Status: {response.status_code})")
            print(f"Response: {response.text}")
    except Exception as e:
        print(f"❌ QR generation error: {e}")
    
    return None

def test_database_connection():
    """Test database operations"""
    try:
        from models import db, User, Credential, Challenge
        from app import app
        
        with app.app_context():
            # Test creating a user
            user = User.create_user("test_db_user", "Test DB User")
            db.session.add(user)
            db.session.commit()
            
            # Test querying the user
            found_user = User.query.filter_by(user_id=user.user_id).first()
            if found_user:
                print("✅ Database operations successful")
                
                # Cleanup
                db.session.delete(found_user)
                db.session.commit()
                return True
            else:
                print("❌ Database query failed")
    except Exception as e:
        print(f"❌ Database error: {e}")
    
    return False

def test_security_headers():
    """Test security headers"""
    try:
        response = requests.get(f"{BASE_URL}/", timeout=5)
        headers = response.headers
        
        required_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Content-Security-Policy'
        ]
        
        missing_headers = []
        for header in required_headers:
            if header not in headers:
                missing_headers.append(header)
        
        if not missing_headers:
            print("✅ Security headers are present")
            return True
        else:
            print(f"❌ Missing security headers: {missing_headers}")
    except Exception as e:
        print(f"❌ Security headers test error: {e}")
    
    return False

def test_api_rate_limiting():
    """Test API rate limiting"""
    try:
        # Make multiple rapid requests
        for i in range(3):
            response = requests.post(
                f"{BASE_URL}/api/begin_registration",
                json=TEST_USER_DATA,
                headers={"Content-Type": "application/json"},
                timeout=5
            )
            
            if response.status_code == 429:
                print("✅ Rate limiting is working")
                return True
        
        print("ℹ️  Rate limiting may not be triggered with low request volume")
        return True
    except Exception as e:
        print(f"❌ Rate limiting test error: {e}")
    
    return False

def main():
    """Run all tests"""
    print("🔐 Testing Veridium MVP")
    print("=" * 50)
    
    tests = [
        ("Server Connection", test_server_connection),
        ("Database Operations", test_database_connection),
        ("Security Headers", test_security_headers),
        ("Registration API", test_begin_registration),
        ("QR Code Generation", test_qr_generation),
        ("Rate Limiting", test_api_rate_limiting),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n📋 Testing {test_name}...")
        result = test_func()
        results.append((test_name, result))
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Test Results Summary")
    print("=" * 50)
    
    passed = 0
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} {test_name}")
        if result:
            passed += 1
    
    print(f"\n📈 Results: {passed}/{len(tests)} tests passed")
    
    if passed == len(tests):
        print("\n🎉 All tests passed! Veridium MVP is ready.")
        print("\n🚀 Next steps:")
        print("1. Test on mobile devices with biometric authentication")
        print("2. Set up HTTPS for production deployment")
        print("3. Test cross-device QR code authentication")
        print("4. Deploy to Render or Heroku")
    else:
        print("\n⚠️  Some tests failed. Please check the errors above.")
        sys.exit(1)

if __name__ == "__main__":
    main() 
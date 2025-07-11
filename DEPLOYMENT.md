# 🚀 Deploy Veridium to Render

## Why Deploy to Render?

✅ **Automatic HTTPS** - WebAuthn requires HTTPS in production  
✅ **No Network Issues** - Eliminates local IP/firewall problems  
✅ **Real Testing Environment** - Test on actual mobile devices anywhere  
✅ **Free Tier Available** - No cost for testing  

## Quick Deployment Steps

### 1. Push to GitHub
```bash
# Initialize git (if not already done)
git init
git add .
git commit -m "Initial Veridium deployment"

# Push to your GitHub repository
git remote add origin https://github.com/YOUR_USERNAME/veridium.git
git push -u origin main
```

### 2. Deploy on Render

1. **Go to [render.com](https://render.com)** and sign up/login
2. **Click "New +"** → **"Web Service"**
3. **Connect your GitHub repository**
4. **Configure the service:**
   - **Name:** `veridium`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `python run.py`
   - **Environment:** `Python 3`

### 3. Set Environment Variables

In Render dashboard, add these environment variables:

```
WEBAUTHN_RP_NAME=Veridium
SECRET_KEY=your-secret-key-here
FLASK_ENV=production
```

### 4. Deploy! 🎉

- Click **"Create Web Service"**
- Wait 3-5 minutes for deployment
- Your app will be available at: `https://veridium-XXXX.onrender.com`

## Testing Biometrics

1. **Open the URL on your mobile device**
2. **Click "Sign Up with Biometrics"**
3. **Follow Face ID/Touch ID/Fingerprint prompts**
4. **Success!** ✨

## Local Alternative (Simple Fix)

If you prefer to test locally first:

```bash
# Start with localhost (works better for WebAuthn)
WEBAUTHN_RP_ID=localhost WEBAUTHN_RP_ORIGIN=http://localhost:5001 HOST=localhost PORT=5001 ./venv/bin/python run.py
```

Then access at: `http://localhost:5001`

---

**Recommendation:** Deploy to Render for the most reliable WebAuthn testing experience! 
/**
 * SMS Proxy Server with Firebase Authentication
 * Handles Fast2SMS OTP sending and Firebase custom token generation
 */

const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');

// Import fetch for Node.js
let fetch;
(async () => {
  const { default: nodeFetch } = await import('node-fetch');
  fetch = nodeFetch;
})();

// Alternative: Use dynamic import in the function
async function getFetch() {
  if (!fetch) {
    const { default: nodeFetch } = await import('node-fetch');
    fetch = nodeFetch;
  }
  return fetch;
}

const app = express();
const PORT = 3001;

// Initialize Firebase Admin SDK
let firebaseAdminInitialized = false;
try {
  // Try to initialize with service account key
  const serviceAccount = require('./serviceAccountKey.json');
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
  firebaseAdminInitialized = true;
  console.log('✅ Firebase Admin SDK initialized with service account');
} catch (error) {
  console.error('❌ Firebase Admin SDK initialization failed:', error.message);
  console.log('⚠️  Firebase custom token generation will not work');
  console.log('💡 Create serviceAccountKey.json from Firebase Console for full functionality');
}

// In-memory OTP storage (in production, use Redis or database)
const otpStore = new Map();

// Rate limiting storage - track last OTP send time per phone number
const rateLimitStore = new Map();

// Enable CORS for all routes
app.use(cors());
app.use(express.json());

// Fast2SMS API key
const FAST2SMS_API_KEY = 'ETyZs2Dvu7Ia4mi6P80bhSjgNxXJKWt1cYrAHwlBpo5zGfF3d9pYtn4Deg9ky3r67fHjldFibNEQWKSI';

// OTP sending endpoint
app.post('/api/send-otp', async (req, res) => {
  try {
    const { phoneNumber } = req.body;

    if (!phoneNumber) {
      return res.status(400).json({
        success: false,
        error: 'Phone number is required',
        errorCode: 'MISSING_PHONE_NUMBER'
      });
    }

    // Format phone number
    const formattedPhone = phoneNumber.startsWith('+') ? phoneNumber : `+${phoneNumber}`;

    console.log(`📱 Sending OTP to: ${formattedPhone}`);

    // Check rate limiting - prevent spam detection
    const now = Date.now();
    const lastSentTime = rateLimitStore.get(formattedPhone);
    const RATE_LIMIT_MINUTES = 2; // Minimum 2 minutes between OTP requests

    if (lastSentTime && (now - lastSentTime) < (RATE_LIMIT_MINUTES * 60 * 1000)) {
      const remainingTime = Math.ceil((RATE_LIMIT_MINUTES * 60 * 1000 - (now - lastSentTime)) / 1000);
      console.log(`⏰ Rate limit: ${formattedPhone} must wait ${remainingTime} seconds`);

      return res.status(429).json({
        success: false,
        error: `Please wait ${remainingTime} seconds before requesting another OTP`,
        errorCode: 'RATE_LIMITED',
        retryAfter: remainingTime
      });
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // Store OTP with timestamp
    otpStore.set(formattedPhone, {
      otp: otp,
      timestamp: Date.now(),
      attempts: 0
    });

    // Clean phone number for Fast2SMS (remove +91 prefix if present)
    let cleanNumber = formattedPhone.replace(/\D/g, '');
    if (cleanNumber.startsWith('91')) {
      cleanNumber = cleanNumber.substring(2);
    }

    // Validate 10-digit Indian number
    if (cleanNumber.length !== 10) {
      return res.status(400).json({
        success: false,
        error: 'Invalid Indian phone number format',
        errorCode: 'INVALID_PHONE_FORMAT'
      });
    }

    console.log(`🔢 Clean number: ${cleanNumber}`);
    console.log(`🔐 Generated OTP: ${otp}`);

    // Create OTP message
    const message = `Your Vrisham verification code is: ${otp}. Valid for 5 minutes. Do not share this code.`;

    // Get fetch function
    const fetchFn = await getFetch();

    // Send SMS via Fast2SMS
    const smsUrl = `https://www.fast2sms.com/dev/bulkV2?authorization=${FAST2SMS_API_KEY}&variables_values=${otp}&route=otp&numbers=${cleanNumber}`;

    const response = await fetchFn(smsUrl, {
      method: 'GET',
    });

    console.log(`📡 Fast2SMS Response Status: ${response.status}`);

    // Get response text to see what Fast2SMS is saying
    const responseText = await response.text();
    console.log(`📡 Fast2SMS Response Body: ${responseText}`);

    if (response.ok) {
      console.log('✅ OTP sent successfully via Fast2SMS');

      // Update rate limit tracking
      rateLimitStore.set(formattedPhone, Date.now());

      return res.status(200).json({
        success: true,
        message: 'OTP sent successfully',
        phoneNumber: formattedPhone,
        expiresAt: Date.now() + (5 * 60 * 1000) // 5 minutes from now
      });
    } else {
      console.error('❌ Fast2SMS API error:', response.status);
      console.error('❌ Fast2SMS Error Details:', responseText);

      // Remove OTP from store if sending failed
      otpStore.delete(formattedPhone);

      return res.status(500).json({
        success: false,
        error: `Failed to send OTP via SMS service: ${responseText}`,
        errorCode: 'SMS_SEND_FAILED'
      });
    }

  } catch (error) {
    console.error('❌ OTP Send Error:', error);

    // Clean up on error
    if (req.body.phoneNumber) {
      const formattedPhone = req.body.phoneNumber.startsWith('+') ? req.body.phoneNumber : `+${req.body.phoneNumber}`;
      otpStore.delete(formattedPhone);
    }

    res.status(500).json({
      success: false,
      error: error.message || 'Internal server error',
      errorCode: 'SERVER_ERROR'
    });
  }
});

// SMS proxy endpoint (legacy - for backward compatibility)
app.post('/api/send-sms', async (req, res) => {
  try {
    const { phoneNumber, message } = req.body;

    if (!phoneNumber || !message) {
      return res.status(400).json({ 
        success: false, 
        error: 'Phone number and message are required' 
      });
    }

    console.log(`📱 Sending SMS to: ${phoneNumber}`);
    console.log(`📝 Message: ${message}`);

    // Clean phone number (remove +91 prefix if present)
    let cleanNumber = phoneNumber.replace(/\D/g, '');
    if (cleanNumber.startsWith('91')) {
      cleanNumber = cleanNumber.substring(2);
    }

    // Validate 10-digit Indian number
    if (cleanNumber.length !== 10) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid Indian phone number format' 
      });
    }

    console.log(`🔢 Clean number: ${cleanNumber}`);

    // Get fetch function
    const fetchFn = await getFetch();

    // Make request to Fast2SMS
    const response = await fetchFn('https://www.fast2sms.com/dev/bulkV2', {
      method: 'POST',
      headers: {
        'Authorization': FAST2SMS_API_KEY,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        route: 'v3',
        sender_id: 'TXTIND',
        message: message,
        language: 'english',
        flash: 0,
        numbers: cleanNumber,
      }),
    });

    console.log(`📡 Fast2SMS Response Status: ${response.status}`);

    if (!response.ok) {
      const error = await response.json();
      console.error('❌ Fast2SMS Error:', error);
      return res.status(500).json({
        success: false,
        error: error.message || 'Failed to send SMS via Fast2SMS',
        errorCode: error.code?.toString() || 'FAST2SMS_ERROR',
      });
    }

    const result = await response.json();
    console.log('📋 Fast2SMS Result:', result);

    if (result.return === true) { 
      console.log('✅ SMS sent successfully!');
      res.json({
        success: true,
        messageId: result.request_id,
        message: 'SMS sent successfully',
      });
    } else {
      console.error('❌ Fast2SMS request failed:', result.message);
      res.status(500).json({
        success: false,
        error: result.message || 'Fast2SMS request failed',
        errorCode: 'FAST2SMS_REQUEST_FAILED',
      });
    }
  } catch (error) {
    console.error('❌ SMS Proxy Error:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Internal server error',
      errorCode: 'SERVER_ERROR',
    });
  }
});

// OTP verification and Firebase token generation endpoint
app.post('/api/verify-otp', async (req, res) => {
  try {
    const { phoneNumber, otp } = req.body;

    if (!phoneNumber || !otp) {
      return res.status(400).json({
        success: false,
        error: 'Phone number and OTP are required',
        errorCode: 'MISSING_FIELDS'
      });
    }

    // Format phone number
    const formattedPhone = phoneNumber.startsWith('+') ? phoneNumber : `+${phoneNumber}`;

    console.log(`🔐 Verifying OTP for ${formattedPhone}`);

    // Check if OTP exists in store
    const storedOtpData = otpStore.get(formattedPhone);

    if (!storedOtpData) {
      return res.status(400).json({
        success: false,
        error: 'No OTP found for this phone number. Please request a new OTP.',
        errorCode: 'OTP_NOT_FOUND'
      });
    }

    // Check if OTP has expired (5 minutes)
    const now = Date.now();
    const otpAge = now - storedOtpData.timestamp;
    const OTP_EXPIRY = 5 * 60 * 1000; // 5 minutes

    if (otpAge > OTP_EXPIRY) {
      otpStore.delete(formattedPhone);
      return res.status(400).json({
        success: false,
        error: 'OTP has expired. Please request a new OTP.',
        errorCode: 'OTP_EXPIRED'
      });
    }

    // Verify OTP
    if (storedOtpData.otp !== otp) {
      // Increment attempt count
      storedOtpData.attempts = (storedOtpData.attempts || 0) + 1;

      if (storedOtpData.attempts >= 3) {
        otpStore.delete(formattedPhone);
        return res.status(400).json({
          success: false,
          error: 'Too many incorrect attempts. Please request a new OTP.',
          errorCode: 'TOO_MANY_ATTEMPTS'
        });
      }

      return res.status(400).json({
        success: false,
        error: 'Invalid OTP. Please try again.',
        errorCode: 'INVALID_OTP',
        attemptsRemaining: 3 - storedOtpData.attempts
      });
    }

    console.log('✅ OTP verified successfully');

    // Clear OTP from store
    otpStore.delete(formattedPhone);

    // Generate Firebase custom token
    if (!firebaseAdminInitialized) {
      console.error('❌ Firebase Admin SDK not initialized - cannot generate custom token');
      return res.status(500).json({
        success: false,
        error: 'Firebase Admin SDK not configured. Please add serviceAccountKey.json',
        errorCode: 'FIREBASE_NOT_CONFIGURED'
      });
    }

    try {
      // Check if user exists in Firestore by phone number
      const usersRef = admin.firestore().collection('Users');
      const userQuery = await usersRef.where('phoneNumber', '==', formattedPhone).get();

      let uid;
      let userExists = false;

      if (!userQuery.empty) {
        // Existing user found - use their existing UID
        const existingUser = userQuery.docs[0];
        uid = existingUser.id;
        userExists = true;
        console.log(`🔄 Existing user found with UID: ${uid}`);
      } else {
        // New user - let Firebase generate a proper UID
        // We'll create a temporary custom token and let the client handle user creation
        uid = `user_${formattedPhone.replace(/[^0-9]/g, '')}`;
        userExists = false;
        console.log(`🆕 New user, using temporary UID: ${uid}`);
      }

      console.log(`🔑 Generating Firebase token for UID: ${uid}`);

      // Generate custom token
      const firebaseToken = await admin.auth().createCustomToken(uid, {
        phoneNumber: formattedPhone,
        verifiedAt: new Date().toISOString(),
        isNewUser: !userExists
      });

      console.log('✅ Firebase custom token generated successfully');

      return res.status(200).json({
        success: true,
        firebaseToken: firebaseToken,
        uid: uid,
        phoneNumber: formattedPhone,
        userExists: userExists,
        message: 'OTP verified and Firebase token generated successfully'
      });

    } catch (firebaseError) {
      console.error('❌ Firebase token generation failed:', firebaseError);
      return res.status(500).json({
        success: false,
        error: 'Failed to generate Firebase authentication token',
        errorCode: 'FIREBASE_TOKEN_ERROR'
      });
    }

  } catch (error) {
    console.error('❌ OTP Verification Error:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Internal server error',
      errorCode: 'SERVER_ERROR'
    });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'SMS Proxy Server with Firebase Auth',
    timestamp: new Date().toISOString(),
    features: {
      smsProxy: true,
      firebaseAuth: admin.apps.length > 0,
      otpStorage: otpStore.size
    }
  });
});

// Start server on all network interfaces
app.listen(PORT, '0.0.0.0', () => {
  console.log('🚀 SMS Proxy Server started!');
  console.log(`📡 Server running on: http://localhost:${PORT}`);
  console.log(`📱 Android Emulator: http://10.0.2.2:${PORT}`);
  console.log(`📱 Physical Device: http://192.168.1.10:${PORT}`);
  console.log(`🔑 Fast2SMS API Key: ${FAST2SMS_API_KEY.substring(0, 10)}...`);
  console.log('');
  console.log('Available endpoints:');
  console.log(`  POST http://localhost:${PORT}/api/send-otp (Web)`);
  console.log(`  POST http://10.0.2.2:${PORT}/api/send-otp (Emulator)`);
  console.log(`  POST http://192.168.1.10:${PORT}/api/send-otp (Device)`);
  console.log(`  GET  http://192.168.1.10:${PORT}/api/health`);
  console.log('');
  console.log('✅ Ready for both Android Emulator and Physical Device!');
  console.log('');
  console.log('🔥 IMPORTANT FOR PHYSICAL DEVICES:');
  console.log('   Make sure Windows Firewall allows port 3001');
  console.log('   Run: netsh advfirewall firewall add rule name="SMS Proxy" dir=in action=allow protocol=TCP localport=3001');
});

module.exports = app;

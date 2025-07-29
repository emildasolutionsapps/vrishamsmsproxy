/**
 * SMS Proxy Server with Firebase Authentication
 * Handles Fast2SMS OTP sending and Firebase custom token generation
 */

// Load environment variables
require('dotenv').config();

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
  // Try to initialize with environment variables first (recommended for production)
  if (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_PRIVATE_KEY && process.env.FIREBASE_CLIENT_EMAIL) {
    console.log('🔧 Initializing Firebase with environment variables...');
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      }),
    });
    firebaseAdminInitialized = true;
    console.log('✅ Firebase Admin SDK initialized with environment variables');
  } else {
    // Fallback to service account key file (for local development)
    console.log('🔧 Trying to initialize Firebase with service account file...');
    const serviceAccount = require('./serviceAccountKey.json');
    admin.initializeApp({
      credential: admin.credential.cert({
        type: "service_account",
        project_id: "vrisham-cad24",
        private_key_id: "cc5cf6ab9e69050ac368fd40d468ccdc73ec7ed2",
        private_key: "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDIP0/dgl6/IE+5\nzu62edJTzFCkXyeUmg7gn3JDmOo/IUQ5r3JJu1BXOMBUUcHvGQgL0aNE5jehswvu\nHCv7yvWMNJ5XqoqmWtV3Ds04Y5Zf1yk5Pb/ggLe39+NUZUsaMmgK2GfCo77bCz4l\nGtbQCgT8UCtmq74TQCuS80KIegLLfTxSWXiJfzzN58LYgYmBOcfu+IaDw0395iNh\n3umhCerxaYDpAhthcYO0l3TWByig79Wa86W1zRAZ/tcs6ruBVwaFl2+yE/+Itc+F\nxuKvo6svHPT1dbXBfDzKXOKQMLXf/ZZraZJFWe82nYpBtiyvZL8OTXJlIby0lmhv\n1xKuK+t3AgMBAAECggEATxgi1Z2PCvMaSowf4deQaiUDnUkwexO22KZiHa0iqTjc\nl+RiwhjIjQsPfL6mWWiLsw9k6+v7AVWVWsGp5dSu1GhcOshT541tT497I9DCLqzv\nzXpEdcqhxnqVQlqYJYrPaak8orbGxgJU05ccTiQHABoyamVfuH7aNzr6hqmavQDR\ncbguLBXk3ql6BBu2Miux55Vgq/7YBa80SjeR94QCZY5JGkB1iyVgep3bbo86XQIr\n4Axg+gNjh59nvcr48HDMZcXdVwy+jBtmj4dD/1QM7mkYd8iN8wmj2ZIL31c6CLmS\njBd9In6S36OEGuj8NmrliY/taRDlD3Oa0zM9i8VNYQKBgQDsXDQecNL1UYajIfKZ\n31cIDu99lolTnQ2luW5cgBaqCfgW+aUEjlLfSbjp57h09swQnkPfSfPtkHUgOQVO\nGqCOzlTE+Xa5FPfri7WIH2n1hMa8Tscf3PFYMndBdvPHEffuQADyVLeJXG8S7nXx\n4lVkmP05+BRRTeGyxTEU7SirmQKBgQDY4uylgt2thTeZ2k0/NF7Nh6FPpJU38fjZ\nf2tY+v6WePNbBCzt4tCtUW4eQsHiwZKVKMB1XOlRlOHB5gEXSgQXkHic8iaV0SOM\nU6YTtYIoXAL2cSZZplyAmS8D13Es6VIwbj3ewiMB4w717TM5SLAO9Qgn4YIiZLOe\nekSrx5c5jwKBgF9p+UAwm3icqJVCJwUmu6NtJBC2rEkspU25RWvh6URLMfNUY+Eq\n8xlgUV1bRYMx/b7XpN6GpAnKvv17B0E4TohXkrDRY7PjWxGjHG0PAV8zcmaiBpA+\nSM8p0CqFMnOyNTvgaoFo4Y552fzydnpmu8IYYGD+XHVV0z6vi9i+xCRBAoGAbyUz\nYspCsfav/K8roPVElA0qdHcCZS4iectbhrjxmMkY5Q6pu6rdh8RQKz/Ivly2squ0\nnTBk/QLQAp7M9lNe73iA5uUNMv9/OR1w4W7F6crlVce8gHrJsrlNp6lTfVGAZgNI\nv4w7hm8Grq7E7lk6qB+X82AUYW27wr4jzOg2ri8CgYB2eddLTGI+ium53pta2FdW\nhI3uB2cp6L/fJxyvmIVvlAnnmaTmWY+kDvHiobXlA9dY7SoRN7GgSnbNNZoIiN/f\n0uNmEtiqXKQjkwLUNeLmMc6kp9XY+Z0InY0ZaedCdiPfoY65cMXhp8NBpsi2qBNK\n9FRsfuQowGqnkEp8zFP0EQ==\n-----END PRIVATE KEY-----\n",
        client_email: "firebase-adminsdk-ucp2q@vrisham-cad24.iam.gserviceaccount.com",
        client_id: "113767465011537940625",
        auth_uri: "https://accounts.google.com/o/oauth2/auth",
        token_uri: "https://oauth2.googleapis.com/token",
        auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
        client_x509_cert_url: "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-ucp2q%40vrisham-cad24.iam.gserviceaccount.com",
        universe_domain: "googleapis.com"
      }),
    });
    firebaseAdminInitialized = true;
    console.log('✅ Firebase Admin SDK initialized with service account file');
  }
} catch (error) {
  console.error('❌ Firebase Admin SDK initialization failed:', error.message);
  console.log('⚠️  Firebase custom token generation will not work');
  console.log('');
  console.log('💡 To fix this, choose one of these options:');
  console.log('   1. Set environment variables (recommended for production):');
  console.log('      - FIREBASE_PROJECT_ID=your-project-id');
  console.log('      - FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\\n..."');
  console.log('      - FIREBASE_CLIENT_EMAIL=firebase-adminsdk-...@your-project.iam.gserviceaccount.com');
  console.log('   2. Create serviceAccountKey.json from Firebase Console (for local development)');
  console.log('');
}

// In-memory OTP storage (in production, use Redis or database)
const otpStore = new Map();

// Rate limiting storage - track last OTP send time per phone number
const rateLimitStore = new Map();

// Enable CORS for all routes
app.use(cors({ origin: true, credentials: true }));
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
      firebaseAdminInitialized: firebaseAdminInitialized,
      otpStorage: otpStore.size
    }
  });
});

// Debug endpoint to check Firebase status
app.get('/api/debug/firebase', (req, res) => {
  res.json({
    firebaseAdminInitialized: firebaseAdminInitialized,
    adminAppsLength: admin.apps.length,
    hasDefaultApp: admin.apps.length > 0,
    appName: admin.apps.length > 0 ? admin.apps[0].name : 'none'
  });
});



// Get local IP address
const os = require('os');
function getLocalIP() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return '192.168.1.14'; // fallback
}

const localIP = getLocalIP();

// Start server on all network interfaces
app.listen(PORT, '0.0.0.0', () => {
  console.log('🚀 SMS Proxy Server started!');
  console.log(`📡 Server running on: http://localhost:${PORT}`);
  console.log(`📱 Android Emulator: http://10.0.2.2:${PORT}`);
  console.log(`📱 Physical Device: http://${localIP}:${PORT}`);
  console.log(`🔑 Fast2SMS API Key: ${FAST2SMS_API_KEY.substring(0, 10)}...`);
  console.log('');
  console.log('Available endpoints:');
  console.log(`  POST http://localhost:${PORT}/api/send-otp (Web)`);
  console.log(`  POST http://10.0.2.2:${PORT}/api/send-otp (Emulator)`);
  console.log(`  POST http://${localIP}:${PORT}/api/send-otp (Device)`);
  console.log(`  GET  http://${localIP}:${PORT}/api/health`);
  console.log(`  GET  http://${localIP}:${PORT}/api/debug/firebase`);
  console.log('');
  console.log('✅ Ready for both Android Emulator and Physical Device!');
  console.log('');
  console.log('🔥 IMPORTANT FOR PHYSICAL DEVICES:');
  console.log('   Make sure Windows Firewall allows port 3001');
  console.log('   Run: netsh advfirewall firewall add rule name="SMS Proxy" dir=in action=allow protocol=TCP localport=3001');
  console.log('');
  console.log('🔧 TROUBLESHOOTING:');
  console.log(`   Test connectivity: http://${localIP}:${PORT}/api/health`);
  console.log(`   Check Firebase: http://${localIP}:${PORT}/api/debug/firebase`);
});

module.exports = app;

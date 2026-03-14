// routes/auth.js — Autentifikatsiya Routelari
const express = require('express');
const router  = express.Router();

const {
  register,
  login,
  logout,
  refreshToken,
  verifyEmail,
  forgotPassword,
  resetPassword,
  getMe
} = require('../controllers/authController');

const {
  googleCallback,
  googleRedirectCallback
} = require('../controllers/googleController');

const { protect } = require('../middleware/auth');

const {
  loginLimiter,
  registerLimiter,
  passwordResetLimiter,
  verifyCsrfToken
} = require('../middleware/security');

// ────────────────────────────────────────────
//  LOCAL AUTH
// ────────────────────────────────────────────

// POST /api/auth/register
router.post('/register',
  registerLimiter,
  verifyCsrfToken,
  register
);

// POST /api/auth/login
router.post('/login',
  loginLimiter,
  verifyCsrfToken,
  login
);

// POST /api/auth/logout
router.post('/logout', logout);

// POST /api/auth/refresh
router.post('/refresh', refreshToken);

// ────────────────────────────────────────────
//  EMAIL
// ────────────────────────────────────────────

// GET /api/auth/verify-email?token=...
router.get('/verify-email', verifyEmail);

// POST /api/auth/forgot-password
router.post('/forgot-password',
  passwordResetLimiter,
  forgotPassword
);

// POST /api/auth/reset-password
router.post('/reset-password',
  verifyCsrfToken,
  resetPassword
);

// ────────────────────────────────────────────
//  GOOGLE OAUTH 2.0
// ────────────────────────────────────────────

// POST /api/auth/google
// Frontend Google Sign-In ID Token yuboradi (One Tap / Sign-In button)
router.post('/google',
  loginLimiter,
  verifyCsrfToken,
  googleCallback
);

// GET /api/auth/google/callback
// Google redirect (Authorization Code Flow)
router.get('/google/callback', googleRedirectCallback);

// ────────────────────────────────────────────
//  PROTECTED ROUTES
// ────────────────────────────────────────────

// GET /api/auth/me
router.get('/me', protect, getMe);

module.exports = router;
// controllers/googleController.js — Google OAuth 2.0 Controlleri
const { OAuth2Client } = require('google-auth-library');
const jwt  = require('jsonwebtoken');
const User = require('../models/User');

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ─── Token va Cookie Yaratish ───
const sendTokenCookies = (res, userId) => {
  const accessToken = jwt.sign(
    { id: userId },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '1h', issuer: 'secureauth' }
  );
  const refreshToken = jwt.sign(
    { id: userId },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d', issuer: 'secureauth' }
  );

  const isProduction = process.env.NODE_ENV === 'production';

  res.cookie('access-token', accessToken, {
    httpOnly: true,
    secure:   isProduction,
    sameSite: 'Strict',
    maxAge:   60 * 60 * 1000
  });
  res.cookie('refresh-token', refreshToken, {
    httpOnly: true,
    secure:   isProduction,
    sameSite: 'Strict',
    maxAge:   7 * 24 * 60 * 60 * 1000,
    path:     '/api/auth/refresh'
  });

  return { accessToken };
};

// ─── Google payload dan ism/familiya olish ───
// Google ba'zan family_name bermaydi — fallback qiymatlar ishlatiladi
const parseName = (firstName, lastName, email) => {
  const emailPrefix = email.split('@')[0];

  // given_name bo'lsa ishlatamiz, bo'lmasa email prefix
  const first = (firstName && firstName.trim()) || emailPrefix;

  // family_name bo'lsa ishlatamiz, bo'lmasa given_name yoki email prefix
  const last  = (lastName  && lastName.trim())  || first;

  return { first, last };
};

// ══════════════════════════════════════
//  Google ID Token tekshirish
//  Flow: Frontend → Google Sign-In SDK → ID Token → POST /api/auth/google
// ══════════════════════════════════════
exports.googleCallback = async (req, res) => {
  try {
    const { credential } = req.body;

    if (!credential) {
      return res.status(400).json({
        success: false,
        message: 'Google credential topilmadi'
      });
    }

    // ── Google ID Token Verify ──
    let payload;
    try {
      const ticket = await client.verifyIdToken({
        idToken:  credential,
        audience: process.env.GOOGLE_CLIENT_ID
      });
      payload = ticket.getPayload();
    } catch (verifyErr) {
      console.error('Google token verify xatosi:', verifyErr.message);
      return res.status(401).json({
        success: false,
        message: 'Google autentifikatsiya muvaffaqiyatsiz'
      });
    }

    // ── Payload dan ma'lumotlar ──
    const {
      sub:         googleId,
      email,
      given_name:  rawFirstName,
      family_name: rawLastName,
      picture:     avatar,
      email_verified
    } = payload;

    if (!email_verified) {
      return res.status(400).json({
        success: false,
        message: 'Google hisobingizning emaili tasdiqlanmagan'
      });
    }

    // ── Ism/Familiya — fallback bilan ──
    const { first: firstName, last: lastName } = parseName(rawFirstName, rawLastName, email);

    // ── Mavjud foydalanuvchini topish ──
    let user = await User.findOne({
      $or: [
        { googleId },
        { email: email.toLowerCase() }
      ]
    });

    if (user) {
      // Mavjud hisob — yangilash
      if (!user.googleId) {
        user.googleId     = googleId;
        user.authProvider = 'google';
      }
      if (!user.avatar && avatar) user.avatar = avatar;
      user.isEmailVerified = true;
      user.lastLogin       = new Date();
      await user.save({ validateBeforeSave: false });

    } else {
      // Yangi foydalanuvchi — yaratish
      user = await User.create({
        firstName,
        lastName,
        email:           email.toLowerCase(),
        googleId,
        avatar:          avatar || null,
        authProvider:    'google',
        isEmailVerified: true
      });
    }

    // ── JWT Cookie yuborish ──
    const { accessToken } = sendTokenCookies(res, user._id);

    res.status(200).json({
      success: true,
      message: 'Google orqali muvaffaqiyatli kirdingiz',
      data: {
        user: {
          id:              user._id,
          firstName:       user.firstName,
          lastName:        user.lastName,
          email:           user.email,
          avatar:          user.avatar,
          isEmailVerified: user.isEmailVerified,
          role:            user.role,
          authProvider:    user.authProvider
        },
        accessToken
      }
    });

  } catch (err) {
    console.error('Google callback xatosi:', err);
    res.status(500).json({
      success: false,
      message: 'Server xatosi'
    });
  }
};

// ══════════════════════════════════════
//  Authorization Code Flow (Redirect)
//  Flow: Frontend → Google → redirect → GET /api/auth/google/callback
// ══════════════════════════════════════
exports.googleRedirectCallback = async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) {
      return res.redirect(`${process.env.CLIENT_URL}/login?error=google_cancelled`);
    }
    if (!code) {
      return res.redirect(`${process.env.CLIENT_URL}/login?error=no_code`);
    }

    // ── Code → Tokens ──
    const oauthClient = new OAuth2Client(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      `${process.env.CLIENT_URL}/api/auth/google/callback`
    );

    const { tokens } = await oauthClient.getToken(code);
    oauthClient.setCredentials(tokens);

    const ticket = await oauthClient.verifyIdToken({
      idToken:  tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();

    const {
      sub:         googleId,
      email,
      given_name:  rawFirstName,
      family_name: rawLastName,
      picture:     avatar,
      email_verified
    } = payload;

    if (!email_verified) {
      return res.redirect(`${process.env.CLIENT_URL}/login?error=email_not_verified`);
    }

    const { first: firstName, last: lastName } = parseName(rawFirstName, rawLastName, email);

    let user = await User.findOne({
      $or: [{ googleId }, { email: email.toLowerCase() }]
    });

    if (user) {
      if (!user.googleId) {
        user.googleId        = googleId;
        user.authProvider    = 'google';
        user.isEmailVerified = true;
      }
      if (!user.avatar && avatar) user.avatar = avatar;
      user.lastLogin = new Date();
      await user.save({ validateBeforeSave: false });
    } else {
      user = await User.create({
        firstName,
        lastName,
        email:           email.toLowerCase(),
        googleId,
        avatar:          avatar || null,
        authProvider:    'google',
        isEmailVerified: true
      });
    }

    sendTokenCookies(res, user._id);
    res.redirect(`${process.env.CLIENT_URL}/dashboard?login=success`);

  } catch (err) {
    console.error('Google redirect callback xatosi:', err);
    res.redirect(`${process.env.CLIENT_URL}/login?error=server_error`);
  }
};
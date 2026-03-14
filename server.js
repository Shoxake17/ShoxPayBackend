// server.js — SecureAuth Backend | Asosiy Kirish Nuqtasi
'use strict';

require('dotenv').config();
const express      = require('express');
const cookieParser = require('cookie-parser');
const connectDB    = require('./config/db');
const authRoutes   = require('./routes/auth');
const cashbackRoutes = require('./routes/cashbackRoutes');

const {
  helmetConfig,
  corsConfig,
  apiLimiter,
  sanitizeConfig,
  sanitizeInput,
  generateCsrfToken,
  securityLogger
} = require('./middleware/security');

const app  = express();
const PORT = process.env.PORT || 5000;

// ══════════════════════════════════════
//  1. MA'LUMOTLAR BAZASIGA ULANISH
// ══════════════════════════════════════
connectDB();

// ══════════════════════════════════════
//  2. XAVFSIZLIK MIDDLEWARE'LARI
// ══════════════════════════════════════

// Helmet: 15+ HTTP xavfsizlik headerlari
app.use(helmetConfig);

// CORS: Faqat ruxsat etilgan domainlar
app.use(corsConfig);

// Cookie Parser
app.use(cookieParser(process.env.COOKIE_SECRET));

// JSON body: 10KB limit (DoS himoyasi)
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));



// XSS himoyasi: Input tozalash
app.use(sanitizeInput);

// CSRF Cookie generatsiya
app.use(generateCsrfToken);

// Xavfsizlik loglash
app.use(securityLogger);

// Umumiy API Rate Limiting
app.use('/api', apiLimiter);
app.use('/api/cashback', cashbackRoutes);

// ══════════════════════════════════════
//  3. HEALTH CHECK
// ══════════════════════════════════════
app.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    status:  'OK',
    time:    new Date().toISOString(),
    env:     process.env.NODE_ENV
  });
});

// ══════════════════════════════════════
//  4. ROUTELAR
// ══════════════════════════════════════
app.use('/api/auth', authRoutes);

// ══════════════════════════════════════
//  5. 404 HANDLER
// ══════════════════════════════════════
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: `${req.originalUrl} yo'li topilmadi`
  });
});

// ══════════════════════════════════════
//  6. GLOBAL XATO HANDLER
// ══════════════════════════════════════
app.use((err, req, res, next) => {
  console.error(`❌ [${new Date().toISOString()}] ${err.stack}`);

  // Mongoose Validation Xatosi
  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map(e => e.message);
    return res.status(400).json({ success: false, message: messages.join(', ') });
  }

  // Mongoose Duplicate Key
  if (err.code === 11000) {
    return res.status(400).json({ success: false, message: 'Bu ma\'lumot allaqachon mavjud' });
  }

  // JWT Xatosi
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({ success: false, message: 'Noto\'g\'ri token' });
  }

  // CORS Xatosi
  if (err.message && err.message.includes('CORS')) {
    return res.status(403).json({ success: false, message: err.message });
  }

  // Umumiy xato — Production'da stack ko'rsatilmaydi
  res.status(err.status || 500).json({
    success: false,
    message: process.env.NODE_ENV === 'production'
      ? 'Server xatosi. Keyinroq urinib ko\'ring.'
      : err.message
  });
});

// ══════════════════════════════════════
//  7. SERVERNI ISHGA TUSHIRISH
// ══════════════════════════════════════
const server = app.listen(PORT, () => {
  console.log(`\n🚀 Server ishga tushdi: http://localhost:${PORT}`);
  console.log(`📋 Muhit: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔐 API: http://localhost:${PORT}/api/auth\n`);
});

// ── Unhandled Rejection ──
process.on('unhandledRejection', (err) => {
  console.error('❌ Unhandled Rejection:', err.message);
  server.close(() => process.exit(1));
});

// ── Uncaught Exception ──
process.on('uncaughtException', (err) => {
  console.error('❌ Uncaught Exception:', err.message);
  process.exit(1);
});

// ── Graceful Shutdown ──
process.on('SIGTERM', () => {
  console.log('👋 SIGTERM qabul qilindi. Server to\'xtatilmoqda...');
  server.close(() => {
    console.log('✅ Server muvaffaqiyatli to\'xtatildi');
    process.exit(0);
  });
});

module.exports = app;
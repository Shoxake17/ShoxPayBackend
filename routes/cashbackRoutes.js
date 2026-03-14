// ============================================
// ShoxPay Backend: routes/cashbackRoutes.js
// ============================================

const express = require('express');
const router  = express.Router();
const CashbackReceipt = require('../models/CashbackReceipt');
const Wallet          = require('../models/Wallet');
const User            = require('../models/User');
const { protect }     = require('../middleware/auth');

const SHOXPOSPRO_SECRET = process.env.SHOXPOSPRO_SECRET || 'shoxpospro-secret-2024';

function verifyPosSecret(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (apiKey !== SHOXPOSPRO_SECRET) {
    return res.status(403).json({ success: false, message: "Ruxsat yo'q" });
  }
  next();
}

// POST /api/cashback/register  (ShoxPosPro tomonidan chaqiriladi)
router.post('/register', verifyPosSecret, async (req, res) => {
  try {
    const { receiptId, totalAmount, storeName } = req.body;
    if (!receiptId || !totalAmount) return res.status(400).json({ success: false, message: 'receiptId va totalAmount majburiy' });
    if (!/^\d{12}$/.test(receiptId)) return res.status(400).json({ success: false, message: "receiptId 12 raqam" });
    if (totalAmount <= 0) return res.status(400).json({ success: false, message: "Summa noto'g'ri" });

    const existing = await CashbackReceipt.findOne({ receipt_id: receiptId });
    if (existing) return res.status(409).json({ success: false, message: 'Bu chek ID allaqachon mavjud' });

    const cashbackAmount = parseFloat((totalAmount * 0.01).toFixed(2));
    const expiresAt      = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await CashbackReceipt.create({ receipt_id: receiptId, total_amount: totalAmount, cashback_amount: cashbackAmount, store_name: storeName || 'ShoxPos', expires_at: expiresAt });
    console.log(`✅ Cashback ro'yxatga olindi: ${receiptId} → ${cashbackAmount} so'm`);
    return res.status(201).json({ success: true, receiptId, cashbackAmount, expiresAt });
  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({ success: false, message: 'Server xatosi' });
  }
});

// POST /api/cashback/claim  (protect — faqat login qilgan user)
router.post('/claim', protect, async (req, res) => {
  try {
    const { receiptId } = req.body;
    const userId = req.user._id;

    if (!receiptId) return res.status(400).json({ success: false, message: 'receiptId majburiy' });

    const user = await User.findById(userId).select('cardNumber firstName');
    if (!user) return res.status(404).json({ success: false, message: 'Foydalanuvchi topilmadi' });
    if (!user.cardNumber) return res.status(400).json({ success: false, message: 'Karta raqami mavjud emas' });

    const receipt = await CashbackReceipt.findOne({ receipt_id: receiptId });
    if (!receipt) return res.status(404).json({ success: false, status: 'NOT_FOUND', message: 'Bunday chek topilmadi' });

    const now = new Date();
    if (receipt.expires_at < now) return res.status(410).json({ success: false, status: 'EXPIRED', message: "Chek muddati o'tib ketgan (24 soat)" });
    if (receipt.is_used) return res.status(409).json({ success: false, status: 'ALREADY_USED', message: 'Cashback allaqachon olingan' });

    receipt.is_used = true;
    receipt.used_at = now;
    receipt.user_phone = user.cardNumber;
    await receipt.save();

    const updatedWallet = await Wallet.findOneAndUpdate(
      { user_id: userId },
      {
        $inc: { balance: receipt.cashback_amount },
        $set: { updated_at: now, card_number: user.cardNumber },
        $push: { transactions: { type: 'cashback', amount: receipt.cashback_amount, receipt_id: receiptId, store_name: receipt.store_name, description: `${receipt.store_name} dan 1% cashback`, created_at: now } },
      },
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );

    console.log(`💰 ${receiptId} → ${receipt.cashback_amount} so'm → ${user.firstName} karta:${user.cardNumber}`);

    return res.status(200).json({
      success: true, status: 'SUCCESS', message: 'Cashback muvaffaqiyatli olindi!',
      receiptId, totalAmount: receipt.total_amount, cashbackAmount: receipt.cashback_amount,
      storeName: receipt.store_name, purchaseDate: receipt.created_at,
      newBalance: updatedWallet.balance, cardNumber: user.cardNumber,
    });
  } catch (err) {
    console.error('Claim error:', err);
    return res.status(500).json({ success: false, message: 'Server xatosi' });
  }
});

// GET /api/cashback/wallet  (protect — login qilgan userning wallet)
router.get('/wallet', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    const user   = await User.findById(userId).select('cardNumber firstName');
    if (!user) return res.status(404).json({ success: false, message: 'User topilmadi' });

    const wallet = await Wallet.findOne({ user_id: userId });
    if (!wallet) {
      return res.json({ success: true, balance: 0, cardNumber: user.cardNumber, transactions: [] });
    }
    return res.json({
      success: true, balance: wallet.balance, cardNumber: user.cardNumber,
      transactions: [...wallet.transactions].reverse().slice(0, 20),
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server xatosi' });
  }
});

// GET /api/cashback/check/:receiptId
router.get('/check/:receiptId', async (req, res) => {
  try {
    const receipt = await CashbackReceipt.findOne({ receipt_id: req.params.receiptId });
    if (!receipt) return res.status(404).json({ success: false, status: 'NOT_FOUND' });
    const isExpired = receipt.expires_at < new Date();
    return res.json({
      success: true, receiptId: req.params.receiptId,
      status: receipt.is_used ? 'USED' : isExpired ? 'EXPIRED' : 'VALID',
      cashbackAmount: receipt.cashback_amount, totalAmount: receipt.total_amount,
      storeName: receipt.store_name, expiresAt: receipt.expires_at,
      isUsed: receipt.is_used, isExpired,
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server xatosi' });
  }
});

module.exports = router;
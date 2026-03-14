// config/db.js — MongoDB ulanishi
const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI, {
      // Mongoose 8+ da bu opsiyalar default bo'lgani uchun ko'rsatilmadi
    });

    console.log(`✅ MongoDB ulandi: ${conn.connection.host}`);

    // Ulanish hodisalari
    mongoose.connection.on('error', (err) => {
      console.error(`❌ MongoDB xatosi: ${err.message}`);
    });

    mongoose.connection.on('disconnected', () => {
      console.warn('⚠️  MongoDB uzildi. Qayta ulanishga harakat...');
    });

  } catch (err) {
    console.error(`❌ MongoDB ulanmadi: ${err.message}`);
    process.exit(1); // Ulanmasa dastur to'xtaydi
  }
};

module.exports = connectDB;
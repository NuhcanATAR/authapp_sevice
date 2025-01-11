const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('../db');
const router = express.Router();

// login endpoint
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Geçersiz e-posta veya şifre' });
    }

    const user = rows[0];

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Geçersiz e-posta veya şifre' });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET, 
      { expiresIn: process.env.JWT_EXPIRES_IN } 
    );

    res.json({ message: 'Giriş başarılı', token });
  } catch (err) {
    res.status(500).json({ error: 'Giriş sırasında hata oluştu' });
  }
});

// register endpoint
router.post('/register', async (req, res) => {
  const { email, password } = req.body;
  try {
     
      const [existingUser] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
      if (existingUser.length > 0) {
          return res.status(400).json({ error: 'Bu e-posta adresi zaten kayıtlı' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const [result] = await pool.query(
          'INSERT INTO users (email, password) VALUES (?, ?)',
          [email, hashedPassword]
      );

      if (result.affectedRows === 0) {
          return res.status(500).json({ error: 'Kullanıcı kaydedilemedi' });
      }

      const userId = result.insertId;
      const [profileResult] = await pool.query(
          'INSERT INTO user_profile (user_id) VALUES (?)',
          [userId]
      );

      if (profileResult.affectedRows === 0) {
          return res.status(500).json({ error: 'Kullanıcı profili kaydedilemedi' });
      }

      const token = jwt.sign(
          { userId, email },
          process.env.JWT_SECRET,
          { expiresIn: process.env.JWT_EXPIRES_IN }
      );

      res.status(201).json({ message: 'Kayıt başarılı', token });
  } catch (err) {
      console.error('Kayıt Hatası:', err);
      res.status(500).json({ error: 'Kayıt sırasında hata oluştu', details: err.message });
  }
});

// all users endpoints
router.get('/users', async (req, res) => {

  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Token eksik veya geçersiz.' });
  }
  const token = authHeader.split(' ')[1];

  try { 
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.userId;
    
    const [users] = await pool.query('SELECT id, email FROM users');

    if (users.length === 0) {
      return res.status(404).json({ message: 'Kullanıcı bulunamadı' });
    }

    const usersWithProfile = [];
    for (const user of users) {
      const [profileResult] = await pool.query(
        'SELECT id, name, surname, bio FROM user_profile WHERE user_id = ?',
        [user.id]
      );

      let profile = null;
      if (profileResult.length > 0) {
        profile = {
          id: profileResult[0].id,
          name: profileResult[0].name,
          surname: profileResult[0].surname,
          bio: profileResult[0].bio,
        };
      }

      usersWithProfile.push({
        id: user.id,
        email: user.email,
        profile: profile,
      });
    }

    res.status(200).json(usersWithProfile);
  } catch (err) {
    console.error('Hata:', err);
    return res.status(500).json({ error: 'Sunucu hatası', details: err.message });
  }
});



// Profile Endpoints
// profile get
router.get('/profile', async (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token eksik veya geçersiz' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.userId;

    const [userResult] = await pool.query(
      'SELECT id, email FROM users WHERE id = ?',
      [userId]
    );

    if (userResult.length === 0) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }

    const [profileResult] = await pool.query(
      'SELECT id, name, surname, bio FROM user_profile WHERE user_id = ?',
      [userId]
    );

    if (profileResult.length === 0) {
      return res.status(404).json({ error: 'Kullanıcı profili bulunamadı' });
    }

    res.status(200).json({
      id: userResult[0].id,
      email: userResult[0].email,
      profile: {
        id: profileResult[0].id,
        name: profileResult[0].name,
        surname: profileResult[0].surname,
        bio: profileResult[0].bio,
      },
    });
  } catch (err) {
    console.error('Hata:', err);
    return res.status(500).json({ error: 'Sunucu hatası', details: err.message });
  }
});

// profile edit
router.put('/profile', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1]; 
  if (!token) {
      return res.status(401).json({ error: 'Yetkilendirme hatası, token eksik' });
  }

  try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const { userId } = decoded;

      const { name, surname, bio } = req.body;

      const [result] = await pool.query(
          'UPDATE user_profile SET name = ?, surname = ?, bio = ? WHERE user_id = ?',
          [name, surname, bio, userId]
      );

      if (result.affectedRows > 0) {
          return res.status(200).json({ message: 'Profil başarıyla güncellendi.' });
      } else {
          return res.status(404).json({ error: 'Profil bulunamadı.' });
      }
  } catch (err) {
      if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
          return res.status(401).json({ error: 'Geçersiz veya süresi dolmuş token' });
      }
      console.error('Profil Güncelleme Hatası:', err);
      res.status(500).json({ error: 'Profil güncellenirken hata oluştu', details: err.message });
  }
});

// JWT Token
router.get('/protected', verifyToken, (req, res) => {
  res.json({ message: `Merhaba, ${req.user.email}. Bu korumalı bir rota!` });
});

function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Token eksik' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token geçersiz' });
    req.user = user;
    next(); 
  });
}

module.exports = router;

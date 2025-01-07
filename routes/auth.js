const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('../db');
const router = express.Router();


router.post('/register', async (req, res) => {
    const { email, password } = req.body;
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const [result] = await pool.query(
        'INSERT INTO users (email, password) VALUES (?, ?)',
        [email, hashedPassword]
      );

      if (result.affectedRows === 0) {
        return res.status(500).json({ error: 'Kullanıcı kaydedilemedi' });
      }
     
      const token = jwt.sign(
        { userId: result.insertId, email },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN } 
      );
  
      res.status(201).json({ message: 'Kayıt başarılı', token });
    } catch (err) {
      console.error('Kayıt Hatası:', err); 
      res.status(500).json({ error: 'Kayıt sırasında hata oluştu ', details: err.message });
    }
  });
  

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

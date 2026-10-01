const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('./config');
const db = require('./database');

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve static frontend files
app.use(express.static(path.join(__dirname, 'public')));

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'مطلوب تسجيل الدخول للوصول' });
  }

  jwt.verify(token, config.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'انتهت صلاحية الجلسة، يرجى إعادة تسجيل الدخول' });
    }
    const user = db.findUserById(decoded.id);
    if (!user) {
      return res.status(403).json({ success: false, message: 'المستخدم لم يعد مسجلاً' });
    }
    req.user = {
      id: user.id,
      username: user.username,
      name: user.name,
      role: user.role
    };
    next();
  });
}

// Admin only middleware
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'هذه العملية مخصصة لمدير النظام فقط' });
  }
  next();
}

// ------------------- API ROUTES -------------------

// 1. Login with Username & Password
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'يرجى إدخال اسم المستخدم وكلمة المرور' });
    }

    const user = db.findUserByUsername(username);
    if (!user) {
      return res.status(401).json({ success: false, message: 'بيانات الدخول غير صحيحة' });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'بيانات الدخول غير صحيحة' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      config.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// 2. Fast PIN Login / Unlock
app.post('/api/auth/pin-login', async (req, res) => {
  try {
    const { pin } = req.body;
    if (!pin) {
      return res.status(400).json({ success: false, message: 'يرجى إدخال الرمز السري PIN' });
    }

    const user = await db.verifyPin(pin);
    if (!user) {
      return res.status(401).json({ success: false, message: 'الرمز السري غير صحيح' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      config.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// 3. Current User verification
app.get('/api/auth/me', authenticateToken, (req, res) => {
  res.json({ success: true, user: req.user });
});

// 4. Change PIN
app.post('/api/auth/change-pin', authenticateToken, async (req, res) => {
  try {
    const { newPin } = req.body;
    if (!newPin || newPin.length < 4) {
      return res.status(400).json({ success: false, message: 'الرمز السري يجب أن يتكون من 4 أرقام على الأقل' });
    }
    await db.updateUserPin(req.user.id, newPin);
    res.json({ success: true, message: 'تم تحديث الرمز السري بنجاح' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// 5. Change Password
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = db.findUserById(req.user.id);

    const isMatch = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'كلمة المرور الحالية غير صحيحة' });
    }

    if (!newPassword || newPassword.length < 4) {
      return res.status(400).json({ success: false, message: 'كلمة المرور الجديدة يجب ألا تقل عن 4 خانات' });
    }

    await db.updateUserPassword(req.user.id, newPassword);
    res.json({ success: true, message: 'تم تحديث كلمة المرور بنجاح' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// 6. Users List (Admin)
app.get('/api/users', authenticateToken, requireAdmin, (req, res) => {
  res.json({ success: true, users: db.getUsers() });
});

// 7. Add New User (Admin)
app.post('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { username, name, email, password, pin, role } = req.body;
    if (!username || !password || !name) {
      return res.status(400).json({ success: false, message: 'يرجى تعبئة الحقول الأساسية: الاسم، اسم المستخدم وكلمة المرور' });
    }
    const newUser = await db.addUser({ username, name, email, password, pin, role });
    res.json({ success: true, user: newUser, message: 'تم إضافة المستخدم بنجاح' });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

// 8. Records: Get all records
app.get('/api/records', authenticateToken, (req, res) => {
  const records = db.getRecords();
  res.json({ success: true, records });
});

// 9. Records: Save a new cash count record
app.post('/api/records', authenticateToken, (req, res) => {
  try {
    const record = db.addRecord(req.body, req.user);
    res.json({ success: true, record, message: 'تم حفظ عملية الجرد في السجل المحمي بنجاح' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// 10. Records: Delete a record
app.delete('/api/records/:id', authenticateToken, (req, res) => {
  try {
    const { id } = req.params;
    const deleted = db.deleteRecord(id);
    if (!deleted) {
      return res.status(404).json({ success: false, message: 'السجل غير موجود' });
    }
    res.json({ success: true, message: 'تم حذف السجل بنجاح' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// 11. Settings: Get & Update
app.get('/api/settings', authenticateToken, (req, res) => {
  res.json({ success: true, settings: db.getSettings() });
});

app.put('/api/settings', authenticateToken, requireAdmin, (req, res) => {
  try {
    const updated = db.updateSettings(req.body);
    res.json({ success: true, settings: updated, message: 'تم تحديث الإعدادات بنجاح' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// 12. Backup Export (Encrypted)
app.get('/api/backup/export', authenticateToken, requireAdmin, (req, res) => {
  try {
    const encryptedData = db.exportEncrypted();
    const filename = `cash_counter_backup_${new Date().toISOString().slice(0, 10)}.enc`;
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.send(encryptedData);
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// 13. Backup Import (Encrypted)
app.post('/api/backup/import', authenticateToken, requireAdmin, (req, res) => {
  try {
    const { backupContent } = req.body;
    if (!backupContent) {
      return res.status(400).json({ success: false, message: 'محتوى النسخة الاحتياطية مفقود' });
    }
    db.importEncrypted(backupContent);
    res.json({ success: true, message: 'تم استرجاع النسخة الاحتياطية بنجاح' });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

// Network info for Mobile QR connect
app.get('/api/network-info', (req, res) => {
  const os = require('os');
  const interfaces = os.networkInterfaces();
  const addresses = [];
  for (const k in interfaces) {
    for (const k2 in interfaces[k]) {
      const address = interfaces[k][k2];
      if (address.family === 'IPv4' && !address.internal) {
        addresses.push(address.address);
      }
    }
  }
  res.json({
    success: true,
    port: config.PORT,
    ips: addresses,
    primaryUrl: addresses.length > 0 ? `http://${addresses[0]}:${config.PORT}` : `http://localhost:${config.PORT}`
  });
});

// Fallback to index.html for SPA
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
app.listen(config.PORT, config.HOST, () => {
  console.log(`=======================================================`);
  console.log(`💵 تطبيق حاسبة الفئات النقدية وإدارة الصندوق جاهز للعمل!`);
  console.log(`🌐 الرابط المحلي: http://localhost:${config.PORT}`);
  console.log(`🔒 بيانات الدخول الافتراضية:`);
  console.log(`   - اسم المستخدم: admin`);
  console.log(`   - كلمة المرور: admin`);
  console.log(`   - الرمز السري السريع (PIN): 1234`);
  console.log(`=======================================================`);
});

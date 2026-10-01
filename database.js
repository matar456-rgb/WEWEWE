const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const config = require('./config');

class SecureDatabase {
  constructor() {
    this.dbFile = config.DB_FILE;
    this.backupDir = config.BACKUP_DIR;
    this.encryptionKey = crypto.createHash('sha256').update(config.JWT_SECRET).digest(); // 32 bytes
    this.data = {
      users: [],
      records: [],
      settings: {
        businessName: 'مؤسسة العد النقدية',
        currencySymbol: 'ر.س',
        currencyName: 'ريال سعودي',
        enableCoins: true,
        autoLockMinutes: 10
      }
    };
    this.init();
  }

  init() {
    if (!fs.existsSync(config.DATA_DIR)) {
      fs.mkdirSync(config.DATA_DIR, { recursive: true });
    }
    if (!fs.existsSync(this.backupDir)) {
      fs.mkdirSync(this.backupDir, { recursive: true });
    }

    if (fs.existsSync(this.dbFile)) {
      try {
        const raw = fs.readFileSync(this.dbFile, 'utf8');
        this.data = this.decrypt(raw);
      } catch (err) {
        console.error('Error reading encrypted database, loading backup or initializing...', err.message);
        this.initDefaultAdmin();
        this.save();
      }
    } else {
      this.initDefaultAdmin();
      this.save();
    }
  }

  initDefaultAdmin() {
    const salt = bcrypt.genSaltSync(10);
    const hashedPin = bcrypt.hashSync(config.DEFAULT_ADMIN.pin, salt);
    const defaultPassword = 'admin';
    const hashedPassword = bcrypt.hashSync(defaultPassword, salt);

    this.data.users = [
      {
        id: 'usr_' + Date.now(),
        username: config.DEFAULT_ADMIN.username,
        name: config.DEFAULT_ADMIN.name,
        email: config.DEFAULT_ADMIN.email,
        passwordHash: hashedPassword,
        pinHash: hashedPin,
        role: 'admin',
        createdAt: new Date().toISOString()
      }
    ];
  }

  encrypt(obj) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', this.encryptionKey, iv);
    let encrypted = cipher.update(JSON.stringify(obj), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return JSON.stringify({
      iv: iv.toString('hex'),
      payload: encrypted
    });
  }

  decrypt(text) {
    const parsed = JSON.parse(text);
    const iv = Buffer.from(parsed.iv, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', this.encryptionKey, iv);
    let decrypted = decipher.update(parsed.payload, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
  }

  save() {
    try {
      const encrypted = this.encrypt(this.data);
      fs.writeFileSync(this.dbFile, encrypted, 'utf8');

      // Periodic backup snapshot
      const backupFile = path.join(this.backupDir, `backup_${new Date().toISOString().slice(0, 10)}.enc.json`);
      fs.writeFileSync(backupFile, encrypted, 'utf8');
    } catch (err) {
      console.error('Failed to save database securely:', err);
    }
  }

  // --- Users Operations ---
  getUsers() {
    return this.data.users.map(u => ({
      id: u.id,
      username: u.username,
      name: u.name,
      email: u.email,
      role: u.role,
      createdAt: u.createdAt
    }));
  }

  findUserByUsername(username) {
    return this.data.users.find(u => u.username.toLowerCase() === username.toLowerCase());
  }

  findUserById(id) {
    return this.data.users.find(u => u.id === id);
  }

  async verifyPin(pin) {
    for (const user of this.data.users) {
      if (user.pinHash && (await bcrypt.compare(pin, user.pinHash))) {
        return user;
      }
    }
    return null;
  }

  async addUser({ username, name, email, password, pin, role = 'cashier' }) {
    if (this.findUserByUsername(username)) {
      throw new Error('اسم المستخدم موجود مسبقاً');
    }
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    const pinHash = pin ? await bcrypt.hash(pin, salt) : null;

    const newUser = {
      id: 'usr_' + Date.now() + Math.random().toString(36).substr(2, 4),
      username,
      name,
      email: email || '',
      passwordHash,
      pinHash,
      role,
      createdAt: new Date().toISOString()
    };

    this.data.users.push(newUser);
    this.save();
    return {
      id: newUser.id,
      username: newUser.username,
      name: newUser.name,
      role: newUser.role
    };
  }

  async updateUserPin(userId, newPin) {
    const user = this.findUserById(userId);
    if (!user) throw new Error('المستخدم غير موجود');
    const salt = await bcrypt.genSalt(10);
    user.pinHash = await bcrypt.hash(newPin, salt);
    this.save();
    return true;
  }

  async updateUserPassword(userId, newPassword) {
    const user = this.findUserById(userId);
    if (!user) throw new Error('المستخدم غير موجود');
    const salt = await bcrypt.genSalt(10);
    user.passwordHash = await bcrypt.hash(newPassword, salt);
    this.save();
    return true;
  }

  // --- Cash Count Records Operations ---
  getRecords() {
    return this.data.records.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  }

  addRecord(recordData, user) {
    const newRecord = {
      id: 'REC-' + Date.now().toString(36).toUpperCase() + '-' + Math.floor(100 + Math.random() * 900),
      cashierId: user ? user.id : null,
      cashierName: recordData.cashierName || (user ? user.name : 'كاشير'),
      shift: recordData.shift || 'الوردية الرئيسية',
      branch: recordData.branch || 'الفرع الرئيسي',
      denominations: recordData.denominations || {},
      totalAmount: Number(recordData.totalAmount) || 0,
      totalCount: Number(recordData.totalCount) || 0,
      expectedAmount: Number(recordData.expectedAmount) || 0,
      difference: Number(recordData.difference) || 0, // actual - expected
      varianceStatus: recordData.varianceStatus || 'balanced', // balanced, overage, shortage
      notes: recordData.notes || '',
      tafqeet: recordData.tafqeet || '',
      createdAt: new Date().toISOString()
    };

    this.data.records.unshift(newRecord);
    this.save();
    return newRecord;
  }

  deleteRecord(id) {
    const initialLen = this.data.records.length;
    this.data.records = this.data.records.filter(r => r.id !== id);
    if (this.data.records.length !== initialLen) {
      this.save();
      return true;
    }
    return false;
  }

  // --- Settings ---
  getSettings() {
    return this.data.settings;
  }

  updateSettings(newSettings) {
    this.data.settings = { ...this.data.settings, ...newSettings };
    this.save();
    return this.data.settings;
  }

  // Export encrypted backup
  exportEncrypted() {
    return this.encrypt(this.data);
  }

  // Import encrypted backup
  importEncrypted(encryptedDataString) {
    const decrypted = this.decrypt(encryptedDataString);
    if (decrypted && decrypted.users && decrypted.records) {
      this.data = decrypted;
      this.save();
      return true;
    }
    throw new Error('الملف المشفر غير صالح أو تالف');
  }
}

module.exports = new SecureDatabase();

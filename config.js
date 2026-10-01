const path = require('path');

module.exports = {
  PORT: process.env.PORT || 3000,
  HOST: process.env.HOST || '0.0.0.0',
  JWT_SECRET: process.env.JWT_SECRET || 'cash-counter-secure-key-2026-super-protected-987654321',
  DATA_DIR: path.join(__dirname, 'data'),
  DB_FILE: path.join(__dirname, 'data', 'store.enc.json'),
  BACKUP_DIR: path.join(__dirname, 'data', 'backups'),
  DEFAULT_ADMIN: {
    username: 'admin',
    name: 'المدير العام',
    email: 'admin@cashcounter.local',
    pin: '1234'
  }
};

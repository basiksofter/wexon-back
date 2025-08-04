const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

// Настройка CORS для разрешения запросов с любых доменов
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    credentials: true
}));

app.use(express.json());

mongoose.connect(process.env.MONGO_URL);

const UserSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  hwid: { type: String, default: "" },
  uid: { 
    type: Number, 
    required: true,
    validate: {
      validator: function(v) {
        return typeof v === 'number' && !isNaN(v) && v > 0;
      },
      message: 'UID must be a positive number'
    }
  },
  registrationDate: Date,
  lastLogin: Date,
  status: String,
  accountType: String,
  licenseKey: { type: String, default: "" },
  licenseExpiry: Date
});
const User = mongoose.model('User', UserSchema);

// Схема для Minecraft файлов
const MinecraftFileSchema = new mongoose.Schema({
  version: { type: String, required: true }, // release, beta, alpha
  fileName: { type: String, required: true },
  fileUrl: { type: String, required: true },
  fileSize: Number,
  checksum: String,
  uploadDate: { type: Date, default: Date.now },
  isActive: { type: Boolean, default: true },
  description: String,
  changelog: String
});
const MinecraftFile = mongoose.model('MinecraftFile', MinecraftFileSchema);

// Схема для лицензионных ключей
const LicenseKeySchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  type: { type: String, required: true }, // basic, premium, admin
  duration: { type: Number, required: true }, // дни
  maxUses: { type: Number, default: 1 },
  usedCount: { type: Number, default: 0 },
  isActive: { type: Boolean, default: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now },
  expiresAt: Date,
  usedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});
const LicenseKey = mongoose.model('LicenseKey', LicenseKeySchema);

// Схема для админ-логов
const AdminLogSchema = new mongoose.Schema({
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  action: String,
  target: String,
  details: String,
  timestamp: { type: Date, default: Date.now }
});
const AdminLog = mongoose.model('AdminLog', AdminLogSchema);

const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';

app.post('/register', async (req, res) => {
  try {
    const { username, email, password, hwid = "" } = req.body;
    
    if (await User.findOne({ username })) {
      return res.status(400).json({ error: 'Username exists' });
    }
    if (await User.findOne({ email })) {
      return res.status(400).json({ error: 'Email exists' });
    }
    
    // Находим максимальный UID с правильной обработкой ошибок
    let newUid = 1;
    try {
      const maxUser = await User.findOne().sort({ uid: -1 });
      console.log('Max user found:', maxUser ? { uid: maxUser.uid, username: maxUser.username } : 'No users found');
      
      if (maxUser && maxUser.uid && !isNaN(maxUser.uid)) {
        newUid = maxUser.uid + 1;
        console.log('Calculated new UID:', newUid);
      } else {
        console.log('Using default UID:', newUid);
      }
    } catch (error) {
      console.error('Error finding max UID:', error);
      newUid = 1; // Fallback к 1 если что-то пошло не так
    }
    
    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({
      username, 
      email, 
      password: hash,
      hwid,
      uid: newUid,
      registrationDate: new Date(),
      lastLogin: new Date(),
      status: 'active',
      accountType: 'basic'
    });
    
    res.json({ 
      id: user._id, 
      username: user.username, 
      email: user.email,
      uid: user.uid,
      hwid: user.hwid,
      accountType: user.accountType,
      registrationDate: user.registrationDate,
      lastLogin: user.lastLogin
    });
  } catch (error) {
    console.error('Registration error:', error);
    if (error.name === 'ValidationError') {
      return res.status(400).json({ error: 'Validation error: ' + error.message });
    }
    res.status(500).json({ error: 'Internal server error during registration' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password, hwid } = req.body;
  const user = await User.findOne({ username });
  
  if (!user) {
    return res.status(400).json({ error: 'User not found' });
  }
  if (!(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ error: 'Wrong password' });
  }
  
  // Обновляем HWID если передан
  if (hwid && hwid !== user.hwid) {
    user.hwid = hwid;
  }
  
  user.lastLogin = new Date();
  await user.save();
  
  const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ 
    token, 
    user: { 
      id: user._id, 
      username: user.username, 
      email: user.email,
      uid: user.uid,
      hwid: user.hwid,
      accountType: user.accountType,
      registrationDate: user.registrationDate,
      lastLogin: user.lastLogin
    } 
  });
});

app.get('/me', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  
  try {
    const { id } = jwt.verify(auth.split(' ')[1], JWT_SECRET);
    const user = await User.findById(id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    res.json({ 
      id: user._id, 
      username: user.username, 
      email: user.email,
      uid: user.uid,
      hwid: user.hwid,
      accountType: user.accountType,
      registrationDate: user.registrationDate,
      lastLogin: user.lastLogin,
      status: user.status
    });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Endpoint для проверки HWID
app.post('/check-hwid', async (req, res) => {
  try {
    const { username, hwid } = req.body;
    
    if (!username || !hwid) {
      return res.status(400).json({ error: 'Username and HWID are required' });
    }
    
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Если у пользователя нет HWID, разрешаем привязку
    if (!user.hwid || user.hwid === "") {
      return res.json({ 
        canBind: true, 
        message: 'HWID can be bound to this account',
        currentHwid: user.hwid || ""
      });
    }
    
    // Если HWID уже привязан, проверяем соответствие
    if (user.hwid === hwid) {
      return res.json({ 
        canBind: true, 
        message: 'HWID matches',
        currentHwid: user.hwid
      });
    } else {
      return res.status(403).json({ 
        canBind: false, 
        error: 'Account is bound to another computer',
        currentHwid: user.hwid
      });
    }
  } catch (error) {
    console.error('HWID check error:', error);
    res.status(500).json({ error: 'Internal server error during HWID check' });
  }
});

// Middleware для логирования запросов
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
});

// Middleware для проверки админ-прав
const requireAdmin = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user || user.accountType !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Middleware для логирования админ-действий
const logAdminAction = async (adminId, action, target, details) => {
  try {
    await AdminLog.create({
      adminId,
      action,
      target,
      details
    });
  } catch (error) {
    console.error('Error logging admin action:', error);
  }
};

// Функция для генерации лицензионного ключа
function generateLicenseKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < 16; i++) {
    if (i > 0 && i % 4 === 0) result += '-';
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// Эндпоинты для Minecraft файлов
app.get('/minecraft/files', async (req, res) => {
  try {
    const files = await MinecraftFile.find({ isActive: true }).sort({ version: 1, uploadDate: -1 });
    res.json(files);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch files' });
  }
});

app.get('/minecraft/files/:version', async (req, res) => {
  try {
    const file = await MinecraftFile.findOne({ 
      version: req.params.version, 
      isActive: true 
    }).sort({ uploadDate: -1 });
    
    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    res.json(file);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch file' });
  }
});

// Админ эндпоинты для управления Minecraft файлами
app.post('/admin/minecraft/upload', requireAdmin, async (req, res) => {
  try {
    const { version, fileName, fileUrl, fileSize, checksum, description, changelog } = req.body;
    
    const file = await MinecraftFile.create({
      version,
      fileName,
      fileUrl,
      fileSize,
      checksum,
      description,
      changelog
    });
    
    await logAdminAction(req.user._id, 'UPLOAD_MINECRAFT', version, `Uploaded ${fileName}`);
    
    res.json(file);
  } catch (error) {
    res.status(500).json({ error: 'Failed to upload file' });
  }
});

app.put('/admin/minecraft/:id', requireAdmin, async (req, res) => {
  try {
    const file = await MinecraftFile.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );
    
    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    await logAdminAction(req.user._id, 'UPDATE_MINECRAFT', file.version, `Updated ${file.fileName}`);
    
    res.json(file);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update file' });
  }
});

app.delete('/admin/minecraft/:id', requireAdmin, async (req, res) => {
  try {
    const file = await MinecraftFile.findByIdAndUpdate(
      req.params.id,
      { isActive: false },
      { new: true }
    );
    
    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    await logAdminAction(req.user._id, 'DELETE_MINECRAFT', file.version, `Deleted ${file.fileName}`);
    
    res.json({ message: 'File deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete file' });
  }
});

// Эндпоинты для лицензионных ключей
app.post('/admin/keys/generate', requireAdmin, async (req, res) => {
  try {
    const { type, duration, maxUses = 1, count = 1 } = req.body;
    
    const keys = [];
    for (let i = 0; i < count; i++) {
      const key = generateLicenseKey();
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + duration);
      
      const licenseKey = await LicenseKey.create({
        key,
        type,
        duration,
        maxUses,
        createdBy: req.user._id,
        expiresAt
      });
      
      keys.push(licenseKey);
    }
    
    await logAdminAction(req.user._id, 'GENERATE_KEYS', type, `Generated ${count} keys`);
    
    res.json(keys);
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate keys' });
  }
});

app.get('/admin/keys', requireAdmin, async (req, res) => {
  try {
    const keys = await LicenseKey.find()
      .populate('createdBy', 'username')
      .populate('usedBy', 'username')
      .sort({ createdAt: -1 });
    
    res.json(keys);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch keys' });
  }
});

app.post('/admin/keys/:id/disable', requireAdmin, async (req, res) => {
  try {
    const key = await LicenseKey.findByIdAndUpdate(
      req.params.id,
      { isActive: false },
      { new: true }
    );
    
    if (!key) {
      return res.status(404).json({ error: 'Key not found' });
    }
    
    await logAdminAction(req.user._id, 'DISABLE_KEY', key.key, 'Key disabled');
    
    res.json({ message: 'Key disabled successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to disable key' });
  }
});

// Эндпоинт для активации ключа пользователем
app.post('/activate-key', async (req, res) => {
  try {
    const { key } = req.body;
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    
    const licenseKey = await LicenseKey.findOne({ key, isActive: true });
    
    if (!licenseKey) {
      return res.status(404).json({ error: 'Invalid or expired key' });
    }
    
    if (licenseKey.usedCount >= licenseKey.maxUses) {
      return res.status(400).json({ error: 'Key usage limit exceeded' });
    }
    
    if (licenseKey.expiresAt && licenseKey.expiresAt < new Date()) {
      return res.status(400).json({ error: 'Key has expired' });
    }
    
    // Обновляем пользователя
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + licenseKey.duration);
    
    await User.findByIdAndUpdate(user._id, {
      accountType: licenseKey.type,
      licenseKey: key,
      licenseExpiry: expiryDate
    });
    
    // Обновляем ключ
    await LicenseKey.findByIdAndUpdate(licenseKey._id, {
      $inc: { usedCount: 1 },
      $push: { usedBy: user._id }
    });
    
    res.json({ 
      message: 'Key activated successfully',
      accountType: licenseKey.type,
      expiryDate: expiryDate
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to activate key' });
  }
});

// Админ эндпоинты для управления пользователями
app.get('/admin/users', requireAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ registrationDate: -1 });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.put('/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    const { accountType, status } = req.body;
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { accountType, status },
      { new: true }
    ).select('-password');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    await logAdminAction(req.user._id, 'UPDATE_USER', user.username, `Updated to ${accountType}`);
    
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update user' });
  }
});

app.get('/admin/logs', requireAdmin, async (req, res) => {
  try {
    const logs = await AdminLog.find()
      .populate('adminId', 'username')
      .sort({ timestamp: -1 })
      .limit(100);
    
    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch logs' });
  }
});

// Обработчик ошибок
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// Обработчик 404
app.use((req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

app.listen(process.env.PORT || 3000, () => {
    console.log('Server started on port', process.env.PORT || 3000);
    console.log('MongoDB URL:', process.env.MONGO_URL ? 'Configured' : 'Not configured');
}); 
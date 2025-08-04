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
  accountType: String
});
const User = mongoose.model('User', UserSchema);

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
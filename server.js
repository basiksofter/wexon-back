const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

mongoose.connect(process.env.MONGO_URL);

const UserSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  registrationDate: Date,
  lastLogin: Date,
  status: String,
  accountType: String
});
const User = mongoose.model('User', UserSchema);

const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';

app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (await User.findOne({ username })) return res.status(400).json({ error: 'Username exists' });
  if (await User.findOne({ email })) return res.status(400).json({ error: 'Email exists' });
  const hash = await bcrypt.hash(password, 10);
  const user = await User.create({
    username, email, password: hash,
    registrationDate: new Date(),
    lastLogin: new Date(),
    status: 'active',
    accountType: 'basic'
  });
  res.json({ id: user._id, username: user.username, email: user.email });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(400).json({ error: 'User not found' });
  if (!(await bcrypt.compare(password, user.password))) return res.status(400).json({ error: 'Wrong password' });
  user.lastLogin = new Date();
  await user.save();
  const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user._id, username: user.username, email: user.email } });
});

app.get('/me', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  try {
    const { id } = jwt.verify(auth.split(' ')[1], JWT_SECRET);
    const user = await User.findById(id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ id: user._id, username: user.username, email: user.email });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.listen(process.env.PORT || 3000, () => console.log('Server started'));
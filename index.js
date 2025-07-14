// index.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI);

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  approved: Boolean,
  role: { type: String, default: 'user' },
  balance: { type: Number, default: 0 },
  transactions: [{ type: mongoose.Schema.Types.Mixed }]
});
const User = mongoose.model('User', userSchema);

app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  const exists = await User.findOne({ email });
  if (exists) return res.status(400).send('Email already exists');
  const hashed = await bcrypt.hash(password, 10);
  await User.create({ name, email, password: hashed, approved: false });
  res.send('Registration submitted. Await admin approval.');
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).send('Invalid');
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).send('Invalid');
  if (!user.approved) return res.status(403).send('Awaiting approval');
  const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET);
  res.json({ token, name: user.name, email: user.email, balance: user.balance });
});

function auth(role) {
  return (req, res, next) => {
    try {
      const decoded = jwt.verify(req.header('Authorization'), process.env.JWT_SECRET);
      if (role && decoded.role !== role) return res.status(403).send('Forbidden');
      req.user = decoded;
      next();
    } catch (err) {
      res.status(401).send('Unauthorized');
    }
  };
}

app.get('/admin/pending', auth('admin'), async (req, res) => {
  const users = await User.find({ approved: false });
  res.json(users);
});

app.post('/admin/approve/:id', auth('admin'), async (req, res) => {
  await User.findByIdAndUpdate(req.params.id, { approved: true });
  res.send('User approved');
});

app.post('/transaction', auth(), async (req, res) => {
  const { type, amount } = req.body;
  const user = await User.findById(req.user.id);
  if (type === 'withdraw' && user.balance < amount) return res.status(400).send('Insufficient funds');
  user.balance += type === 'deposit' ? amount : -amount;
  user.transactions.push({ type, amount, date: new Date() });
  await user.save();
  res.send('Transaction successful');
});

app.get('/me', auth(), async (req, res) => {
  const user = await User.findById(req.user.id);
  res.json({ name: user.name, balance: user.balance, transactions: user.transactions });
});

(async () => {
  const exists = await User.findOne({ email: 'admin@newportbank.com' });
  if (!exists) {
    const hashed = await bcrypt.hash('admin123', 10);
    await User.create({
      name: 'Admin',
      email: 'admin@newportbank.com',
      password: hashed,
      approved: true,
      role: 'admin'
    });
  }
})();

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || "mongodb+srv://akilanirmal2020:d1QbcRXU2aS10Dqe@cluster0.rm7l3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => console.error('❌ MongoDB Connection Error:', err));


// User Schema
const userSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  username: { type: String, unique: true },
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ['patient', 'pharmacy', 'admin'] },
  pharmacyName: String,
  address: String,
  latitude: String,
  longitude: String,
  isActive: { type: Boolean, default: true }
});

// Medicine Schema
const medicineSchema = new mongoose.Schema({
  name: { type: String, required: true },
  dosage: { type: String, required: true },
  price: { type: Number, required: true },
  quantity: { type: Number, required: true },
  description: String,
  category: String,
  expiryDate: Date,
  isAvailable: { type: Boolean, default: true },
  pharmacyId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Medicine = mongoose.model('Medicine', medicineSchema);

// Pharmacy middleware with token parsing inside
const pharmacyMiddleware = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ message: 'No token provided' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    const user = await User.findById(decoded._id);
    if (!user || user.role !== 'pharmacy') {
      return res.status(403).json({ message: 'Access denied. Pharmacy owners only.' });
    }

    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid or expired token' });
  }
};

// Auth routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, username, password, role } = req.body;

    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      ...req.body,
      password: hashedPassword
    });

    await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error registering user', error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password, role } = req.body;

    const user = await User.findOne({ email, role });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { _id: user._id, role: user.role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.json({ token, user: { id: user._id, role: user.role, email: user.email } });
  } catch (err) {
    res.status(500).json({ message: 'Error logging in', error: err.message });
  }
});

// Medicine routes
app.get('/api/medicines', pharmacyMiddleware, async (req, res) => {
  try {
    const medicines = await Medicine.find({ pharmacyId: req.user._id });
    res.json(medicines);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching medicines', error: err.message });
  }
});

app.post('/api/medicines', pharmacyMiddleware, async (req, res) => {
  try {
    const medicine = new Medicine({
      ...req.body,
      pharmacyId: req.user._id
    });
    await medicine.save();
    res.status(201).json(medicine);
  } catch (err) {
    res.status(500).json({ message: 'Error adding medicine', error: err.message });
  }
});

app.put('/api/medicines/:id', pharmacyMiddleware, async (req, res) => {
  try {
    const medicine = await Medicine.findOneAndUpdate(
      { _id: req.params.id, pharmacyId: req.user._id },
      { ...req.body, updatedAt: Date.now() },
      { new: true }
    );

    if (!medicine) {
      return res.status(404).json({ message: 'Medicine not found' });
    }

    res.json(medicine);
  } catch (err) {
    res.status(500).json({ message: 'Error updating medicine', error: err.message });
  }
});

app.delete('/api/medicines/:id', pharmacyMiddleware, async (req, res) => {
  try {
    const medicine = await Medicine.findOneAndDelete({
      _id: req.params.id,
      pharmacyId: req.user._id
    });

    if (!medicine) {
      return res.status(404).json({ message: 'Medicine not found' });
    }

    res.json({ message: 'Medicine deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error deleting medicine', error: err.message });
  }
});

app.post('/api/medicines/bulk', pharmacyMiddleware, async (req, res) => {
  try {
    const medicines = req.body.map(medicine => ({
      ...medicine,
      pharmacyId: req.user._id
    }));

    const result = await Medicine.insertMany(medicines);
    res.status(201).json({
      message: 'Bulk import successful',
      count: result.length
    });
  } catch (err) {
    res.status(500).json({ message: 'Error in bulk import', error: err.message });
  }
});

// Public routes
app.get('/api/medicines/pharmacy/:pharmacyId', async (req, res) => {
  try {
    const medicines = await Medicine.find({
      pharmacyId: req.params.pharmacyId,
      isAvailable: true
    });
    res.json(medicines);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching medicines', error: err.message });
  }
});

app.get('/api/medicines/search', async (req, res) => {
  try {
    const { query } = req.query;
    const medicines = await Medicine.find({
      $or: [
        { name: { $regex: query, $options: 'i' } },
        { category: { $regex: query, $options: 'i' } },
        { description: { $regex: query, $options: 'i' } }
      ],
      isAvailable: true
    }).populate('pharmacyId', 'pharmacyName address latitude longitude');

    res.json(medicines);
  } catch (err) {
    res.status(500).json({ message: 'Error searching medicines', error: err.message });
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

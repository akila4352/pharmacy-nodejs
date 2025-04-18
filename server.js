require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || "mongodb+srv://akilanirmal2020:d1QbcRXU2aS10Dqe@cluster0.rm7l3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => console.error('❌ MongoDB Connection Error:', err));

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your_default_secret';

// User Schema
const userSchema = new mongoose.Schema({
    firstName: String,
    lastName: String,
    username: String,
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        enum: ['patient', 'pharmacy', 'admin'],
        default: 'patient'
    },
    pharmacyDetails: {
        pharmacyName: String,
        address: String,
        medicineName: String,
        price: Number,
        latitude: String,
        longitude: String,
        isAvailable: {
            type: Boolean,
            default: true
        }
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Password hash
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

// Compare password method
userSchema.methods.comparePassword = function(candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// Pharmacy Schema
const pharmacySchema = new mongoose.Schema({
    name: String,
    address: String,
    medicineName: String,
    price: Number,
    isAvailable: { type: Boolean, default: true },
    location: {
        type: { type: String, default: 'Point' },
        coordinates: [Number]
    }
});
pharmacySchema.index({ location: '2dsphere' });
const Pharmacy = mongoose.model('Pharmacy', pharmacySchema);

// Register Endpoint
app.post('/api/auth/register', async (req, res) => {
    try {
        const {
            firstName, lastName, username, email, password, role,
            adminCode, pharmacyName, address, medicineName,
            price, latitude, longitude, isAvailable
        } = req.body;

        if (await User.findOne({ email })) {
            return res.status(400).json({ message: 'User already exists' });
        }

        if (role === 'admin' && adminCode !== '1234') {
            return res.status(400).json({ message: 'Invalid admin code' });
        }

        if (role === 'pharmacy') {
            if (!pharmacyName || !address || !medicineName || !price || !latitude || !longitude) {
                return res.status(400).json({ message: 'All pharmacy fields are required' });
            }
        }

        const newUser = new User({
            firstName,
            lastName,
            username,
            email,
            password,
            role,
            ...(role === 'pharmacy' && {
                pharmacyDetails: {
                    pharmacyName,
                    address,
                    medicineName,
                    price,
                    latitude,
                    longitude,
                    isAvailable
                }
            })
        });

        await newUser.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Login Endpoint
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password, role } = req.body;
        const user = await User.findOne({ email });

        if (!user) return res.status(404).json({ message: 'User not found' });

        const isMatch = await user.comparePassword(password);
        if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

        if (user.role !== role) {
            return res.status(401).json({
                message: 'Invalid role selected. Please select the correct role for your account.'
            });
        }

        const token = jwt.sign(
            { id: user._id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                email: user.email,
                role: user.role,
                firstName: user.firstName,
                lastName: user.lastName
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Add Pharmacy Endpoint (Corrected)
app.post('/api/pharmacies', async (req, res) => {
    try {
        const { name, address, medicineName, price, isAvailable, location } = req.body;
        
        // Validate that location contains valid coordinates
        if (!location || !location.coordinates || location.coordinates.length !== 2 ||
            isNaN(parseFloat(location.coordinates[0])) || isNaN(parseFloat(location.coordinates[1]))) {
            return res.status(400).json({ error: 'Invalid location coordinates' });
        }
        
        // Create new pharmacy
        const pharmacy = new Pharmacy({
            name,
            address,
            medicineName,
            price: parseFloat(price),
            isAvailable: Boolean(isAvailable),
            location: {
                type: 'Point',
                coordinates: [
                    parseFloat(location.coordinates[0]), 
                    parseFloat(location.coordinates[1])
                ]
            }
        });
        
        await pharmacy.save();
        res.status(201).json(pharmacy);
    } catch (err) {
        console.error('Error creating pharmacy:', err);
        res.status(500).json({ error: err.message });
    }
});

// Search Nearby Pharmacies
app.get('/api/pharmacies/search', async (req, res) => {
    try {
        const { latitude, longitude, medicineName } = req.query;

        const pharmacies = await Pharmacy.find({
            location: {
                $nearSphere: {
                    $geometry: {
                        type: 'Point',
                        coordinates: [parseFloat(longitude), parseFloat(latitude)]
                    },
                    $maxDistance: 10000 // 10km
                }
            },
            isAvailable: true,
            medicineName: new RegExp(medicineName, 'i')
        });

        res.json(pharmacies);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update Pharmacy
app.put('/api/pharmacies/:id', async (req, res) => {
    try {
        const updated = await Pharmacy.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.json(updated || { message: 'Not found' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete Pharmacy
app.delete('/api/pharmacies/:id', async (req, res) => {
    try {
        const deleted = await Pharmacy.findByIdAndDelete(req.params.id);
        res.json(deleted ? { message: 'Deleted' } : { message: 'Not found' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Server Start
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
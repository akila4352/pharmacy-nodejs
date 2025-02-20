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

// Updated User Schema
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
    // Pharmacy specific fields
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


// Hash password before saving
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (err) {
        next(err);
    }
});

// Compare passwords
userSchema.methods.comparePassword = async function(candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// Updated Register endpoint
app.post('/api/auth/register', async (req, res) => {
    try {
        const { 
            firstName, 
            lastName, 
            username, 
            email, 
            password, 
            role,
            adminCode,
            pharmacyName,
            address,
            medicineName,
            price,
            latitude,
            longitude,
            isAvailable
        } = req.body;

        // Check if user exists
        if (await User.findOne({ email })) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Validate admin registration
        if (role === 'admin' && adminCode !== '1234') {
            return res.status(400).json({ message: 'Invalid admin code' });
        }

        // Validate pharmacy registration
        if (role === 'pharmacy') {
            if (!pharmacyName || !address || !medicineName || !price || !latitude || !longitude) {
                return res.status(400).json({ 
                    message: 'All pharmacy fields are required' 
                });
            }
        }

        // Create new user with role-specific data
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


// Updated Login User with role verification
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password, role } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // First verify the password
        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Then verify the role
        if (user.role !== role) {
            return res.status(401).json({ 
                message: 'Invalid role selected. Please select the correct role for your account.' 
            });
        }

        // If both password and role are correct, generate token
        const token = jwt.sign(
            { 
                id: user._id, 
                email: user.email, 
                role: user.role 
            }, 
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


// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
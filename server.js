require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const FormData = require('form-data');
const vision = require('@google-cloud/vision');
const axios = require('axios');
const nodemailer = require('nodemailer');

const upload = multer({ dest: 'uploads/' });

const app = express();

// Middleware
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://pharmacy-krpq-eqgupb0na-akilas-projects-cefe165a.vercel.app'
  ],
  credentials: true,
}));
app.use(express.json({ limit: "50mb" })); // Increase JSON payload limit
app.use(express.urlencoded({ limit: "50mb", extended: true })); // Increase URL-encoded payload limit

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
    name: String,
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
    phone: String,
    role: {
        type: String,
        enum: ['patient', 'pharmacy', 'admin'],
        default: 'patient'
    },
    isActive: {
        type: Boolean,
        default: true
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
    },
    isEmailVerified: { type: Boolean, default: false },
    otp: String,
    otpExpires: Date,
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
    ownerId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User' 
    },
    location: {
        type: { type: String, default: 'Point' },
        coordinates: [Number]
    },
    stock: [
        {
            medicineName: String,
            price: Number,
            isAvailable: { type: Boolean, default: true },
            quantity: { type: Number, default: 0 } // <-- add this
        }
    ],
    photoUrl: String, // <-- add this field
    createdAt: {
        type: Date,
        default: Date.now
    }
});

pharmacySchema.index({ location: '2dsphere' });
const Pharmacy = mongoose.model('Pharmacy', pharmacySchema);

// Pharmacy Calendar Schema
const pharmacyCalendarSchema = new mongoose.Schema({
    pharmacyId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Pharmacy',
        required: true,
    },
    date: {
        type: Date,
        required: true,
    },
    openingTime: {
        type: String,
        required: true,
    },
    closingTime: {
        type: String,
        required: true,
    },
    isAvailable: {
        type: Boolean,
        default: true,
    },
});

const PharmacyCalendar = mongoose.model('PharmacyCalendar', pharmacyCalendarSchema);

// Medicine Search Schema
const medicineSearchSchema = new mongoose.Schema({
    medicineName: { type: String, required: true, unique: true }, // Make unique
    count: { type: Number, default: 1 }, // Add count field
    searchedAt: { type: Date, default: Date.now }
});
const MedicineSearch = mongoose.model('MedicineSearch', medicineSearchSchema);

// Auth Middleware
const authMiddleware = (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ message: 'No token provided' });
        
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
};

// Nodemailer transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER, // set in .env
        pass: process.env.EMAIL_PASS  // set in .env
    }
});

// Add this check to log missing credentials for easier debugging
if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.error('❌ Missing EMAIL_USER or EMAIL_PASS in your environment variables (.env file).');
    // Optionally, you can exit the process if credentials are missing:
    // process.exit(1);
}

// Helper to send OTP email
async function sendOTPEmail(to, otp) {
    await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to,
        subject: 'Your OTP Verification Code',
        text: `Your OTP code is: ${otp}`
    });
}

// Helper to send low stock email
async function sendLowStockEmail(to, medicineName, quantity) {
    await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to,
        subject: `Low Stock Alert: ${medicineName}`,
        text: `Warning: The stock for "${medicineName}" is low (current quantity: ${quantity}). Please restock soon.`
    });
}

// Temporary in-memory store for pending registrations
const pendingRegistrations = {};

// Register Endpoint (store pending, don't save to DB yet)
app.post('/api/auth/register', async (req, res) => {
    try {
        const {
            firstName, lastName, username, email, password, phone, role,
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
            const missingFields = [];
            if (!pharmacyName) missingFields.push('pharmacyName');
            if (!address) missingFields.push('address');
            if (!medicineName) missingFields.push('medicineName');
            if (!price) missingFields.push('price');
            if (!latitude) missingFields.push('latitude');
            if (!longitude) missingFields.push('longitude');

            if (missingFields.length > 0) {
                return res.status(400).json({
                    message: `The following fields are required for pharmacy registration: ${missingFields.join(', ')}`
                });
            }
        }

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 min

        // Store all registration data in memory with OTP
        pendingRegistrations[email] = {
            firstName,
            lastName,
            name: `${firstName} ${lastName}`,
            username,
            email,
            password,
            phone,
            role,
            isActive: true,
            isEmailVerified: false,
            otp,
            otpExpires,
            pharmacyDetails: (role === 'pharmacy' ? {
                pharmacyName,
                address,
                medicineName,
                price,
                latitude,
                longitude,
                isAvailable
            } : undefined)
        };

        // Send OTP email
        await sendOTPEmail(email, otp);

        res.status(201).json({ message: 'OTP sent to email. Please verify to complete registration.' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Verify OTP Endpoint (save user to DB if OTP correct)
app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        const pending = pendingRegistrations[email];
        if (!pending) return res.status(404).json({ success: false, message: 'No pending registration found. Please register again.' });
        if (pending.otp !== otp) {
            return res.status(400).json({ success: false, message: 'Invalid OTP' });
        }
        if (pending.otpExpires < new Date()) {
            delete pendingRegistrations[email];
            return res.status(400).json({ success: false, message: 'OTP expired. Please register again.' });
        }

        // Save user to DB
        const userObj = { ...pending };
        delete userObj.otp;
        delete userObj.otpExpires;
        userObj.isEmailVerified = true;

        // Do NOT hash password here! Let the pre-save hook handle it.

        const newUser = new User(userObj);
        await newUser.save();

        // If user is a pharmacy owner, create pharmacy entry
        if (userObj.role === 'pharmacy') {
            const pd = userObj.pharmacyDetails;
            const newPharmacy = new Pharmacy({
                name: pd.pharmacyName,
                address: pd.address,
                ownerId: newUser._id,
                location: {
                    type: 'Point',
                    coordinates: [parseFloat(pd.longitude), parseFloat(pd.latitude)]
                },
                stock: [
                    {
                        medicineName: pd.medicineName,
                        price: parseFloat(pd.price),
                        isAvailable: pd.isAvailable !== false
                    }
                ]
            });
            await newPharmacy.save();
        }

        // Remove from pending
        delete pendingRegistrations[email];

        res.json({ success: true, message: 'Email verified and registration complete.' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// Resend OTP Endpoint (regenerate OTP for pending registration)
app.post('/api/auth/resend-otp', async (req, res) => {
    try {
        const { email } = req.body;
        const pending = pendingRegistrations[email];
        if (!pending) return res.status(404).json({ success: false, message: 'No pending registration found. Please register again.' });

        // Generate new OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 min
        pending.otp = otp;
        pending.otpExpires = otpExpires;

        await sendOTPEmail(email, otp);

        res.json({ success: true, message: 'OTP resent successfully' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// Login Endpoint
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password, role } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            console.log(`[LOGIN] User not found for email: ${email}`);
            return res.status(404).json({ message: 'User not found' });
        }

        // Add debug: show password hashes for troubleshooting
        // console.log(`[LOGIN] User password hash: ${user.password}`);
        // console.log(`[LOGIN] Provided password: ${password}`);

        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            console.log(`[LOGIN] Password mismatch for email: ${email}`);
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        if (user.role !== role) {
            console.log(`[LOGIN] Role mismatch for email: ${email}. Expected: ${user.role}, Provided: ${role}`);
            return res.status(401).json({
                message: 'Invalid role selected. Please select the correct role for your account.'
            });
        }

        if (!user.isActive) {
            return res.status(401).json({
                message: 'Your account has been deactivated. Please contact administrator.'
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
                lastName: user.lastName,
                name: user.name
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get All Users
app.get('/api/users', async (req, res) => {
    try {
        const users = await User.find().select('-password');
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get Pharmacy Owners - FIXED
app.get('/api/users/pharmacy-owners', async (req, res) => {
    try {
        const owners = await User.find({ role: 'pharmacy' }).select('-password');
        
        // Get pharmacy count for each owner
        const ownersWithCount = await Promise.all(owners.map(async (owner) => {
            const count = await Pharmacy.countDocuments({ ownerId: owner._id });
            return {
                ...owner.toObject(),
                pharmacyCount: count
            };
        }));
        
        res.json(ownersWithCount);
    } catch (err) {
        console.error('Error fetching pharmacy owners:', err);
        res.status(500).json({ error: err.message });
    }
});

// Get User by ID
app.get('/api/users/:id', async (req, res) => {
    try {
        // Ensure valid ObjectId
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ message: 'Invalid user ID format' });
        }
        
        const user = await User.findById(req.params.id).select('-password');
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.json(user);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update User
app.put('/api/users/:id', async (req, res) => {
    try {
        // Ensure valid ObjectId
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ message: 'Invalid user ID format' });
        }
        
        const { name, email, phone, role, firstName, lastName } = req.body;
        
        // Build update object
        const updateData = {};
        if (firstName) updateData.firstName = firstName;
        if (lastName) updateData.lastName = lastName;
        if (name) updateData.name = name;
        if (email) updateData.email = email;
        if (phone) updateData.phone = phone;
        if (role) updateData.role = role;
        
        const updatedUser = await User.findByIdAndUpdate(
            req.params.id,
            updateData,
            { new: true }
        ).select('-password');
        
        if (!updatedUser) return res.status(404).json({ message: 'User not found' });
        res.json(updatedUser);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete User
app.delete('/api/users/:id', async (req, res) => {
    try {
        // Ensure valid ObjectId
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ message: 'Invalid user ID format' });
        }
        
        const deletedUser = await User.findByIdAndDelete(req.params.id);
        if (!deletedUser) return res.status(404).json({ message: 'User not found' });
        
        // Also delete associated pharmacies if user is a pharmacy owner
        if (deletedUser.role === 'pharmacy') {
            await Pharmacy.deleteMany({ ownerId: deletedUser._id });
        }
        
        res.json({ message: 'User deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update User Status (Activate/Deactivate)
app.put('/api/users/:id/status', async (req, res) => {
    try {
        // Ensure valid ObjectId
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ message: 'Invalid user ID format' });
        }
        
        const { isActive } = req.body;
        
        const updatedUser = await User.findByIdAndUpdate(
            req.params.id,
            { isActive },
            { new: true }
        ).select('-password');
        
        if (!updatedUser) return res.status(404).json({ message: 'User not found' });
        res.json(updatedUser);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get All Pharmacies
app.get('/api/pharmacies', async (req, res) => {
    try {
        const pharmacies = await Pharmacy.find()
            .populate('ownerId', 'name email phone'); // Populate owner details
        res.json(pharmacies);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get Pharmacies by Owner
app.get('/api/pharmacies/owner/:ownerId', async (req, res) => {
    try {
        // Ensure valid ObjectId
        if (!mongoose.Types.ObjectId.isValid(req.params.ownerId)) {
            return res.status(400).json({ message: 'Invalid owner ID format' });
        }
        
        const pharmacy = await Pharmacy.findOne({ ownerId: req.params.ownerId });
        if (!pharmacy) return res.status(404).json({ message: 'Pharmacy not found' });

        res.json(pharmacy);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Search Pharmacies by Medicine Name (with or without location)
app.get('/api/pharmacies/search', async (req, res) => {
    try {
        const { latitude, longitude, medicineName } = req.query;

        let pharmacies = [];
        if (latitude && longitude) {
            // Nearby search
            const query = {
                location: {
                    $nearSphere: {
                        $geometry: {
                            type: 'Point',
                            coordinates: [parseFloat(longitude), parseFloat(latitude)]
                        },
                        $maxDistance: 10000 // 10km
                    }
                }
            };
            pharmacies = await Pharmacy.find(query).populate('ownerId', 'name email phone');
        } else {
            // All pharmacies
            pharmacies = await Pharmacy.find().populate('ownerId', 'name email phone');
        }

        // Filter by medicine name if provided
        let filteredPharmacies = pharmacies;
        if (medicineName) {
            filteredPharmacies = pharmacies.filter(pharmacy =>
                (pharmacy.stock || []).some(stockItem =>
                    stockItem.medicineName &&
                    stockItem.medicineName.toLowerCase() === medicineName.toLowerCase()
                )
            );
        }

        res.json(filteredPharmacies);
    } catch (err) {
        console.error('Error searching pharmacies:', err);
        res.status(500).json({ error: err.message });
    }
});

// Get Pharmacy by ID
app.get('/api/pharmacies/:id', async (req, res) => {
    try {
        // Ensure valid ObjectId
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ message: 'Invalid pharmacy ID format' });
        }
        
        const pharmacy = await Pharmacy.findById(req.params.id)
            .populate('ownerId', 'name email phone');
            
        if (!pharmacy) return res.status(404).json({ message: 'Pharmacy not found' });
        res.json(pharmacy);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Add Pharmacy
app.post('/api/pharmacies', async (req, res) => {
    try {
        const { name, address, ownerId, latitude, longitude, stock } = req.body;

        // Ensure valid ObjectId for owner
        if (!mongoose.Types.ObjectId.isValid(ownerId)) {
            return res.status(400).json({ message: 'Invalid owner ID format' });
        }

        // Check if owner exists and has pharmacy role
        const owner = await User.findById(ownerId);
        if (!owner) {
            return res.status(404).json({ message: 'Owner not found' });
        }
        if (owner.role !== 'pharmacy') {
            return res.status(400).json({ message: 'User is not a pharmacy owner' });
        }

        // Check if pharmacy already exists for the owner
        let pharmacy = await Pharmacy.findOne({ ownerId });
        if (pharmacy) {
            // Add new stock items to the existing pharmacy
            pharmacy.stock.push(...stock);
        } else {
            // Create new pharmacy with stock
            pharmacy = new Pharmacy({
                name,
                address,
                ownerId,
                location: {
                    type: 'Point',
                    coordinates: [parseFloat(longitude), parseFloat(latitude)]
                },
                stock
            });
        }

        await pharmacy.save();
        res.status(201).json(pharmacy);
    } catch (err) {
        console.error('Error creating pharmacy:', err);
        res.status(500).json({ error: err.message });
    }
});

// Update Pharmacy
app.put('/api/pharmacies/:id', async (req, res) => {
    try {
        // Ensure valid ObjectId
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ message: 'Invalid pharmacy ID format' });
        }
        
        const { name, address, latitude, longitude, stock } = req.body;
        
        const updateData = {};
        if (name) updateData.name = name;
        if (address) updateData.address = address;
        if (latitude !== undefined && longitude !== undefined) {
            updateData.location = {
                type: 'Point',
                coordinates: [parseFloat(longitude), parseFloat(latitude)]
            };
        }
        if (stock) updateData.stock = stock;
        
        const updated = await Pharmacy.findByIdAndUpdate(
            req.params.id, 
            updateData, 
            { new: true }
        );
        
        if (!updated) return res.status(404).json({ message: 'Pharmacy not found' });
        res.json(updated);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update Pharmacy Opening/Closing Times and Availability
app.put('/api/pharmacies/:id/calendar', async (req, res) => {
    try {
        const { openingTime, closingTime, isAvailable } = req.body;

        // Ensure valid ObjectId
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ message: 'Invalid pharmacy ID format' });
        }

        const updatedPharmacy = await Pharmacy.findByIdAndUpdate(
            req.params.id,
            { openingTime, closingTime, isAvailable },
            { new: true }
        );

        if (!updatedPharmacy) return res.status(404).json({ message: 'Pharmacy not found' });

        res.json(updatedPharmacy);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Add or Update Calendar Entry
app.post('/api/pharmacies/:id/calendar', async (req, res) => {
    try {
        const { id } = req.params;
        const { date, openingTime, closingTime, isAvailable } = req.body;

        // Ensure valid ObjectId
        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ message: 'Invalid pharmacy ID format' });
        }

        // Check if the pharmacy exists
        const pharmacy = await Pharmacy.findById(id);
        if (!pharmacy) {
            return res.status(404).json({ message: 'Pharmacy not found' });
        }

        // Upsert calendar entry
        const calendarEntry = await PharmacyCalendar.findOneAndUpdate(
            { pharmacyId: id, date },
            { openingTime, closingTime, isAvailable },
            { new: true, upsert: true }
        );

        res.status(200).json(calendarEntry);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get Calendar Entries for a Pharmacy
app.get('/api/pharmacies/:id/calendar', async (req, res) => {
    try {
        const { id } = req.params;

        // Ensure valid ObjectId
        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ message: 'Invalid pharmacy ID format' });
        }

        const calendarEntries = await PharmacyCalendar.find({ pharmacyId: id });
        res.status(200).json(calendarEntries);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete Pharmacy
app.delete('/api/pharmacies/:id', async (req, res) => {
    try {
        // Ensure valid ObjectId
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ message: 'Invalid pharmacy ID format' });
        }
        
        const deleted = await Pharmacy.findByIdAndDelete(req.params.id);
        if (!deleted) return res.status(404).json({ message: 'Pharmacy not found' });
        
        res.json({ message: 'Deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update Pharmacy Availability to Always Be "Available"
app.put('/api/pharmacies/fix-availability', async (req, res) => {
    try {
        await Pharmacy.updateMany({}, { isAvailable: true });
        res.json({ message: 'All pharmacies are now marked as available.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get Pharmacy Statistics
app.get('/api/stats', async (req, res) => {
    try {
        const totalPharmacies = await Pharmacy.countDocuments();
        const availableMedicines = await Pharmacy.countDocuments({ isAvailable: true });
        const totalUsers = await User.countDocuments();
        const totalOwners = await User.countDocuments({ role: 'pharmacy' });
        
        // Get unique medicine names
        const medicines = await Pharmacy.distinct('medicineName');
        
        res.json({
            totalPharmacies,
            totalMedicines: medicines.length,
            availableMedicines,
            totalUsers,
            totalOwners
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update Single Stock
app.post('/api/pharmacies/update-stock', authMiddleware, async (req, res) => {
    try {
        const { medicineName, price, isAvailable, quantity } = req.body;

        // Ensure the user is a pharmacy owner
        const pharmacy = await Pharmacy.findOne({ ownerId: req.user.id });
        if (!pharmacy) {
            return res.status(404).json({ message: "Pharmacy not found for this owner" });
        }

        // Check if the medicine already exists in the stock
        let existingMedicine = pharmacy.stock.find(
            (item) => item.medicineName.toLowerCase() === medicineName.toLowerCase()
        );

        let sendLowStock = false;
        let newQuantity = quantity !== undefined ? Number(quantity) : 0;

        if (existingMedicine) {
            // Update existing medicine
            existingMedicine.price = price;
            existingMedicine.isAvailable = isAvailable;
            if (quantity !== undefined) {
                existingMedicine.quantity = newQuantity;
            }
            if (existingMedicine.quantity !== undefined && existingMedicine.quantity < 100) {
                sendLowStock = true;
            }
        } else {
            // Add new medicine to stock
            pharmacy.stock.push({
                medicineName,
                price,
                isAvailable,
                quantity: newQuantity
            });
            if (newQuantity < 100) {
                sendLowStock = true;
            }
            existingMedicine = pharmacy.stock[pharmacy.stock.length - 1];
        }

        await pharmacy.save();

        // Always send low stock alert if quantity < 100
        if (sendLowStock) {
            const owner = await User.findById(pharmacy.ownerId);
            if (owner && owner.email) {
                await sendLowStockEmail(owner.email, existingMedicine.medicineName, existingMedicine.quantity);
            }
        }

        res.status(200).json({ message: "Stock updated successfully", pharmacy });
    } catch (err) {
        console.error("Error updating stock:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Update Bulk Stock
app.post('/api/pharmacies/update-stock-bulk', authMiddleware, async (req, res) => {
    try {
        const { stock } = req.body;

        // Ensure the user is a pharmacy owner
        const pharmacy = await Pharmacy.findOne({ ownerId: req.user.id });
        if (!pharmacy) {
            return res.status(404).json({ message: "Pharmacy not found for this owner" });
        }

        for (const newItem of stock) {
            let existingMedicine = pharmacy.stock.find(
                (item) => item.medicineName.toLowerCase() === newItem.medicineName.toLowerCase()
            );

            let sendLowStock = false;
            let newQuantity = newItem.quantity !== undefined ? Number(newItem.quantity) : 0;

            if (existingMedicine) {
                existingMedicine.price = newItem.price;
                existingMedicine.isAvailable = newItem.isAvailable;
                if (newItem.quantity !== undefined) {
                    existingMedicine.quantity = newQuantity;
                }
                if (existingMedicine.quantity !== undefined && existingMedicine.quantity < 100) {
                    sendLowStock = true;
                }
            } else {
                pharmacy.stock.push({
                    medicineName: newItem.medicineName,
                    price: newItem.price,
                    isAvailable: newItem.isAvailable,
                    quantity: newQuantity
                });
                if (newQuantity < 100) {
                    sendLowStock = true;
                }
                existingMedicine = pharmacy.stock[pharmacy.stock.length - 1];
            }

            // Always send low stock alert if quantity < 100
            if (sendLowStock) {
                const owner = await User.findById(pharmacy.ownerId);
                if (owner && owner.email) {
                    await sendLowStockEmail(owner.email, existingMedicine.medicineName, existingMedicine.quantity);
                }
            }
        }

        await pharmacy.save();
        res.status(200).json({ message: "Bulk stock updated successfully", pharmacy });
    } catch (err) {
        console.error("Error updating bulk stock:", err);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Prescription OCR endpoint using Google Gemini Vision 2.0 API
app.post('/api/prescription/scan', upload.single('prescription'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        // Only allow image files
        const allowedTypes = ['image/jpeg', 'image/png', 'image/jpg', 'image/bmp', 'image/gif', 'image/tiff', 'image/webp'];
        if (!allowedTypes.includes(req.file.mimetype)) {
            fs.unlink(req.file.path, () => {});
            return res.status(400).json({ error: 'Unsupported file type' });
        }

        // Read file and encode to base64
        const imageBuffer = fs.readFileSync(req.file.path);
        const base64Image = imageBuffer.toString('base64');

        // Clean up uploaded file
        fs.unlink(req.file.path, () => {});

        // Gemini Vision API endpoint and key
        const GEMINI_API_KEY = process.env.GEMINI_API_KEY || 'AIzaSyAquE8L7ug-kfoJ-s3b4WUDvUUZgCi_2cg';
        // Use the supported Gemini 1.5 model endpoint for vision (as of July 2024)
        // See: https://ai.google.dev/gemini-api/docs/models/gemini
        const geminiUrl = 'https://generativelanguage.googleapis.com/v1/models/gemini-1.5-flash:generateContent?key=' + GEMINI_API_KEY;

        // Prepare Gemini Vision API request
        const geminiReq = {
            contents: [
                {
                    parts: [
                        {
                            text: "Extract all readable text from this prescription image. Return only the text, no explanation."
                        },
                        {
                            inlineData: {
                                mimeType: req.file.mimetype,
                                data: base64Image
                            }
                        }
                    ]
                }
            ]
        };

        // Call Gemini Vision API
        let geminiRes;
        try {
            geminiRes = await axios.post(geminiUrl, geminiReq, {
                headers: { 'Content-Type': 'application/json' }
            });
        } catch (apiErr) {
            // Handle Gemini API errors (404, 401, etc.)
            const apiMessage = apiErr.response?.data?.error?.message || apiErr.message || "Gemini Vision API request failed";
            return res.status(apiErr.response?.status || 500).json({ error: apiMessage });
        }

        // Parse Gemini response
        let rawText = '';
        if (
            geminiRes.data &&
            geminiRes.data.candidates &&
            geminiRes.data.candidates.length > 0 &&
            geminiRes.data.candidates[0].content &&
            geminiRes.data.candidates[0].content.parts &&
            geminiRes.data.candidates[0].content.parts.length > 0
        ) {
            rawText = geminiRes.data.candidates[0].content.parts[0].text || '';
        }

        res.json({ rawText });
    } catch (err) {
        if (req.file?.path) {
            fs.unlink(req.file.path, () => {});
        }
        res.status(500).json({ error: err.message });
    }
});

// In-memory store for password reset OTPs
const passwordResetOtps = {};

// Forgot Password Endpoint (send OTP)
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 min

        passwordResetOtps[email] = { otp, otpExpires };

        await sendOTPEmail(email, otp);

        res.json({ success: true, message: 'OTP sent to your email.' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// Reset Password Endpoint (verify OTP and set new password)
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });

        const record = passwordResetOtps[email];
        if (!record) return res.status(400).json({ success: false, message: 'No OTP request found. Please request again.' });
        if (record.otp !== otp) return res.status(400).json({ success: false, message: 'Invalid OTP' });
        if (record.otpExpires < new Date()) {
            delete passwordResetOtps[email];
            return res.status(400).json({ success: false, message: 'OTP expired. Please request again.' });
        }

        // Update password (ensure pre-save hook is called)
        user.password = newPassword;
        await user.save();

        delete passwordResetOtps[email];

        res.json({ success: true, message: 'Password reset successful. You can now login.' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// Save medicine search (increment count or create new)
app.post('/api/medicine-search', async (req, res) => {
    try {
        let { medicineName } = req.body;
        if (!medicineName) return res.status(400).json({ message: "medicineName required" });
        medicineName = medicineName.trim().toLowerCase();

        // Try to update count if exists, else insert new
        const result = await MedicineSearch.findOneAndUpdate(
            { medicineName },
            { $inc: { count: 1 }, $set: { searchedAt: new Date() } },
            { upsert: true, new: true }
        );
        res.json({ success: true, medicine: result });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Get all searched medicine names and their total search count (from all time)
app.get('/api/medicine-search/all', async (req, res) => {
    try {
        const medicines = await MedicineSearch.find({}, { _id: 0, medicineName: 1, count: 1 }).sort({ count: -1 });
        res.json({
            medicines: medicines.map(m => ({
                name: m.medicineName,
                count: m.count
            }))
        });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Medicine name suggestions endpoint for autocomplete
app.get('/api/medicines/suggestions', async (req, res) => {
    try {
        const { query } = req.query;
        if (!query || !query.trim()) {
            return res.json([]);
        }
        // Find medicine names starting with the query, sorted by count
        const suggestions = await MedicineSearch.find(
            { medicineName: { $regex: '^' + query.trim().toLowerCase(), $options: 'i' } },
            { _id: 0, medicineName: 1 }
        )
        .sort({ count: -1 })
        .limit(10);

        res.json(suggestions.map(m => m.medicineName));
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({ message: err.message || "Internal Server Error" });
});

// Catch-all route for undefined endpoints
app.use((req, res) => {
  res.status(404).json({ message: "Endpoint not found" });
});

// Serve uploaded images statically
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Upload/update pharmacy photo endpoint
app.post('/api/pharmacies/:id/photo', upload.single('photo'), async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            if (req.file?.path) fs.unlink(req.file.path, () => {});
            return res.status(400).json({ message: 'Invalid pharmacy ID format' });
        }
        if (!req.file) {
            return res.status(400).json({ message: 'No file uploaded' });
        }
        // Only allow image files
        const allowedTypes = ['image/jpeg', 'image/png', 'image/jpg', 'image/bmp', 'image/gif', 'image/tiff', 'image/webp'];
        if (!allowedTypes.includes(req.file.mimetype)) {
            fs.unlink(req.file.path, () => {});
            return res.status(400).json({ message: 'Unsupported file type' });
        }

        // Move file to /uploads with a unique name
        const ext = path.extname(req.file.originalname) || '.jpg';
        const newFilename = `pharmacy_${req.params.id}_${Date.now()}${ext}`;
        const newPath = path.join(__dirname, 'uploads', newFilename);
        fs.renameSync(req.file.path, newPath);

        // Build the public URL
        const photoUrl = `/uploads/${newFilename}`;

        // Update pharmacy document
        const updated = await Pharmacy.findByIdAndUpdate(
            req.params.id,
            { photoUrl },
            { new: true }
        );
        if (!updated) {
            fs.unlink(newPath, () => {});
            return res.status(404).json({ message: 'Pharmacy not found' });
        }
        res.json(updated);
    } catch (err) {
        if (req.file?.path) fs.unlink(req.file.path, () => {});
        res.status(500).json({ message: err.message });
    }
});

// Get current pharmacy for logged-in owner (for dashboard profile)
app.get('/api/pharmacies/my', async (req, res) => {
    try {
        // For demo, get first pharmacy (replace with auth in production)
        const pharmacy = await Pharmacy.findOne();
        if (!pharmacy) return res.status(404).json({ message: 'Pharmacy not found' });
        res.json(pharmacy);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Server Start
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
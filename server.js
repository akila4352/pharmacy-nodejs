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

const upload = multer({ dest: 'uploads/' });

const app = express();

// Middleware
app.use(cors());
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
            isAvailable: { type: Boolean, default: true }
        }
    ],
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

// Register Endpoint
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

        const newUser = new User({
            firstName,
            lastName,
            name: `${firstName} ${lastName}`,
            username,
            email,
            password,
            phone,
            role,
            isActive: true,
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
        
        // If user is a pharmacy owner, create a pharmacy entry as well
        if (role === 'pharmacy') {
            const newPharmacy = new Pharmacy({
                name: pharmacyName,
                address,
                ownerId: newUser._id,
                location: {
                    type: 'Point',
                    coordinates: [parseFloat(longitude), parseFloat(latitude)]
                },
                stock: [
                    {
                        medicineName,
                        price: parseFloat(price),
                        isAvailable: isAvailable !== false
                    }
                ]
            });
            await newPharmacy.save();
        }
        
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
        const { medicineName, price, isAvailable } = req.body;

        // Ensure the user is a pharmacy owner
        const pharmacy = await Pharmacy.findOne({ ownerId: req.user.id });
        if (!pharmacy) {
            return res.status(404).json({ message: "Pharmacy not found for this owner" });
        }

        // Check if the medicine already exists in the stock
        const existingMedicine = pharmacy.stock.find(
            (item) => item.medicineName.toLowerCase() === medicineName.toLowerCase()
        );

        if (existingMedicine) {
            // Update existing medicine
            existingMedicine.price = price;
            existingMedicine.isAvailable = isAvailable;
        } else {
            // Add new medicine to stock
            pharmacy.stock.push({ medicineName, price, isAvailable });
        }

        await pharmacy.save();
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

        // Update or add each medicine in the stock
        stock.forEach((newItem) => {
            const existingMedicine = pharmacy.stock.find(
                (item) => item.medicineName.toLowerCase() === newItem.medicineName.toLowerCase()
            );

            if (existingMedicine) {
                // Update existing medicine
                existingMedicine.price = newItem.price;
                existingMedicine.isAvailable = newItem.isAvailable;
            } else {
                // Add new medicine to stock
                pharmacy.stock.push(newItem);
            }
        });

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

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({ message: err.message || "Internal Server Error" });
});

// Catch-all route for undefined endpoints
app.use((req, res) => {
  res.status(404).json({ message: "Endpoint not found" });
});

// Server Start
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
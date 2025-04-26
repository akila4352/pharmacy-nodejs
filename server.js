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

// Process Prescription Endpoint
app.post('/api/process-prescription', async (req, res) => {
    try {
        const { imageText, userLocation } = req.body;
        
        if (!imageText || !imageText.trim()) {
            return res.status(400).json({ message: 'No text detected in the prescription' });
        }

        // Extract medicine names from the detected text
        // This is a simple implementation - in a production environment, 
        // you would use NLP or a more sophisticated algorithm
        const detectedMedicines = extractMedicineNames(imageText);
        
        if (!detectedMedicines || detectedMedicines.length === 0) {
            return res.status(404).json({ message: 'No medicines detected in the prescription' });
        }

        // Find pharmacies with the detected medicines
        const pharmaciesWithMedicines = await findPharmaciesWithMedicines(detectedMedicines, userLocation);
        
        res.json({
            detectedMedicines,
            pharmacies: pharmaciesWithMedicines
        });
    } catch (error) {
        console.error('Prescription processing error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Helper function to extract medicine names from prescription text
function extractMedicineNames(text) {
    // Split the text into lines and words
    const words = text.toLowerCase().split(/[\s,;]+/);
    
    // Filter out common words that are likely not medicine names
    // This is a simplified approach - a real implementation would use a database of medicine names
    const commonWords = ['prescription', 'mg', 'ml', 'tablet', 'capsule', 'syrup', 'take', 'daily', 'times', 
                        'day', 'patient', 'name', 'doctor', 'hospital', 'date', 'dose'];
    
    // Extract potential medicine names (words with 4+ characters not in common words)
    const potentialMedicines = words.filter(word => 
        word.length >= 4 && 
        !commonWords.includes(word) &&
        !/^\d+$/.test(word) // Exclude numbers
    );
    
    // Return unique medicine names
    return [...new Set(potentialMedicines)];
}

// Helper function to find pharmacies with specified medicines
async function findPharmaciesWithMedicines(medicines, userLocation) {
    try {
        // Default search radius in meters (10km)
        const maxDistance = 10000;
        
        // If user location provided, search nearby pharmacies
        let query = { isAvailable: true };
        
        // Create regex OR condition for medicine names
        const medicineRegexes = medicines.map(med => new RegExp(med, 'i'));
        query.medicineName = { $in: medicineRegexes };
        
        // Add geospatial query if user location is provided
        if (userLocation && userLocation.latitude && userLocation.longitude) {
            query.location = {
                $nearSphere: {
                    $geometry: {
                        type: 'Point',
                        coordinates: [parseFloat(userLocation.longitude), parseFloat(userLocation.latitude)]
                    },
                    $maxDistance: maxDistance
                }
            };
        }
        
        // Find pharmacies matching the criteria
        const pharmacies = await Pharmacy.find(query);
        
        return pharmacies.map(pharmacy => ({
            id: pharmacy._id,
            name: pharmacy.name,
            address: pharmacy.address,
            medicineName: pharmacy.medicineName,
            price: pharmacy.price,
            distance: userLocation ? calculateDistance(
                userLocation.latitude, 
                userLocation.longitude,
                pharmacy.location.coordinates[1],
                pharmacy.location.coordinates[0]
            ) : null
        }));
    } catch (error) {
        console.error('Error finding pharmacies:', error);
        return [];
    }
}

// Calculate distance between two points in kilometers
function calculateDistance(lat1, lon1, lat2, lon2) {
    const R = 6371; // Radius of the earth in km
    const dLat = deg2rad(lat2 - lat1);
    const dLon = deg2rad(lon2 - lon1); 
    const a = 
        Math.sin(dLat/2) * Math.sin(dLat/2) +
        Math.cos(deg2rad(lat1)) * Math.cos(deg2rad(lat2)) * 
        Math.sin(dLon/2) * Math.sin(dLon/2); 
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a)); 
    return R * c; // Distance in km
}

function deg2rad(deg) {
    return deg * (Math.PI/180);
}

// Server Start
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
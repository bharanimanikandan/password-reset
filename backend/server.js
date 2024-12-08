require("dotenv").config(); // For environment variables
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json()); // For parsing application/json data

// Environment Variables
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/password-reset";

// Connect to MongoDB
const connectDB = async () => {
    try {
        await mongoose.connect(MONGO_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 10000, // 10 seconds timeout
        });
        console.log("MongoDB Connected Successfully");
    } catch (err) {
        console.error("Error connecting to MongoDB:", err.message);
        process.exit(1); // Exit if MongoDB connection fails
    }
};
connectDB();

// User Model
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    resetToken: { type: String },
    resetTokenExpiration: { type: Date },
});
const User = mongoose.model("User", UserSchema);

// Routes
app.get("/", (req, res) => {
    res.send("Server is running");
});

// Register route
app.post("/auth/register", async (req, res) => {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
        return res.status(400).json({ error: "Please provide all required fields" });
    }

    try {
        // Check if user exists
        const userExists = await User.findOne({ email });
        if (userExists) {
            return res.status(400).json({ error: "User already exists" });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const user = new User({ email, password: hashedPassword });
        await user.save();

        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        console.error("Error during registration:", error);
        res.status(500).json({ error: "Internal server error during registration" });
    }
});

// Password Reset Flow: Request Password Reset
app.post("/auth/forgot-password", async (req, res) => {
    const { email } = req.body;

    try {
        // Check if user exists
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        // Generate reset token
        const resetToken = Math.random().toString(36).substring(2, 12); // Random token
        user.resetToken = resetToken;
        user.resetTokenExpiration = Date.now() + 3600000; // 1-hour expiration

        // Save the updated user
        await user.save();

        // Simulate sending email
        console.log(`Password reset link: http://localhost:${PORT}/auth/reset-password/${resetToken}`);
        res.status(200).json({ message: "Password reset link sent to your email" });
    } catch (err) {
        console.error("Error in forgot-password:", err.message);
        res.status(500).json({ message: "An error occurred", error: err.message });
    }
});

// Password Reset Flow: Reset Password
app.post("/auth/reset-password/:token", async (req, res) => {
    const { token } = req.params;
    const { newPassword } = req.body;

    try {
        // Find user with matching token and check expiration
        const user = await User.findOne({
            resetToken: token,
            resetTokenExpiration: { $gt: Date.now() }, // Token must not be expired
        });

        if (!user) {
            return res.status(400).json({ message: "Invalid or expired token" });
        }

        // Update password (hashing not implemented here; ensure hashing in production)
        user.password = await bcrypt.hash(newPassword, 10);
        user.resetToken = undefined;
        user.resetTokenExpiration = undefined;

        // Save the updated user
        await user.save();

        res.status(200).json({ message: "Password successfully reset" });
    } catch (err) {
        console.error("Error in reset-password:", err.message);
        res.status(500).json({ message: "An error occurred", error: err.message });
    }
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

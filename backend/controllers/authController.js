const crypto = require("crypto");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const sendEmail = require("../utils/sendEmail");

// Forget Password
exports.forgotPassword = async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (!user) return res.status(404).json({ message: "User not found" });

  const resetToken = crypto.randomBytes(32).toString("hex");
  user.resetToken = resetToken;
  user.resetTokenExpiry = Date.now() + 3600000; // 1 hour
  await user.save();

  const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
  await sendEmail(user.email, "Password Reset", `Click here to reset your password: ${resetLink}`);

  res.status(200).json({ message: "Password reset link sent to your email" });
};

// Reset Password
exports.resetPassword = async (req, res) => {
  const { token, password } = req.body;
  const user = await User.findOne({
    resetToken: token,
    resetTokenExpiry: { $gt: Date.now() },
  });

  if (!user) return res.status(400).json({ message: "Invalid or expired token" });

  user.password = password;
  user.resetToken = undefined;
  user.resetTokenExpiry = undefined;
  await user.save();

  res.status(200).json({ message: "Password reset successfully" });
};
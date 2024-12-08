const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const authRoutes = require("./routes/authRoutes");

const app = express();

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Routes
app.use("/auth", authRoutes);

module.exports = app;
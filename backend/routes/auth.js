const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const requireAuth = require("../middleware/requireAuth");

const router = express.Router();

// POST /auth/register
router.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ ok: false, message: "Email and password are required." });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res
        .status(409)
        .json({ ok: false, message: "Email already registered." });
    }

    const hashed = await bcrypt.hash(password, 12);
    const user = await User.create({ email, password: hashed });

    return res
      .status(201)
      .json({ ok: true, message: "Registered", userId: user._id });
  } catch (err) {
    console.error("Register error:", err);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});

// POST /auth/login
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ ok: false, message: "Email and password are required." });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res
        .status(401)
        .json({ ok: false, message: "Invalid credentials." });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res
        .status(401)
        .json({ ok: false, message: "Invalid credentials." });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "2h" }
    );

    return res.json({ ok: true, token });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});

// GET /auth/me (protected)
router.get("/me", requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-password");
    if (!user) {
      return res.status(404).json({ ok: false, message: "User not found" });
    }

    return res.json({
      ok: true,
      user: {
        id: user._id,
        email: user.email,
        createdAt: user.createdAt,
        hasPublicKey: !!user.publicKey,
      },
    });
  } catch (err) {
    console.error("Me route error:", err);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});

// POST /auth/public-key (save or update user's public key)
router.post("/public-key", requireAuth, async (req, res) => {
  try {
    const { publicKey } = req.body;

    if (!publicKey) {
      return res
        .status(400)
        .json({ ok: false, message: "publicKey is required" });
    }

    console.log("Saving public key for user:", req.user.userId);

    const user = await User.findByIdAndUpdate(
      req.user.userId,
      { publicKey },
      { new: true }
    ).select("-password");

    if (!user) {
      return res.status(404).json({ ok: false, message: "User not found" });
    }

    return res.json({
      ok: true,
      message: "Public key saved",
      publicKey: user.publicKey,
    });
  } catch (err) {
    console.error("Public key save error:", err);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});

// GET /auth/public-key/:email (get a user's public key by email)
router.get("/public-key/:email", requireAuth, async (req, res) => {
  try {
    const { email } = req.params;

    const user = await User.findOne({ email }).select("publicKey email");
    if (!user) {
      return res.status(404).json({ ok: false, message: "User not found" });
    }

    if (!user.publicKey) {
      return res
        .status(404)
        .json({ ok: false, message: "User has no public key set" });
    }

    return res.json({
      ok: true,
      email: user.email,
      publicKey: user.publicKey,
    });
  } catch (err) {
    console.error("Public key fetch error:", err);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});

module.exports = router;
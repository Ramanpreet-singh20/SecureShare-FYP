const express = require("express");
const requireAuth = require("../middleware/requireAuth");
const User = require("../models/User");
const Share = require("../models/Share");

const router = express.Router();

// POST /shares  (send encrypted text OR file)
router.post("/", requireAuth, async (req, res) => {
  try {
    const {
      recipientEmail,
      ciphertext,
      encryptedKey,
      iv,
      expiresInMinutes,
      isFile,
      fileName,
      fileType,
      fileSize,
    } = req.body;

    if (!recipientEmail || !ciphertext || !encryptedKey || !iv) {
      return res.status(400).json({
        ok: false,
        message:
          "recipientEmail, ciphertext, encryptedKey, and iv are required",
      });
    }

    const recipient = await User.findOne({ email: recipientEmail });
    if (!recipient) {
      return res
        .status(404)
        .json({ ok: false, message: "Recipient not found" });
    }

    let expiresAt = null;
    if (expiresInMinutes && Number.isFinite(expiresInMinutes)) {
      expiresAt = new Date(Date.now() + expiresInMinutes * 60 * 1000);
    }

    const share = await Share.create({
      sender: req.user.userId,
      recipient: recipient._id,
      ciphertext,
      encryptedKey,
      iv,
      expiresAt,
      isFile: !!isFile,
      fileName: isFile ? fileName : null,
      fileType: isFile ? fileType : null,
      fileSize: isFile ? fileSize : null,
    });

    return res.status(201).json({
      ok: true,
      message: "Encrypted share stored",
      shareId: share._id,
    });
  } catch (err) {
    console.error("Create share error:", err);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});

// GET /shares/inbox  (get encrypted messages/files for logged-in user)
router.get("/inbox", requireAuth, async (req, res) => {
  try {
    const now = new Date();

    const shares = await Share.find({
      recipient: req.user.userId,
      $or: [
        { expiresAt: null },
        { expiresAt: { $gt: now } }, // skip expired
      ],
    })
      .populate("sender", "email")
      .sort({ createdAt: -1 });

    const result = shares.map((s) => ({
      id: s._id,
      senderEmail: s.sender ? s.sender.email : "Unknown",
      ciphertext: s.ciphertext,
      encryptedKey: s.encryptedKey,
      iv: s.iv,
      isFile: s.isFile,
      fileName: s.fileName,
      fileType: s.fileType,
      fileSize: s.fileSize,
      createdAt: s.createdAt,
      expiresAt: s.expiresAt,
    }));

    return res.json({ ok: true, inbox: result });
  } catch (err) {
    console.error("Inbox error:", err);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});

module.exports = router;
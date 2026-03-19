const express = require("express");
const Share = require("../models/Share");
const User = require("../models/User");
const requireAuth = require("../middleware/requireAuth");

const router = express.Router();

// POST /shares
router.post("/", requireAuth, async (req, res) => {
  try {
    const {
      recipientEmail,
      ciphertext,
      encryptedKey,
      iv,
      isFile,
      fileName,
      fileType,
      fileSize,
      expiresInMinutes,
    } = req.body;

    if (!recipientEmail || !ciphertext || !encryptedKey || !iv) {
      return res.status(400).json({
        ok: false,
        message: "recipientEmail, ciphertext, encryptedKey and iv are required.",
      });
    }

    const recipient = await User.findOne({ email: recipientEmail });
    if (!recipient) {
      return res.status(404).json({
        ok: false,
        message: "Recipient not found.",
      });
    }

    let expiresAt = null;
    if (expiresInMinutes && Number(expiresInMinutes) > 0) {
      expiresAt = new Date(Date.now() + Number(expiresInMinutes) * 60 * 1000);
    }

    const share = await Share.create({
      sender: req.user.userId,
      recipient: recipient._id,
      ciphertext,
      encryptedKey,
      iv,
      isFile: !!isFile,
      fileName: isFile ? fileName : null,
      fileType: isFile ? fileType : null,
      fileSize: isFile ? fileSize : null,
      expiresAt,
    });

    return res.status(201).json({
      ok: true,
      message: "Share stored.",
      shareId: share._id,
    });
  } catch (err) {
    console.error("Create share error:", err);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});

// GET /shares/inbox
router.get("/inbox", requireAuth, async (req, res) => {
  try {
    const now = new Date();

    const shares = await Share.find({
      recipient: req.user.userId,
    })
      .populate("sender", "email")
      .sort({ createdAt: -1 });

    const inbox = shares.map((s) => ({
      id: s._id.toString(),
      senderEmail: s.sender?.email || "Unknown",
      ciphertext: s.ciphertext,
      encryptedKey: s.encryptedKey,
      iv: s.iv,
      isFile: s.isFile,
      fileName: s.fileName,
      fileType: s.fileType,
      fileSize: s.fileSize,
      createdAt: s.createdAt,
      expiresAt: s.expiresAt,
      isExpired: s.expiresAt ? s.expiresAt < now : false,
    }));

    return res.json({ ok: true, inbox });
  } catch (err) {
    console.error("Inbox error:", err);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});

// DELETE /shares/:id
router.delete("/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;

    const share = await Share.findById(id);
    if (!share) {
      return res.status(404).json({
        ok: false,
        message: "Share not found.",
      });
    }

    const userId = req.user.userId.toString();
    const isAllowed =
      share.sender.toString() === userId ||
      share.recipient.toString() === userId;

    if (!isAllowed) {
      return res.status(403).json({
        ok: false,
        message: "Not allowed to delete this share.",
      });
    }

    await share.deleteOne();

    return res.json({
      ok: true,
      message: "Share deleted.",
    });
  } catch (err) {
    console.error("Delete share error:", err);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});

module.exports = router;
const mongoose = require("mongoose");

const shareSchema = new mongoose.Schema({
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  recipient: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  // AES-GCM encrypted data (text or file) in base64
  ciphertext: {
    type: String,
    required: true,
  },
  // RSA-OAEP encrypted AES key (base64)
  encryptedKey: {
    type: String,
    required: true,
  },
  // AES-GCM IV (base64)
  iv: {
    type: String,
    required: true,
  },

  // ---- New fields for files ----
  isFile: {
    type: Boolean,
    default: false,
  },
  fileName: {
    type: String,
    default: null,
  },
  fileType: {
    type: String,
    default: null,
  },
  fileSize: {
    type: Number,
    default: null,
  },

  createdAt: {
    type: Date,
    default: Date.now,
  },
  expiresAt: {
    type: Date,
    default: null,
  },
});

shareSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
module.exports = mongoose.model("Share", shareSchema);
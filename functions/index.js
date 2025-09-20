const functions = require("firebase-functions");
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(cors({ origin: true }));
app.use(express.json());

// Get private key from functions config (recommended)
const IMAGEKIT_PRIVATE_KEY = functions.config().imagekit?.private_key || "";
const IMAGEKIT_PUBLIC_KEY = functions.config().imagekit?.public_key || "public_6MDkzxKFxdmlY1RsT/NsiyTLMmo=";
// optionally you can set a folder prefix or other defaults:
const DEFAULT_FOLDER = functions.config().imagekit?.folder || "";

if (!IMAGEKIT_PRIVATE_KEY) {
  console.warn("Warning: IMAGEKIT_PRIVATE_KEY not set in functions config.");
}

// Endpoint: /get-imagekit-auth
app.get("/get-imagekit-auth", (req, res) => {
  try {
    // token must be unique per request
    const token = uuidv4();
    // expire time (unix seconds). Must be < 1 hour in future.
    const expire = Math.floor(Date.now() / 1000) + 60 * 60; // 1 hour
    // signature = HMAC-SHA1(token + expire) using private key
    const toSign = token + expire;
    const hmac = crypto.createHmac("sha1", IMAGEKIT_PRIVATE_KEY);
    hmac.update(toSign);
    const signature = hmac.digest("hex").toLowerCase();

    res.json({
      token,
      expire: String(expire),
      signature,
      publicKey: IMAGEKIT_PUBLIC_KEY,
      folder: DEFAULT_FOLDER
    });
  } catch (err) {
    console.error("Auth generate error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

// Export as a function
exports.imagekitAuth = functions.https.onRequest(app);

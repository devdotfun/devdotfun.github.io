const functions = require("firebase-functions");
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(cors({ origin: true }));
app.use(express.json());

// Read ImageKit keys from functions config (secure)
const IMAGEKIT_PRIVATE_KEY = functions.config().imagekit && functions.config().imagekit.private_key;
const IMAGEKIT_PUBLIC_KEY = functions.config().imagekit && functions.config().imagekit.public_key;
const DEFAULT_FOLDER = (functions.config().imagekit && functions.config().imagekit.folder) || "";

if (!IMAGEKIT_PRIVATE_KEY) {
  console.warn("IMAGEKIT_PRIVATE_KEY is not set in functions config.");
}

// GET /get-imagekit-auth
app.get("/get-imagekit-auth", (req, res) => {
  try {
    const token = uuidv4();
    const expire = Math.floor(Date.now() / 1000) + 60 * 60; // 1 hour in future (seconds)
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
    console.error("Error generating ImageKit auth:", err);
    res.status(500).json({ error: "server_error" });
  }
});

// Export as Cloud Function
exports.imagekitAuth = functions.https.onRequest(app);

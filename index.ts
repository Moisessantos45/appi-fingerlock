import express from "express";
import { config } from "dotenv";
import cors from "cors";
import CryptoJS from 'crypto-js';
import { rateLimit } from 'express-rate-limit'

config();

const app = express();

const PORT = process.env.PORT || 4000;

const limiter = rateLimit({
	windowMs: 15 * 60 * 1000,
	limit: 100,
	standardHeaders: 'draft-8',
	legacyHeaders: false,
})

app.use(limiter);

app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST"],
    credentials: true,
  })
);

app.use(express.json());

function encrypt(text: string, secretKey: string) {
  return CryptoJS.AES.encrypt(text, secretKey).toString();
}

function decrypt(ciphertext: string, secretKey: string) {
  const bytes = CryptoJS.AES.decrypt(ciphertext, secretKey);
  return bytes.toString(CryptoJS.enc.Utf8);
}

app.get("/", (_, res) => {
  res.send("Hello World!");
});

app.post("/hash", async (req, res) => {
  const { password } = req.body;
  try {
    if (!password || password.trim() === "") {
      res.status(400).json({ error: "Password is required" });
      return;
    }

    const secretKey = process.env.SECRET_KEY_HASH;
    if (!secretKey) {
      res.status(500).json({ error: "Secret key not found" });
      return;
    }

    const hashedPassword = encrypt(password, secretKey);
    res.json({ hashedPassword });
  } catch (error) {
    console.error("Error hashing password:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/decrypt", async (req, res) => {
  const { hashedPassword } = req.body;
  try {
    if (!hashedPassword || hashedPassword.trim() === "") {
      res.status(400).json({ error: "Hashed password is required" });
      return;
    }

    const secretKey = process.env.SECRET_KEY_HASH;
    if (!secretKey) {
      res.status(500).json({ error: "Secret key not found" });
      return;
    }

    const decryptedPassword = decrypt(hashedPassword, secretKey);
    res.json({ decryptedPassword });
  } catch (error) {
    console.error("Error decrypting password:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

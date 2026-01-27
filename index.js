import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json({ limit: "5mb" }));


const PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
PASTE_FULL_CONTENT_OF_private_key.pem
-----END PRIVATE KEY-----`;

function decryptAES(encryptedData, aesKey, iv) {
  const decipher = crypto.createDecipheriv("aes-256-cbc", aesKey, iv);
  let decrypted = decipher.update(encryptedData, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

function encryptAES(data, aesKey, iv) {
  const cipher = crypto.createCipheriv("aes-256-cbc", aesKey, iv);
  let encrypted = cipher.update(data, "utf8");
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return encrypted;
}

app.post("/flow", (req, res) => {
  try {
    const {
      encrypted_flow_data,
      encrypted_aes_key,
      initial_vector,
    } = req.body;

    if (!encrypted_flow_data || !encrypted_aes_key || !initial_vector) {
      return res.status(200).send("ERROR");
    }

    // 🔓 AES key decrypt
    const aesKey = crypto.privateDecrypt(
      {
        key: PRIVATE_KEY,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(encrypted_aes_key, "base64")
    );

    // 🔓 Request IV
    const requestIV = Buffer.from(initial_vector, "base64");
    if (requestIV.length !== 16) {
      return res.status(200).send("ERROR");
    }

    // 🔓 Decrypt request payload
    const decryptedPayload = decryptAES(
      encrypted_flow_data,
      aesKey,
      requestIV
    );

    console.log("✅ Flow payload:", decryptedPayload);

    // 🟢 RESPONSE ENCRYPTION (META FORMAT)
    const responseIV = crypto.randomBytes(16);
    const encryptedPayload = encryptAES("{}", aesKey, responseIV);

    // 🟢 IMPORTANT: IV + encrypted payload
    const finalResponse = Buffer.concat([
      responseIV,
      encryptedPayload,
    ]).toString("base64");

    res
      .status(200)
      .set("Content-Type", "text/plain")
      .send(finalResponse);

  } catch (err) {
    console.error("❌ Flow crypto error:", err.message);
    return res.status(200).send("ERROR");
  }
});

app.get("/", (req, res) => {
  res.send("Flow crypto server running");
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Flow crypto server running on port ${PORT}`);
});

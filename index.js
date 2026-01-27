import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";
import axios from "axios";

dotenv.config();

const app = express();

app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  })
);

const PORT = process.env.PORT || 10000;
const APP_SECRET = process.env.APP_SECRET;
const N8N_WEBHOOK_URL = process.env.N8N_WEBHOOK_URL; // n8n ની લિંક .env માં નાખજો

const getPrivateKey = () => {
  const key = process.env.PRIVATE_KEY;
  return key ? key.replace(/\\n/g, '\n') : null;
};

// Response એન્ક્રિપ્ટ કરવા માટેનું ફંક્શન
const encryptResponse = (data, aesKey, iv) => {
  const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
  let encrypted = cipher.update(JSON.stringify(data), "utf8", "base64");
  encrypted += cipher.final("base64");
  const authTag = cipher.getAuthTag().toString("base64");
  return { encrypted, authTag };
};

app.get("/flow", (req, res) => res.status(200).send("OK"));

app.post("/flow", async (req, res) => {
  try {
    const signature = req.headers["x-hub-signature-256"];
    const expected = "sha256=" + crypto.createHmac("sha256", APP_SECRET).update(req.rawBody).digest("hex");

    if (!signature || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
      return res.status(401).send("Invalid Signature");
    }

    // Health Check માટે
    if (!req.body.encrypted_flow_data) {
      return res.status(200).send("OK");
    }

    const PRIVATE_KEY = getPrivateKey();
    const encryptedKey = Buffer.from(req.body.encrypted_aes_key, "base64");
    const iv = Buffer.from(req.body.initial_vector, "base64");

    // Decrypt AES Key
    const aesKey = crypto.privateDecrypt(
      { key: PRIVATE_KEY, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
      encryptedKey
    );

    // Decrypt Flow Data
    const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, iv);
    decipher.setAuthTag(Buffer.from(req.body.auth_tag, "base64"));
    let decrypted = decipher.update(req.body.encrypted_flow_data, "base64", "utf8");
    decrypted += decipher.final("utf8");

    const flowData = JSON.parse(decrypted);
    console.log("✅ Decrypted Data:", flowData);

    // ૧. ડેટા n8n પર મોકલો
    if (N8N_WEBHOOK_URL) {
        axios.post(N8N_WEBHOOK_URL, flowData).catch(e => console.error("n8n Error:", e.message));
    }

    // ૨. Meta ને એન્ક્રિપ્ટેડ રિસ્પોન્સ મોકલો
    const responseData = {
      version: "3.0",
      screen: "SUCCESS",
      data: { extension_message_response: { params: { "message": "Received!" } } }
    };

    const { encrypted, authTag } = encryptResponse(responseData, aesKey, iv);

    // Meta ને ફક્ત Base64 સ્ટ્રિંગ જ જોઈએ છે
    res.set("Content-Type", "text/plain");
    return res.status(200).send(encrypted);

  } catch (err) {
    console.error("❌ Error:", err.message);
    return res.status(500).send("Internal Error");
  }
});

app.listen(PORT, () => console.log(`🚀 Server on port ${PORT}`));

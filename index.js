import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const app = express();

// Meta sends RAW body for signature verification
app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  })
);

const PORT = process.env.PORT || 10000;
const APP_SECRET = process.env.APP_SECRET;

// Private Key ને \n સાથે બરાબર ફોર્મેટ કરવા માટે
const getPrivateKey = () => {
  const key = process.env.PRIVATE_KEY;
  if (!key) return null;
  return key.replace(/\\n/g, '\n');
};

/* --------------------------------------------------
   HEALTH CHECK (GET)
-------------------------------------------------- */
app.get("/flow", (req, res) => {
  return res.status(200).send("OK");
});

/* --------------------------------------------------
   FLOW ENDPOINT (POST)
-------------------------------------------------- */
app.post("/flow", (req, res) => {
  try {
    const signature = req.headers["x-hub-signature-256"];
    if (!signature) {
      console.error("❌ Missing signature");
      return res.status(401).send("Missing signature");
    }

    // Signature Verification
    const expected =
      "sha256=" +
      crypto
        .createHmac("sha256", APP_SECRET)
        .update(req.rawBody)
        .digest("hex");

    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
      console.error("❌ Invalid signature");
      return res.status(401).send("Invalid signature");
    }

    // IMPORTANT: Meta Health Check/Test Calls during setup
    if (!req.body.encrypted_flow_data) {
      console.log("ℹ️ Meta Health Check - sending 200 OK");
      return res.status(200).send("OK");
    }

    const PRIVATE_KEY = getPrivateKey();
    const encryptedKey = Buffer.from(req.body.encrypted_aes_key, "base64");
    const iv = Buffer.from(req.body.initial_vector, "base64");

    // Decrypt AES Key using RSA Private Key
    const aesKey = crypto.privateDecrypt(
      {
        key: PRIVATE_KEY,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256", // આ ખાસ ચેક કરજો, Meta ઘણીવાર આ એક્સપેક્ટ કરે છે
      },
      encryptedKey
    );

    // Decrypt Flow Data using AES-GCM
    const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, iv);
    decipher.setAuthTag(Buffer.from(req.body.auth_tag, "base64"));

    let decrypted = decipher.update(
      req.body.encrypted_flow_data,
      "base64",
      "utf8"
    );
    decrypted += decipher.final("utf8");

    const flowData = JSON.parse(decrypted);
    console.log("✅ Decrypted Flow Data:", flowData);

    // તમારી જરૂરિયાત મુજબ Response (SUCCESS સ્ક્રીનનું નામ આપો)
    return res.status(200).json({
      version: "3.0",
      screen: "SUCCESS", 
      data: {
        extension_message_response: {
          params: {
            "message": "Appointment received!"
          }
        }
      }
    });

  } catch (err) {
    console.error("❌ Critical Flow Error:", err.message);
    return res.status(500).send("Internal Server Error");
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Flow server running on port ${PORT}`);
});

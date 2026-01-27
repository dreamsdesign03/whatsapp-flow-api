import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const app = express();

/**
 * IMPORTANT
 * Meta sends RAW body for signature verification
 */
app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  })
);

const PORT = process.env.PORT || 10000;
const PRIVATE_KEY = process.env.PRIVATE_KEY;
const APP_SECRET = process.env.APP_SECRET;

/* --------------------------------------------------
   HEALTH CHECK (Meta calls this)
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
      return res.sendStatus(401);
    }

    if (!req.rawBody) {
      console.error("❌ Missing raw body");
      return res.sendStatus(400);
    }

    const expected =
      "sha256=" +
      crypto
        .createHmac("sha256", APP_SECRET)
        .update(req.rawBody)
        .digest("hex");

    if (
      signature.length !== expected.length ||
      !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))
    ) {
      console.error("❌ Invalid signature");
      return res.sendStatus(401);
    }

    // ✅ IMPORTANT: Meta test calls don't send encrypted payload
    if (!req.body.encrypted_flow_data) {
      console.log("ℹ️ Meta test call – no encrypted data");
      return res.status(200).json({ screen: "SUCCESS" });
    }

    const encryptedKey = Buffer.from(req.body.encrypted_aes_key, "base64");
    const iv = Buffer.from(req.body.initial_vector, "base64");

    const aesKey = crypto.privateDecrypt(
      {
        key: PRIVATE_KEY,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      },
      encryptedKey
    );

    const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, iv);
    decipher.setAuthTag(Buffer.from(req.body.auth_tag, "base64"));

    let decrypted = decipher.update(
      req.body.encrypted_flow_data,
      "base64",
      "utf8"
    );
    decrypted += decipher.final("utf8");

    const flowData = JSON.parse(decrypted);
    console.log("✅ FLOW DATA:", flowData);

    return res.status(200).json({
      screen: "SUCCESS",
      data: { message: "Flow received successfully" },
    });
  } catch (err) {
    console.error("❌ Flow error:", err.message);
    return res.sendStatus(500);
  }
});

/* --------------------------------------------------
   SERVER START
-------------------------------------------------- */
app.listen(PORT, () => {
  console.log(`🚀 Flow crypto server running on port ${PORT}`);
});

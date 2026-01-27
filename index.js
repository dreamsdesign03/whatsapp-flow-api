import express from "express";
import crypto from "crypto";
import axios from "axios";

const app = express();

// Meta signature વેરીફિકેશન માટે RAW body જોઈએ
app.use(express.json({
    verify: (req, res, buf) => { req.rawBody = buf; }
}));

// --- કોન્ફિગરેશન (અહીં તારા ડેટા નાખો) ---
const APP_SECRET = "f32d7a3f9e81dad4a6698b771d36af09"; // તારો મેટા એપ સિક્રેટ
const N8N_WEBHOOK_URL = "https://n8n.srv891967.hstgr.cloud/webhook/1073466d-3451-4f8c-aec2-61cc763d2f64"; // તારી n8n લિંક
const PORT = process.env.PORT || 10000;

// તમારી આખી પ્રાઈવેટ કી અહીં ડાયરેક્ટ પેસ્ટ કરી છે
const PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCZtyf1FVm2xG4E
ws0Bv7KlwLV4Dad+B6/OBGTQS/3bLPPgiD8g1QxzLX5OWjKEtan0/IPomItqAsFU
Ne4PJGRkWA3UyL+qDvMIDpKp7Zb1oFif2C6nfEM4EiAp5NJWiZ9kh0FUVQhWTLvy
4I9RbMZ2g/2gAPNWgaGT8+cpFiZxjZvA1oYHj5/KwKArAmbGHHtBTOSfvmsK5Xut
ffK5liBRDA16fH+n/VHtIZAbOj3Ypw2QtOyUkHVI1CkuJfOMVx0wcUs0FbZZdC7f
MwH/F3J3REy6tcqGxpDxA8gkHSbq3yy7OEIQR36bQvsw/mJ3F7r2Z2J+jftlWuSG
RRph8wiNAgMBAAECggEAAkSgk04wV7EISouxSLBSa32vb8kLyqFEZ87KygQFB+He
61Y3UD20hFKMhY1xJ2Ii0tmS/LCbhgHqZlqxW4nW7WAbPCOGKHU2As1sPpOh4Zfv
FtSyw4fi2gXycYvNyrcXIf2Y6iyjBdr1/vxvQO1Q9Fi4Ok8pSAJ7pto3c/S+tngx
k2BWNlL9YHCAO68+udZIU02PtEOJYquc/WciUDOzlklowoMPP5VxNv10BkkkigWC
2IHWaYu5ZzBJYr+Nw3X3XK6+PJX3NxwH8IBge8SZsqu7qkF8YR/vgEXXw06wrQ5Q
bKI6UHBvjd6y6v2Qqv3fLrXYDBJyNw2bycwCukCwQQKBgQDOOoft7yavov80KqF1
a/6YYG68ytsQdvelq7g0lPOD3rwABvoa6nZZo6RBKlvzPJnU2vWKobVsMztDo9r8
i/aZg5sqcBQfAlCt6wXG3xj/p/q49G2aN5/ymEnZcW4cqRNb0EIkytCwCcAcSrTo
vSKTUwiBZeatOK2kvaF/MjwpkQKBgQC+0DENdppCHCO5yOwV3Siyipf/o1GTtMG3
B0yRlBXTx48MJf1La4p2+zcmPZj6FhTvG8FB0Gdb+EstRkWI3ghncPprEcj9gjm6
hn36wXX8Zpo7nsvb9h23cP2yCJplIPixsVdJTkQ+eI8az+vZad1IT7T7l5irOsEl
d67Z2/KRPQKBgQCQ7t2cwBfmE51bIiK6jR0uJYdtsvrlxVYh3l7kxVGmeaCSPFUF
GYX3VWQYUBazCQHrb75koWUJF7Asxzkdh5fVJ4Ki/oWFjXD56VP0AdJlyb4QwedN
HI6SRaiQ4oDKL6DlQ6VYihjDvvZ+a5pcfp+P/ijaF61YS57tSj/3TmytoQKBgE02
A1NWVa9AobgwtE9YkXpFmKHp3T2um+BLBNG3oWlzy893o9ob5wikOLmxnTA9NTVX
/sh54wkVHJ5yW/q5FZ992ObwaGskgeWXPGz2UZ7Tib9sT0NvgLDU+ONMleUsBVYp
048nK3g34nhQADiWnOMA1dQkkLNg7/0QQ+GGHc5lAoGAbKAQSDXvw/EoC49/fpns
Ej76VZG+osgyWqq4z4xYy6wkRkhyCKN9ogRt4FN3+9sKsl+pnfg4QwyPQWwXRU0j
G5L3oGfbtlmohW4deH0ZoRpljE/21dqRrxppeSbxjjb1egeesx0z7Y14JF81SvVv
8tWimOfa16GJSr1MazMwQvg=
-----END PRIVATE KEY-----`;

// Response એન્ક્રિપ્ટ કરવા માટેનું ફંક્શન
const encryptResponse = (data, aesKey, iv) => {
    const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
    let encrypted = cipher.update(JSON.stringify(data), "utf8", "base64");
    encrypted += cipher.final("base64");
    const authTag = cipher.getAuthTag();
    return Buffer.concat([Buffer.from(encrypted, "base64"), authTag]).toString("base64");
};

app.get("/flow", (req, res) => res.status(200).send("OK"));

app.post("/flow", async (req, res) => {
    try {
        const signature = req.headers["x-hub-signature-256"];
        const expected = "sha256=" + crypto.createHmac("sha256", APP_SECRET).update(req.rawBody).digest("hex");

        if (!signature || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
            return res.status(401).send("Invalid Signature");
        }

        if (!req.body.encrypted_flow_data) return res.status(200).send("OK");

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

        // n8n પર ડેટા મોકલો
        axios.post(N8N_WEBHOOK_URL, flowData).catch(e => console.error("n8n Error"));

        // Meta ને રિસ્પોન્સ મોકલો
        const responseData = {
            version: "3.0",
            screen: "SUCCESS",
            data: { extension_message_response: { params: { "message": "Received!" } } }
        };

        const encryptedBody = encryptResponse(responseData, aesKey, iv);
        res.set("Content-Type", "text/plain");
        return res.status(200).send(encryptedBody);

    } catch (err) {
        console.error("❌ Critical Error:", err.message);
        return res.status(500).send("Internal Error");
    }
});

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

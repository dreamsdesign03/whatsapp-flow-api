import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 8080;

/* 🔐 PRIVATE KEY (Exactly jem chhe em j rehva dejo) */
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

/**
 * 🔓 DECRYPT FUNCTION
 */
function decryptRequest(body) {
    const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;

    // 1. Decrypt AES Key using RSA Private Key
    const aesKey = crypto.privateDecrypt(
        {
            key: PRIVATE_KEY,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        },
        Buffer.from(encrypted_aes_key, "base64")
    );

    const flowDataBuffer = Buffer.from(encrypted_flow_data, "base64");
    const ivBuffer = Buffer.from(initial_vector, "base64");

    // 2. Extract Tag (Last 16 bytes) and Ciphertext
    const tag = flowDataBuffer.slice(-16);
    const encryptedData = flowDataBuffer.slice(0, -16);

    // 3. Decrypt Flow Data using AES-GCM
    const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, ivBuffer);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([
        decipher.update(encryptedData),
        decipher.final(),
    ]).toString("utf-8");

    return { data: JSON.parse(decrypted), aesKey, iv: ivBuffer };
}

/**
 * 🔒 ENCRYPT FUNCTION
 */
function encryptResponse(data, aesKey, iv) {
    // WhatsApp expectation: Flip bits of the IV for response
    const flippedIv = Buffer.from(iv.map((b) => ~b));
    
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, flippedIv);
    
    const ciphertext = Buffer.concat([
        cipher.update(JSON.stringify(data), "utf8"),
        cipher.final(),
        cipher.getAuthTag(),
    ]);

    return ciphertext.toString("base64");
}

/* 📅 STATIC DATA */
const dates = [
    { id: "2026-01-31", title: "Sat, Jan 31" },
    { id: "2026-02-01", title: "Sun, Feb 1" }
];

const times = [
    { id: "10:00", title: "10:00 AM", enabled: true },
    { id: "11:00", title: "11:00 AM", enabled: true }
];

/* 🚀 FLOW ENDPOINT */
app.post("/flow", (req, res) => {
    try {
        if (!req.body.encrypted_flow_data) {
            return res.status(400).send("Missing encrypted data");
        }

        const { data, aesKey, iv } = decryptRequest(req.body);
        console.log("📥 RECEIVED ACTION:", data.action);
        console.log("📥 PAYLOAD:", data);

        let responseBody = {
            version: "3.0", // Flows Data API Version
            data: {}
        };

        // --- logic routing ---

        // 1. Initial Load or Ping
        if (!data.action || data.action === "ping") {
            responseBody.data = {
                date_options: dates,
                time_options: [],
                is_time_enabled: false
            };
        } 
        // 2. When user selects a date
        else if (data.action === "date_selected") {
            responseBody.data = {
                time_options: times,
                is_time_enabled: true
            };
        }
        // 3. Final submission
        else if (data.action === "complete_booking") {
            console.log("✅ SUCCESSFUL BOOKING:", data);
            responseBody.data = {
                success: true,
                message: "Appointment confirmed!"
            };
        }

        // Encrypt the response
        const encryptedRes = encryptResponse(responseBody, aesKey, iv);

        // ⚠️ VERY IMPORTANT: Content-Type must be text/plain
        res.setHeader("Content-Type", "text/plain");
        return res.status(200).send(encryptedRes);

    } catch (err) {
        console.error("❌ ERROR:", err.message);
        // If decryption fails, Meta expects 421
        return res.status(421).send("Decryption failed");
    }
});

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

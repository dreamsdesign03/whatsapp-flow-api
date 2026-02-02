import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 8080;

// ✅ Tamari PKCS#8 Private Key (Ensure it's exactly as provided by Meta)
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
... (Keep your full key here) ...
-----END PRIVATE KEY-----`;

// --- HELPER FUNCTIONS ---

function decryptRequest(body) {
    const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;
    const aesKey = crypto.privateDecrypt(
        { key: PRIVATE_KEY, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
        Buffer.from(encrypted_aes_key, "base64")
    );
    const flowDataBuffer = Buffer.from(encrypted_flow_data, "base64");
    const ivBuffer = Buffer.from(initial_vector, "base64");
    const tag = flowDataBuffer.slice(-16);
    const encryptedData = flowDataBuffer.slice(0, -16);
    const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, ivBuffer);
    decipher.setAuthTag(tag);
    return { 
        data: JSON.parse(Buffer.concat([decipher.update(encryptedData), decipher.final()]).toString("utf-8")), 
        aesKey, 
        iv: ivBuffer 
    };
}

function encryptResponse(data, aesKey, iv) {
    const flippedIv = Buffer.from(iv.map((b) => ~b));
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, flippedIv);
    return Buffer.concat([cipher.update(JSON.stringify(data), "utf8"), cipher.final(), cipher.getAuthTag()]).toString("base64");
}

// 📅 Generate next 7 working days (No Sat/Sun)
function getDynamicDates() {
    const options = [];
    let d = new Date();
    while (options.length < 7) {
        const day = d.getDay();
        if (day !== 0 && day !== 6) {
            const id = d.toISOString().split('T')[0];
            const title = d.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' });
            options.push({ id, title });
        }
        d.setDate(d.getDate() + 1);
    }
    return options;
}

// ⏰ Generate 30-min slots from 11:00 AM to 6:00 PM
function getDynamicTimes() {
    const slots = [];
    for (let hour = 11; hour < 18; hour++) {
        ["00", "30"].forEach(min => {
            let h = hour > 12 ? hour - 12 : hour;
            let ampm = hour >= 12 ? "PM" : "AM";
            let timeStr = `${h}:${min} ${ampm}`;
            slots.push({ id: timeStr, title: timeStr });
        });
    }
    return slots;
}

// Simple in-memory storage for booked slots
let bookedSlots = new Set(); 

// --- MAIN ENDPOINT ---

app.post("/flow", (req, res) => {
    try {
        // 1. Health Check Handling (Important for Meta Verification)
        if (!req.body.encrypted_flow_data) {
            console.log("✅ Health Check / Verification Received");
            return res.status(200).send("Active");
        }

        // 2. Decrypt Request
        const { data, aesKey, iv } = decryptRequest(req.body);
        console.log("📥 Action:", data.action, "| Data:", data.data);

        let responseBody = { version: "3.0", data: {} };
        const action = data.action;

        // 3. Logic based on Action
        if (action === "INIT" || action === "ping") {
            responseBody.screen = "APPOINTMENT";
            responseBody.data = {
                date_options: getDynamicDates(),
                time_options: []
            };
        } 
        else if (action === "date_selected" || (action === "data_exchange" && data.payload?.action === "date_selected")) {
            const selectedDate = data.data?.date || data.payload?.date;
            const allTimes = getDynamicTimes();
            
            // Filter already booked slots for this date
            const availableTimes = allTimes.filter(slot => !bookedSlots.has(`${selectedDate}_${slot.id}`));

            responseBody.screen = "APPOINTMENT";
            responseBody.data = {
                date_options: getDynamicDates(),
                time_options: availableTimes
            };
        }
        else if (action === "complete_booking") {
            const { date, time } = data.data;
            bookedSlots.add(`${date}_${time}`); // Save booking
            
            responseBody.screen = "SUMMARY"; // Stay on summary or navigate to a success screen
            responseBody.data = { 
                extension_message_response: { status: "success", message: "Appointment Confirmed!" } 
            };
        }

        // 4. Encrypt and Send Response
        const encryptedRes = encryptResponse(responseBody, aesKey, iv);
        res.setHeader("Content-Type", "text/plain");
        return res.status(200).send(encryptedRes);

    } catch (error) {
        console.error("❌ Encryption/Logic Error:", error.message);
        // Meta requires 421 for decryption issues
        return res.status(421).send("Decryption Error");
    }
});

// GET endpoint just in case Meta hits it for simple URL check
app.get("/flow", (req, res) => res.status(200).send("Flow Server is Live!"));

app.listen(PORT, () => console.log(`🚀 Flow Backend live on port ${PORT}`));

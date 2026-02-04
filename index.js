import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 10000;

// 1. Data Mappings (Summary screen par text lakhva mate)
const DEPT_NAMES = {
    shopping: "Shopping & Groceries",
    clothing: "Clothing & Apparel",
    home: "Home Goods & Decor",
    electronics: "Electronics & Appliances",
    beauty: "Beauty & Personal Care"
};

const LOC_NAMES = {
    "1": "King’s Cross, London",
    "2": "Oxford Street, London",
    "3": "Covent Garden, London",
    "4": "Piccadilly Circus, London"
};

// 2. Encryption/Decryption Helpers (Tamari existing logic mujab)
const rawKey = process.env.PRIVATE_KEY || "";
const PRIVATE_KEY = formatPrivateKey(rawKey);

function formatPrivateKey(key) {
    if (!key) return "";
    if (key.includes('BEGIN PRIVATE KEY')) return key;
    const wrappedKey = key.replace(/\\n/g, '\n').match(/.{1,64}/g)?.join('\n') || key;
    return `-----BEGIN PRIVATE KEY-----\n${wrappedKey}\n-----END PRIVATE KEY-----`;
}

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
    const decryptedData = JSON.parse(Buffer.concat([decipher.update(encryptedData), decipher.final()]).toString("utf-8"));
    return { data: decryptedData, aesKey, iv: ivBuffer };
}

function encryptResponse(data, aesKey, iv) {
    const flippedIv = Buffer.from(iv.map((b) => ~b));
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, flippedIv);
    return Buffer.concat([cipher.update(JSON.stringify(data), "utf8"), cipher.final(), cipher.getAuthTag()]).toString("base64");
}

// 3. Dynamic Option Generators
const getDynamicDates = () => [
    { id: "2026-02-05", title: "Thu Feb 05 2026" },
    { id: "2026-02-06", title: "Fri Feb 06 2026" },
    { id: "2026-02-07", title: "Sat Feb 07 2026" }
];

const getDynamicTimes = () => [
    { id: "10:30", title: "10:30 AM" },
    { id: "11:30", title: "11:30 AM" },
    { id: "12:30", title: "12:30 PM" }
];

// 4. Main Route
app.post("/flow", (req, res) => {
    try {
        // Health check logic for raw pings
        if (!req.body.encrypted_flow_data) {
            return res.status(200).send("Active");
        }

        const { data, aesKey, iv } = decryptRequest(req.body);
        const screen = data.screen;
        const action = data.action;
        const input = data.data || {}; 

        let responseBody = { version: "3.0", screen: screen, data: {} };

        // FIX: Aa line badha data formats handle karse
        const payload = data.data || data.payload || {};

        // 1. Ping / Health Check Handling
        if (action === "ping" || !screen) {
            return res.status(200).send(encryptResponse({ 
                version: "3.0", 
                data: { status: "active" } 
            }, aesKey, iv));
        }

        // 2. APPOINTMENT SCREEN - Dynamic Data Fill
        if (action === "INIT" || screen === "APPOINTMENT") {
            responseBody.screen = "APPOINTMENT";
            responseBody.data = {
                department: Object.keys(DEPT_NAMES).map(id => ({ id, title: DEPT_NAMES[id] })),
                location: Object.keys(LOC_NAMES).map(id => ({ id, title: LOC_NAMES[id] })),
                date: getDynamicDates(),
                time: getDynamicTimes(),
                is_location_enabled: true,
                is_date_enabled: true,
                is_time_enabled: true
            };
            console.log("✅ APPOINTMENT Data Loaded");
        }

        // 3. SUMMARY SCREEN - Accurate Review Data
        else if (screen === "DETAILS" && action === "data_exchange") {
            const deptTitle = DEPT_NAMES[payload.department] || payload.department;
            const locTitle = LOC_NAMES[payload.location] || payload.location;
            
            responseBody.screen = "SUMMARY";
            responseBody.data = {
                appointment: `${deptTitle} at ${locTitle}\n${payload.date} at ${payload.time}.`,
                details: `Name: ${payload.name}\nEmail: ${payload.email}\nPhone: ${payload.phone}`,
                // Passing IDs back for the final submission
                department: payload.department,
                location: payload.location,
                date: payload.date,
                time: payload.time,
                name: payload.name,
                email: payload.email,
                phone: payload.phone
            };
            console.log("✅ SUMMARY Data Prepared");
        }

        // 4. FINAL SUBMIT
        else if (screen === "SUMMARY" && action === "data_exchange") {
            return res.status(200).send(encryptResponse({
                version: "3.0",
                type: "TERMINATE",
                data: { extension_message_response: { params: { status: "success", message: "Success!" } } }
            }, aesKey, iv));
        }

        return res.status(200).send(encryptResponse(responseBody, aesKey, iv));

    } catch (error) {
        console.error("💥 Error:", error.message);
        res.status(421).send("Error");
    }
});

app.listen(PORT, () => console.log(`🚀 Server on port ${PORT}`));

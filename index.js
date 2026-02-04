import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 10000;

// Fix for OpenSSL 3.0 on Render/Modern Node.js
process.env.NODE_OPTIONS = '--openssl-legacy-provider';

const rawKey = process.env.PRIVATE_KEY || "";
let PRIVATE_KEY = "";

// PEM format converter with better error handling
function formatPrivateKey(key) {
    if (!key) {
        console.log("⚠️ PRIVATE_KEY not found in env");
        return "";
    }
    
    try {
        if (key.includes('BEGIN PRIVATE KEY')) return key;
        const cleanedKey = key.replace(/\\n/g, '\n').replace(/\\s/g, '');
        const wrappedKey = cleanedKey.match(/.{1,64}/g)?.join('\n') || cleanedKey;
        return `-----BEGIN PRIVATE KEY-----\n${wrappedKey}\n-----END PRIVATE KEY-----`;
    } catch (e) {
        console.error("❌ Key format error:", e.message);
        return "";
    }
}

PRIVATE_KEY = formatPrivateKey(rawKey);
console.log("🔑 Private key loaded:", PRIVATE_KEY ? "✅ YES" : "❌ NO");

// 🔐 FIXED Crypto helpers with error handling
function decryptRequest(body) {
    console.log("🔓 Attempting decryption...");
    
    try {
        const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;
        
        if (!encrypted_aes_key || !encrypted_flow_data || !initial_vector) {
            throw new Error("Missing encryption fields");
        }

        // Try different padding methods for compatibility
        const decryptOptions = [
            { padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
            { padding: crypto.constants.RSA_PKCS1_PADDING, oaepHash: "sha1" },
            { padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }
        ];

        let aesKey;
        for (const options of decryptOptions) {
            try {
                aesKey = crypto.privateDecrypt(
                    { key: PRIVATE_KEY, ...options },
                    Buffer.from(encrypted_aes_key, "base64")
                );
                console.log("✅ Decryption successful with options:", options);
                break;
            } catch (e) {
                console.log("⚠️ Padding failed:", options.padding, e.message);
                continue;
            }
        }

        if (!aesKey) {
            throw new Error("All decryption methods failed");
        }

        const flowDataBuffer = Buffer.from(encrypted_flow_data, "base64");
        const ivBuffer = Buffer.from(initial_vector, "base64");
        const tag = flowDataBuffer.slice(-16);
        const encryptedData = flowDataBuffer.slice(0, -16);

        const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, ivBuffer);
        decipher.setAuthTag(tag);
        
        const decryptedData = JSON.parse(
            Buffer.concat([decipher.update(encryptedData), decipher.final()]).toString("utf-8")
        );
        
        console.log("✅ Full decryption successful. Data keys:", Object.keys(decryptedData));
        return { data: decryptedData, aesKey, iv: ivBuffer };
        
    } catch (error) {
        console.error("💥 DECRYPTION FAILED:", error.message);
        throw error;
    }
}

function encryptResponse(data, aesKey, iv) {
    try {
        const flippedIv = Buffer.from(iv.map((b) => ~b));
        const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, flippedIv);
        return Buffer.concat([
            cipher.update(JSON.stringify(data), "utf8"), 
            cipher.final(), 
            cipher.getAuthTag()
        ]).toString("base64");
    } catch (error) {
        console.error("💥 ENCRYPTION FAILED:", error.message);
        throw error;
    }
}

// Dynamic data generators (same as before)
function getDynamicDates() {
    const options = [];
    let d = new Date();
    for (let i = 0; i < 14 && options.length < 7; i++) {
        if (d.getDay() !== 0 && d.getDay() !== 6) {
            const dateStr = d.toISOString().split('T')[0];
            options.push({ 
                id: dateStr,
                title: d.toLocaleDateString('en-IN', { 
                    weekday: 'short', day: 'numeric', month: 'short' 
                })
            });
        }
        d.setDate(d.getDate() + 1);
    }
    return options;
}

function getDynamicTimes() {
    const slots = [];
    for (let h = 10; h <= 20; h++) {
        ["00", "30"].forEach(m => {
            if (slots.length < 12) {
                const hour12 = h % 12 || 12;
                const ampm = h >= 12 ? "PM" : "AM";
                slots.push({ id: `${h}:${m}`, title: `${hour12}:${m} ${ampm}` });
            }
        });
    }
    return slots;
}

const DEPARTMENTS = [
    { id: "haircut", title: "Haircut & Styling" },
    { id: "beauty", title: "Beauty & Makeup" },
    { id: "spa", title: "Spa & Massage" },
    { id: "manicure", title: "Manicure & Pedicure" }
];

const LOCATIONS = [
    { id: "1", title: "Vadodara - Alkapuri" },
    { id: "2", title: "Vadodara - Fatehgunj" },
    { id: "3", title: "Vadodara - Gotri" }
];

const DEPT_NAMES = { haircut: "Haircut & Styling", beauty: "Beauty & Makeup", spa: "Spa & Massage", manicure: "Manicure & Pedicure" };
const LOC_NAMES = { "1": "Vadodara - Alkapuri", "2": "Vadodara - Fatehgunj", "3": "Vadodara - Gotri" };

app.post("/flow", (req, res) => {
    try {
        console.log("\n🚀 === NEW REQUEST ===");
        
        // HEALTH CHECK - Return "Active" for ping without encryption
        if (!req.body.encrypted_flow_data) {
            console.log("🏓 HEALTH CHECK - Returning Active");
            return res.status(200).send("Active");
        }

        console.log("📡 Encrypted request received");
        const { data, aesKey, iv } = decryptRequest(req.body);
        
        console.log("📱 Screen:", data.screen || "APPOINTMENT");
        console.log("⚡ Action:", data.action || "NONE");

        let responseBody = { version: "3.0", screen: data.screen || "APPOINTMENT", data: {} };

        // PING
        if (data.action === "ping") {
            return res.status(200).send(encryptResponse({ data: { status: "active" } }, aesKey, iv));
        }

        // APPOINTMENT
        if (data.screen === "APPOINTMENT" || data.action === "INIT") {
            responseBody.data = {
                department: DEPARTMENTS,
                location: LOCATIONS,
                date: getDynamicDates(),
                time: getDynamicTimes()
            };
            console.log("✅ APPOINTMENT data sent");
            return res.status(200).send(encryptResponse(responseBody, aesKey, iv));
        }

        // DETAILS
        if (data.screen === "DETAILS") {
            const appointmentData = {
                department: data.payload?.department || data.data?.department || "",
                location: data.payload?.location || data.data?.location || "",
                date: data.payload?.date || data.data?.date || "",
                time: data.payload?.time || data.data?.time || "",
                name: data.payload?.name || data.data?.name || "",
                phone: data.payload?.phone || data.data?.phone || "",
                email: data.payload?.email || data.data?.email || ""
            };
            responseBody.data = appointmentData;
            console.log("✅ DETAILS data sent");
            return res.status(200).send(encryptResponse(responseBody, aesKey, iv));
        }

        // SUMMARY
        // #4 SUMMARY SCREEN - FULL DEBUG VERSION
       if (data.screen === "SUMMARY") {
            console.log("📋 SUMMARY RAW DATA:", JSON.stringify(data, null, 2));
            
            const bookingData = {
                department: data.data?.department || data.payload?.department || "",
                location: data.data?.location || data.payload?.location || "",
                date: data.data?.date || data.payload?.date || "",
                time: data.data?.time || data.payload?.time || "",
                name: data.data?.name || data.payload?.name || "",
                phone: data.data?.phone || data.payload?.phone || "",
                email: data.data?.email || data.payload?.email || ""
            };
            
            // Create formatted text
            const appointment = `${DEPT_NAMES[bookingData.department] || bookingData.department} Department`;
            const details = `Name: ${bookingData.name}\nPhone: ${bookingData.phone}`;
            
            console.log("📦 bookingData:", bookingData);
            console.log("📝 appointment:", appointment);
            console.log("📝 details:", details);
            
            responseBody.data = {
                department: bookingData.department,
                location: bookingData.location,
                date: bookingData.date,
                time: bookingData.time,
                name: bookingData.name,
                phone: bookingData.phone,
                email: bookingData.email,
                appointment: appointment,
                details: details
            };
            
            return res.status(200).send(encryptResponse(responseBody, aesKey, iv));
        }
        

        // CONFIRM
        if (data.action === "data_exchange" && data.payload?.action === "confirm_booking") {
            console.log("🎉 BOOKING CONFIRMED:", data.data);
            responseBody = {
                version: "3.0",
                type: "TERMINATE",
                screen: "SUMMARY",
                data: {
                    extension_message_response: {
                        params: {
                            flow_token: data.flow_token,
                            status: "success",
                            message: `✅ *Appointment Booked!*\n\n👤 ${data.data?.name}\n📅 ${data.data?.date} ${data.data?.time}`
                        }
                    }
                }
            };
            return res.status(200).send(encryptResponse(responseBody, aesKey, iv));
        }

        console.log("⚠️ Unknown request");
        res.status(200).send(encryptResponse(responseBody, aesKey, iv));

    } catch (error) {
        console.error("💥 CRITICAL ERROR:", error.message);
        
        // For health check failures, return "Active" anyway
        if (!req.body.encrypted_flow_data) {
            return res.status(200).send("Active");
        }
        
        res.status(421).send("Error");
    }
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log("✅ OpenSSL legacy provider enabled");
});

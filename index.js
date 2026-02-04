import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 10000;

// Render variable mathi key lese
const rawKey = process.env.PRIVATE_KEY || "";
const PRIVATE_KEY = formatPrivateKey(rawKey);

// PEM format converter
function formatPrivateKey(key) {
    if (!key) return "";
    if (key.includes('BEGIN PRIVATE KEY')) return key;
    const wrappedKey = key.replace(/\\s/g, '').replace(/(.{64})/g, "$1\\n");
    return `-----BEGIN PRIVATE KEY-----\\n${wrappedKey}\\n-----END PRIVATE KEY-----`;
}

// 🔐 Crypto helpers
function decryptRequest(body) {
    console.log("🔓 Decrypting request...");
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
    console.log("✅ Decryption successful. Data keys:", Object.keys(decryptedData));
    
    return { 
        data: decryptedData, 
        aesKey, 
        iv: ivBuffer 
    };
}

function encryptResponse(data, aesKey, iv) {
    const flippedIv = Buffer.from(iv.map((b) => ~b));
    const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, flippedIv);
    return Buffer.concat([cipher.update(JSON.stringify(data), "utf8"), cipher.final(), cipher.getAuthTag()]).toString("base64");
}

// 📅 Dynamic Data Generators
function getDynamicDates() {
    console.log("📅 Generating dynamic dates...");
    const options = [];
    let d = new Date();
    
    // Skip weekends, get next 7 working days
    for (let i = 0; i < 14 && options.length < 7; i++) {
        if (d.getDay() !== 0 && d.getDay() !== 6) {
            const dateStr = d.toISOString().split('T')[0];
            options.push({ 
                id: dateStr,
                title: d.toLocaleDateString('en-IN', { 
                    weekday: 'short', 
                    day: 'numeric', 
                    month: 'short' 
                })
            });
            console.log(`   Added: ${options[options.length-1].title}`);
        }
        d.setDate(d.getDate() + 1);
    }
    console.log(`✅ Generated ${options.length} date options`);
    return options;
}

function getDynamicTimes() {
    console.log("🕒 Generating dynamic times...");
    const slots = [];
    for (let h = 10; h <= 20; h++) {
        ["00", "30"].forEach(m => {
            const hour12 = h % 12 || 12;
            const ampm = h >= 12 ? "PM" : "AM";
            if (slots.length < 12) { // Limit to 12 slots
                slots.push({ 
                    id: `${h}:${m}`, 
                    title: `${hour12}:${m} ${ampm}` 
                });
            }
        });
    }
    console.log(`✅ Generated ${slots.length} time slots`);
    return slots;
}

// Static data
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

// Data mapping for display
const DEPT_NAMES = {
    haircut: "Haircut & Styling",
    beauty: "Beauty & Makeup", 
    spa: "Spa & Massage",
    manicure: "Manicure & Pedicure"
};

const LOC_NAMES = {
    "1": "Vadodara - Alkapuri",
    "2": "Vadodara - Fatehgunj", 
    "3": "Vadodara - Gotri"
};

// 🌐 Main Flow Endpoint
app.post("/flow", (req, res) => {
    try {
        console.log("\n🚀 === NEW REQUEST ===");
        console.log("📡 Request body keys:", Object.keys(req.body));
        
        if (!req.body.encrypted_flow_data) {
            console.log("🏓 PING response");
            return res.status(200).send("Active");
        }

        const { data, aesKey, iv } = decryptRequest(req.body);
        
        console.log("\n📱 SCREEN:", data.screen || "UNKNOWN");
        console.log("⚡ ACTION:", data.action || "NONE");
        console.log("🔍 FULL DATA:", JSON.stringify(data, null, 2));
        console.log("📦 PAYLOAD:", JSON.stringify(data.payload || {}, null, 2));
        console.log("📋 FORM DATA:", JSON.stringify(data.data || {}, null, 2));

        let responseBody = { version: "3.0", screen: data.screen || "APPOINTMENT", data: {} };

        // #1 PING
        if (data.action === "ping") {
            console.log("🏓 PING - Sending active status");
            return res.status(200).send(encryptResponse({ data: { status: "active" } }, aesKey, iv));
        }

        // #2 APPOINTMENT SCREEN - Load Dynamic Data
        if (data.screen === "APPOINTMENT" || data.action === "INIT") {
            console.log("\n🎯 LOADING APPOINTMENT SCREEN - SENDING DYNAMIC DATA");
            
            responseBody.data = {
                department: DEPARTMENTS,
                location: LOCATIONS,
                date: getDynamicDates(),
                time: getDynamicTimes()
            };
            
            console.log("✅ DROPDOWN DATA SENT:");
            console.log("   Departments:", responseBody.data.department.map(d => d.title));
            console.log("   Locations:", responseBody.data.location.map(l => l.title));
            console.log("   Dates:", responseBody.data.date.map(d => d.title));
            console.log("   Times:", responseBody.data.time.map(t => t.title));
            
            return res.status(200).send(encryptResponse(responseBody, aesKey, iv));
        }

        // #3 DETAILS SCREEN - Pass through appointment data + empty personal fields
        if (data.screen === "DETAILS") {
            console.log("\n👤 DETAILS SCREEN - Extracting appointment data");
            
            const appointmentData = {
                department: data.payload?.department || data.data?.department || "",
                location: data.payload?.location || data.data?.location || "",
                date: data.payload?.date || data.data?.date || "",
                time: data.payload?.time || data.data?.time || "",
                name: data.payload?.name || "",
                phone: data.payload?.phone || "",
                email: data.payload?.email || ""
            };
            
            responseBody.data = appointmentData;
            
            console.log("✅ DETAILS DATA PREPARED:");
            console.log("   Service:", appointmentData.department);
            console.log("   Location:", appointmentData.location);
            console.log("   Date:", appointmentData.date);
            console.log("   Time:", appointmentData.time);
            
            return res.status(200).send(encryptResponse(responseBody, aesKey, iv));
        }

        // #4 SUMMARY SCREEN - Format display data
        if (data.screen === "SUMMARY") {
            console.log("\n📋 SUMMARY SCREEN - Formatting final display");
            
            const bookingData = {
                department: data.payload?.department || data.data?.department,
                location: data.payload?.location || data.data?.location,
                date: data.payload?.date || data.data?.date,
                time: data.payload?.time || data.data?.time,
                name: data.payload?.name || data.data?.name,
                phone: data.payload?.name || data.data?.phone,
                email: data.payload?.email || data.data?.email
            };
            
            console.log("📦 RAW BOOKING DATA:", bookingData);

            // Format display strings
            const appointmentText = `${DEPT_NAMES[bookingData.department] || bookingData.department} at ${LOC_NAMES[bookingData.location] || bookingData.location}`;
            const detailsText = `${bookingData.name}\n${bookingData.phone}\n${bookingData.email}`;

            responseBody.data = {
                department: bookingData.department,
                location: bookingData.location,
                date: bookingData.date,
                time: bookingData.time,
                name: bookingData.name,
                phone: bookingData.phone,
                email: bookingData.email,
                appointment: appointmentText,
                details: detailsText
            };
            
            console.log("✅ SUMMARY DISPLAY TEXT:");
            console.log("   Appointment:", appointmentText);
            console.log("   Details:\n" + detailsText);
            
            return res.status(200).send(encryptResponse(responseBody, aesKey, iv));
        }

        // #5 CONFIRM BOOKING - Final submission
        if (data.action === "data_exchange" && data.payload?.action === "confirm_booking") {
            console.log("\n🎉 BOOKING CONFIRMED! SAVING DATA:");
            console.log("👤 Customer:", data.data?.name || "Unknown");
            console.log("📅 Appointment:", `${data.data?.date} ${data.data?.time}`);
            console.log("📍 Location:", LOC_NAMES[data.data?.location]);
            console.log("✂️ Service:", DEPT_NAMES[data.data?.department]);
            
            // TODO: Save to database here
            
            responseBody = {
                version: "3.0",
                type: "TERMINATE",
                screen: "SUMMARY",
                data: {
                    extension_message_response: {
                        params: {
                            flow_token: data.flow_token,
                            status: "success",
                            message: `✅ *Appointment Confirmed!*\n\n👤 ${data.data?.name || "Customer"}\n📅 ${data.data?.date} at ${data.data?.time}\n📍 ${LOC_NAMES[data.data?.location] || data.data?.location}\n✂️ ${DEPT_NAMES[data.data?.department] || data.data?.department}`
                        }
                    }
                }
            };
            
            console.log("🏁 Flow terminated successfully");
            return res.status(200).send(encryptResponse(responseBody, aesKey, iv));
        }

        // Fallback
        console.log("⚠️ Unknown screen/action - sending empty response");
        res.status(200).send(encryptResponse(responseBody, aesKey, iv));

    } catch (error) {
        console.error("💥 ERROR:", error);
        res.status(421).send("Error");
    }
});

app.listen(PORT, () => {
    console.log(`\n🚀 WhatsApp Flow Server running on port ${PORT}`);
    console.log("✅ Dynamic dates/times enabled");
    console.log("✅ Detailed logging enabled");
    console.log("✅ Ready for frontend flow!\n");
});

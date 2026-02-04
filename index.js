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
        if (!req.body.encrypted_flow_data) return res.status(200).send("Active");

        const { data, aesKey, iv } = decryptRequest(req.body);
        const screen = data.screen;
        const action = data.action;
        const input = data.data || {}; // Flow mathi aavto data

        let responseBody = { version: "3.0", screen: screen, data: {} };

        // STEP 1: Pehli screen (APPOINTMENT) load thava mate
        if (action === "INIT") {
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
        }

        // STEP 2: DETAILS screen par carry forward thava mate (Tamari JSON ma 'navigate' chhe)
        // Note: Navigate backend call nathi kartu, pan DETAILS screen par dynamic placeholder mate
        // Jyare 'data_exchange' SUMMARY mate thase tyare backend active thase.

        // STEP 3: SUMMARY Screen (Review Time) - Aa Accurate Logic Chhe
        else if (screen === "DETAILS" && action === "data_exchange") {
            const deptTitle = DEPT_NAMES[input.department] || input.department;
            const locTitle = LOC_NAMES[input.location] || input.location;
            
            responseBody.screen = "SUMMARY";
            responseBody.data = {
                // Formatting for ${data.appointment}
                appointment: `${deptTitle} Department at ${locTitle}\n${input.date} at ${input.time}.`,
                
                // Formatting for ${data.details}
                details: `Name: ${input.name}\nEmail: ${input.email}\nPhone: ${input.phone}\n\n${input.more_details || ""}`,
                
                // Carry forward original values to use in Confirm Appointment footer
                department: input.department,
                location: input.location,
                date: input.date,
                time: input.time,
                name: input.name,
                email: input.email,
                phone: input.phone,
                more_details: input.more_details
            };
        }

        // STEP 4: Final Confirmation (data_exchange from SUMMARY screen)
        else if (screen === "SUMMARY" && action === "data_exchange") {
            return res.status(200).send(encryptResponse({
                version: "3.0",
                type: "TERMINATE",
                data: {
                    extension_message_response: {
                        params: {
                            flow_token: data.flow_token,
                            status: "success",
                            message: "✅ Appointment Confirmed!"
                        }
                    }
                }
            }, aesKey, iv));
        }

        return res.status(200).send(encryptResponse(responseBody, aesKey, iv));

    } catch (error) {
        console.error("💥 Error:", error.message);
        res.status(421).send("Error");
    }
});

app.listen(PORT, () => console.log(`🚀 Server on port ${PORT}`));

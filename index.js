
import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 10000;

// Render variable mathi key lese
const rawKey = process.env.PRIVATE_KEY || "";

// PEM format converter
const formatPrivateKey = (key) => {
    if (!key) return "";
    if (key.includes('BEGIN PRIVATE KEY')) return key;
    const wrappedKey = key.replace(/\s/g, '').replace(/(.{64})/g, "$1\n");
    return `-----BEGIN PRIVATE KEY-----\n${wrappedKey}\n-----END PRIVATE KEY-----`;
};

const PRIVATE_KEY = formatPrivateKey(rawKey);

// --- CRYPTO HELPERS ---
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

// --- DYNAMIC DATA GENERATORS ---
function getDynamicDates() {
    const options = [];
    let d = new Date();
    while (options.length < 7) {
        if (d.getDay() !== 0 && d.getDay() !== 6) {
            options.push({ 
                id: d.toISOString().split('T')[0], 
                title: d.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' }) 
            });
        }
        d.setDate(d.getDate() + 1);
    }
    return options;
}

function getDynamicTimes() {
    const slots = [];
    for (let h = 11; h < 18; h++) {
        ["00", "30"].forEach(m => {
            const displayH = h > 12 ? h - 12 : h;
            const ampm = h >= 12 ? "PM" : "AM";
            slots.push({ id: `${displayH}:${m} ${ampm}`, title: `${displayH}:${m} ${ampm}` });
        });
    }
    return slots;
}

let bookedSlots = new Set();

// --- MAIN ENDPOINT ---
// ... (Crypto helpers and dynamic generators same rehse)

app.post("/flow", (req, res) => {
  try {
    if (!req.body.encrypted_flow_data) return res.status(200).send("Active");

    const { data, aesKey, iv } = decryptRequest(req.body);
    console.log("🔍 RAW DATA:", JSON.stringify(data, null, 2));
    console.log("📱 Screen:", data.screen || "NONE");
    console.log("⚡ Action:", data.action);
    console.log("📦 Payload:", data.payload || "EMPTY");

    let responseBody = { version: "3.0", screen: data.screen || "APPOINTMENT", data: {} };

    // 🚀 NEW: Handle custom navigation actions
    if (data.action === "go_to_summary") {
      console.log("🎉 GO TO SUMMARY!");
      responseBody.screen = "SUMMARY";
      responseBody.data = {
        name: data.payload?.name || data.name || "Not provided",
        phone: data.payload?.phone || data.phone || "Not provided",
        date: data.payload?.date || data.date || "Not selected", 
        time: data.payload?.time || data.time || "Not selected"
      };
      console.log("✅ SUMMARY DATA:", responseBody.data);
      return res.status(200).send(encryptResponse(responseBody, aesKey, iv));
    }

    if (data.action === "go_to_details") {
      console.log("✅ GO TO DETAILS!");
      bookedSlots.add(`${data.payload.date}_${data.payload.time}`);
      responseBody.screen = "DETAILS";
      responseBody.data = {
        date: data.payload.date,
        time: data.payload.time
      };
      return res.status(200).send(encryptResponse(responseBody, aesKey, iv));
    }

    // PING
    if (data.action === "ping") {
      return res.status(200).send(encryptResponse({ data: { status: "active" } }, aesKey, iv));
    }

    // INIT
    if (data.action === "INIT") {
      responseBody.data = { 
        date_options: getDynamicDates(), 
        time_options: getDynamicTimes()
      };
      return res.status(200).send(encryptResponse(responseBody, aesKey, iv));
    }

    // SUMMARY Confirm
    if (data.action === "data_exchange" && data.screen === "SUMMARY") {
      console.log("✅ BOOKING CONFIRMED!");
      responseBody = { 
        version: "3.0", 
        type: "TERMINATE",
        screen: "SUMMARY",
        data: {
          ...data.data,
          extension_message_response: {
            params: {
              flow_token: data.flow_token,
              status: "success",
              message: "Appointment booked successfully! 🎉"
            }
          }
        }
      };
      return res.status(200).send(encryptResponse(responseBody, aesKey, iv));
    }

    // APPOINTMENT date/time selection
    if (data.action === "data_exchange" && data.screen === "APPOINTMENT") {
      const date = data.date || data.data?.date;
      const time = data.time || data.data?.time;
      
      if (date && !time) {
        responseBody.data = {
          date_options: getDynamicDates(),
          time_options: getDynamicTimes()
        };
      }
      return res.status(200).send(encryptResponse(responseBody, aesKey, iv));
    }

    res.status(200).send(encryptResponse(responseBody, aesKey, iv));
  } catch (error) {
    console.error("💥 ERROR:", error);
    res.status(421).send("Error");
  }
});





app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

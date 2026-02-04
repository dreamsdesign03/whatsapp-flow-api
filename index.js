
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

    let responseBody = { version: "3.0", screen: data.screen || "APPOINTMENT", data: {} };

    // #1 PING
    if (data.action === "ping") {
      console.log("🏓 PING");
      return res.status(200).send(encryptResponse({ data: { status: "active" } }, aesKey, iv));
    }

    // #2 INIT - Load APPOINTMENT data
    if (data.action === "INIT") {
      console.log("🚀 INIT - Loading APPOINTMENT data");
      responseBody.data = {
        department: [
          { id: "beauty", title: "Beauty & Personal Care" },
          { id: "shopping", title: "Shopping & Groceries" },
          { id: "clothing", title: "Clothing & Apparel" },
          { id: "electronics", title: "Electronics" },
          { id: "home", title: "Home Goods & Decor" }
        ],
        location: [
          { id: "1", title: "Vadodara Branch 1" },
          { id: "2", title: "Vadodara Branch 2" },
          { id: "3", title: "Alkapuri Store" },
          { id: "4", title: "Fatehgunj Outlet" }
        ],
        is_location_enabled: true,
        date: getDynamicDates(),  // Your existing function
        is_date_enabled: true,
        time: getDynamicTimes(),  // Your existing function  
        is_time_enabled: true
      };
      return res.status(200).send(encryptResponse(responseBody, aesKey, iv));
    }

    // #3 APPOINTMENT data_exchange (dropdown selections)
    if (data.action === "data_exchange" && data.screen === "APPOINTMENT") {
      console.log("📋 APPOINTMENT SELECTION:", data);
      
      // Refresh data on any selection
      responseBody.data = {
        department: [
          { id: "beauty", title: "Beauty & Personal Care" },
          { id: "shopping", title: "Shopping & Groceries" },
          { id: "clothing", title: "Clothing & Apparel" },
          { id: "electronics", title: "Electronics" },
          { id: "home", title: "Home Goods & Decor" }
        ],
        location: [
          { id: "1", title: "Vadodara Branch 1" },
          { id: "2", title: "Vadodara Branch 2" },
          { id: "3", title: "Alkapuri Store" },
          { id: "4", title: "Fatehgunj Outlet" }
        ],
        is_location_enabled: true,
        date: getDynamicDates(),
        is_date_enabled: true,
        time: getDynamicTimes(),
        is_time_enabled: true
      };
      return res.status(200).send(encryptResponse(responseBody, aesKey, iv));
    }

    // 🚨 #4 DETAILS Continue (data_exchange → SUMMARY)
    if (data.action === "data_exchange" && data.screen === "DETAILS") {
      console.log("🎉 DETAILS FORM SUBMITTED:", data);
      
      const bookingData = {
        department: data.department || data.payload?.department,
        location: data.location || data.payload?.location, 
        date: data.date || data.payload?.date,
        time: data.time || data.payload?.time,
        name: data.name || data.payload?.name,
        email: data.email || data.payload?.email,
        phone: data.phone || data.payload?.phone,
        more_details: data.more_details || data.payload?.more_details
      };

      // Format for SUMMARY display
      const deptNames = {
        beauty: "Beauty & Personal Care",
        shopping: "Shopping & Groceries", 
        clothing: "Clothing & Apparel",
        electronics: "Electronics",
        home: "Home Goods & Decor"
      };
      
      const locationNames = {
        "1": "Vadodara Branch 1",
        "2": "Vadodara Branch 2", 
        "3": "Alkapuri Store",
        "4": "Fatehgunj Outlet"
      };

      responseBody = {
        version: "3.0",
        screen: "SUMMARY",
        data: {
          // Formatted display strings
          appointment: `${deptNames[bookingData.department] || bookingData.department} at ${locationNames[bookingData.location] || bookingData.location}\n${bookingData.date} at ${bookingData.time}`,
          details: `Name: ${bookingData.name}\nEmail: ${bookingData.email}\nPhone: ${bookingData.phone}${bookingData.more_details ? `\n\n${bookingData.more_details}` : ""}`,
          
          // Raw data for confirm
          department: bookingData.department,
          location: bookingData.location,
          date: bookingData.date,
          time: bookingData.time,
          name: bookingData.name,
          email: bookingData.email,
          phone: bookingData.phone,
          more_details: bookingData.more_details
        }
      };
      
      console.log("✅ SUMMARY DATA PREPARED:", responseBody.data);
      return res.status(200).send(encryptResponse(responseBody, aesKey, iv));
    }

    // #5 SUMMARY Confirm (data_exchange → TERMINATE)
    if (data.action === "data_exchange" && data.screen === "SUMMARY") {
      console.log("✅ FINAL CONFIRMATION!");
      
      responseBody = {
        version: "3.0",
        type: "TERMINATE",
        screen: "SUMMARY",
        data: {
          extension_message_response: {
            params: {
              flow_token: data.flow_token,
              status: "success",
              message: "🎉 Appointment booked successfully!\n\nWe'll send you a confirmation soon."
            }
          }
        }
      };
      console.log("🛑 FLOW TERMINATED");
      return res.status(200).send(encryptResponse(responseBody, aesKey, iv));
    }

    // Fallback - stay on current screen
    console.log("⚠️ FALLBACK - staying on screen");
    res.status(200).send(encryptResponse(responseBody, aesKey, iv));

  } catch (error) {
    console.error("💥 ERROR:", error);
    res.status(421).send("Error");
  }
});





app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

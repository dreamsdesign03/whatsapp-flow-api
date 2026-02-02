import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 8080;

/* ==========================
   🔐 META PRIVATE KEY
========================== */
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

/* ==========================
   🧠 IN-MEMORY BOOKINGS
   (date => [time,time])
========================== */
const BOOKINGS = {};

/* ==========================
   🔐 DECRYPT REQUEST
========================== */
function decryptRequest(body) {
  const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;

  const aesKey = crypto.privateDecrypt(
    {
      key: PRIVATE_KEY,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    Buffer.from(encrypted_aes_key, "base64")
  );

  const flowBuffer = Buffer.from(encrypted_flow_data, "base64");
  const iv = Buffer.from(initial_vector, "base64");

  const tag = flowBuffer.slice(-16);
  const encrypted = flowBuffer.slice(0, -16);

  const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, iv);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]).toString("utf8");

  return {
    data: JSON.parse(decrypted),
    aesKey,
    iv,
  };
}

/* ==========================
   🔐 ENCRYPT RESPONSE
========================== */
function encryptResponse(data, aesKey, iv) {
  const flippedIv = Buffer.from(iv.map((b) => ~b));
  const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, flippedIv);

  return Buffer.concat([
    cipher.update(JSON.stringify(data), "utf8"),
    cipher.final(),
    cipher.getAuthTag(),
  ]).toString("base64");
}

/* ==========================
   📅 NEXT 7 WORKING DATES
========================== */
function getNext7WorkingDates() {
  const dates = [];
  let d = new Date();

  while (dates.length < 7) {
    d.setDate(d.getDate() + 1);
    const day = d.getDay(); // 0 Sun, 6 Sat
    if (day === 0 || day === 6) continue;

    const iso = d.toISOString().split("T")[0];
    const title = d.toLocaleDateString("en-US", {
      weekday: "short",
      month: "short",
      day: "numeric",
    });

    dates.push({ id: iso, title });
  }
  return dates;
}

/* ==========================
   ⏰ TIME SLOTS (11–6, 30min)
========================== */
function generateTimeSlots() {
  const slots = [];
  let start = 11 * 60;
  const end = 18 * 60;

  while (start < end) {
    const h1 = String(Math.floor(start / 60)).padStart(2, "0");
    const m1 = String(start % 60).padStart(2, "0");

    const next = start + 30;
    const h2 = String(Math.floor(next / 60)).padStart(2, "0");
    const m2 = String(next % 60).padStart(2, "0");

    slots.push({
      id: `${h1}:${m1}`,
      title: `${h1}:${m1} - ${h2}:${m2}`,
    });

    start = next;
  }
  return slots;
}

/* ==========================
   ❌ REMOVE BOOKED SLOTS
========================== */
function getAvailableSlots(date) {
  const all = generateTimeSlots();
  const booked = BOOKINGS[date] || [];
  return all.filter((s) => !booked.includes(s.id));
}

/* ==========================
   🚀 FLOW ENDPOINT
========================== */
app.post("/flow", (req, res) => {
  try {
    // Meta ping / Render health
    if (!req.body.encrypted_flow_data) {
      console.log("🟢 Ping received");
      return res.status(200).send("Active");
    }

    const { data, aesKey, iv } = decryptRequest(req.body);

    console.log("📥 FLOW ACTION:", JSON.stringify(data, null, 2));

    let response = {
      version: "3.0",
      screen: "APPOINTMENT",
      data: {},
    };

    /* ===== INIT ===== */
    if (!data.action || data.action === "INIT" || data.action === "ping") {
      const dates = getNext7WorkingDates();
      console.log("📅 Dates sent:", dates.map((d) => d.id));

      response.data = {
        date_options: dates,
        time_options: [],
      };
    }

    /* ===== DATE SELECTED ===== */
    if (data.action === "date_selected" && data.data?.date) {
      const date = data.data.date;
      const slots = getAvailableSlots(date);

      console.log(`⏰ Slots for ${date}:`, slots.map((s) => s.id));

      response.data = {
        time_options: slots,
      };
    }

    /* ===== CONFIRM BOOKING ===== */
    if (data.action === "complete_booking") {
      const { date, time, name, phone } = data.data;

      BOOKINGS[date] = BOOKINGS[date] || [];
      BOOKINGS[date].push(time);

      console.log("✅ BOOKED:", { date, time, name, phone });
      console.log("📦 CURRENT BOOKINGS:", BOOKINGS);
    }

    const encrypted = encryptResponse(response, aesKey, iv);
    return res.status(200).send(encrypted);
  } catch (err) {
    console.error("❌ FLOW ERROR:", err.message);
    return res.status(421).send("Error");
  }
});

/* ==========================
   🟢 START SERVER
========================== */
app.listen(PORT, () =>
  console.log(`🚀 WhatsApp Flow API live on ${PORT}`)
);

import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json());

const PORT = 8080;

/* 🔐 PRIVATE KEY (Meta se jo generate ki ho) */
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

/* 🔓 Decrypt */
function decrypt(body) {
  const aesKey = crypto.privateDecrypt(
    {
      key: PRIVATE_KEY,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256"
    },
    Buffer.from(body.encrypted_aes_key, "base64")
  );

  const flowData = Buffer.from(body.encrypted_flow_data, "base64");
  const iv = Buffer.from(body.initial_vector, "base64");

  const encrypted = flowData.slice(0, -16);
  const tag = flowData.slice(-16);

  const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, iv);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]).toString();

  return { data: JSON.parse(decrypted), aesKey, iv };
}

/* 🔒 Encrypt */
function encrypt(data, aesKey, iv) {
  const flippedIv = Buffer.from(iv.map(b => ~b));
  const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, flippedIv);

  return Buffer.concat([
    cipher.update(JSON.stringify(data)),
    cipher.final(),
    cipher.getAuthTag()
  ]).toString("base64");
}

/* 📅 DATA */
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
  if (!req.body.encrypted_flow_data) return res.send("OK");

  const { data, aesKey, iv } = decrypt(req.body);
  console.log("FLOW:", data);

  /* INITIAL LOAD */
  if (!data.action) {
    return res.send(
      encrypt(
        {
          data: {
            date_options: dates,
            time_options: [],
            is_time_enabled: false
          }
        },
        aesKey,
        iv
      )
    );
  }

  /* DATE SELECTED */
  if (data.action === "date_selected") {
    return res.send(
      encrypt(
        {
          data: {
            time_options: times,
            is_time_enabled: true
          }
        },
        aesKey,
        iv
      )
    );
  }

  /* FINAL SUBMIT */
  if (data.action === "complete_booking") {
    console.log("✅ BOOKED:", data);
    return res.send(encrypt({ data: { success: true } }, aesKey, iv));
  }

  res.send("OK");
});

app.listen(PORT, () =>
  console.log(`🚀 Flow backend running on ${PORT}`)
);

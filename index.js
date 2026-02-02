import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 8080;

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

// 🔐 DECRYPT
function decrypt(body) {
  const aesKey = crypto.privateDecrypt(
    {
      key: PRIVATE_KEY,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256"
    },
    Buffer.from(body.encrypted_aes_key, "base64")
  );

  const iv = Buffer.from(body.initial_vector, "base64");
  const encrypted = Buffer.from(body.encrypted_flow_data, "base64");

  const tag = encrypted.slice(-16);
  const data = encrypted.slice(0, -16);

  const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, iv);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([
    decipher.update(data),
    decipher.final()
  ]);

  return { payload: JSON.parse(decrypted), aesKey, iv };
}

// 🔐 ENCRYPT
function encrypt(payload, aesKey, iv) {
  const flippedIV = Buffer.from(iv.map(b => ~b));
  const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, flippedIV);

  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(payload)),
    cipher.final()
  ]);

  return Buffer.concat([encrypted, cipher.getAuthTag()]).toString("base64");
}

app.post("/flow", (req, res) => {
  try {
    if (!req.body.encrypted_flow_data) return res.sendStatus(200);

    const { payload, aesKey, iv } = decrypt(req.body);
    console.log("FLOW:", payload);

    // 🟢 HEALTH CHECK
    if (payload.action === "ping") {
      return res.send(encrypt({ data: { status: "active" } }, aesKey, iv));
    }

    // 🟢 INIT → LOAD DATES
    if (payload.action === "INIT") {
      return res.send(
        encrypt(
          {
            screen: "APPOINTMENT",
            data: {
              date_options: [
                { id: "2026-02-03", title: "Mon, Feb 3" },
                { id: "2026-02-04", title: "Tue, Feb 4" }
              ],
              time_options: []
            }
          },
          aesKey,
          iv
        )
      );
    }

    // 🟢 DATE SELECTED → LOAD TIMES
    if (payload.action === "date_selected") {
      return res.send(
        encrypt(
          {
            screen: "APPOINTMENT",
            data: {
              time_options: [
                { id: "10:00", title: "10:00 AM" },
                { id: "12:00", title: "12:00 PM" }
              ]
            }
          },
          aesKey,
          iv
        )
      );
    }

    // 🟢 FINAL SUBMIT
    if (payload.action === "complete_booking") {
      console.log("BOOKING CONFIRMED:", payload.data);
      return res.send(
        encrypt(
          { screen: "SUCCESS", data: {} },
          aesKey,
          iv
        )
      );
    }

    res.sendStatus(200);
  } catch (err) {
    console.error(err);
    res.sendStatus(421);
  }
});

app.listen(PORT, () =>
  console.log(`🚀 Flow backend running on ${PORT}`)
);

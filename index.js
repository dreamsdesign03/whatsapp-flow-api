import express from "express";
import crypto from "crypto";
import axios from "axios";

const app = express();
app.use(express.json());

// Railway માટે પોર્ટ સેટઅપ
const PORT = process.env.PORT || 8080; 
const N8N_WEBHOOK_URL = "https://n8n.srv891967.hstgr.cloud/webhook/1073466d-3451-4f8c-aec2-61cc763d2f64";

// તમારી પ્રાઈવેટ કી (Direct Code માં)
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

const decryptRequest = (body, privatePem) => {
  const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;
  const decryptedAesKey = crypto.privateDecrypt(
    { key: crypto.createPrivateKey(privatePem), padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
    Buffer.from(encrypted_aes_key, "base64")
  );
  const flowDataBuffer = Buffer.from(encrypted_flow_data, "base64");
  const initialVectorBuffer = Buffer.from(initial_vector, "base64");
  const TAG_LENGTH = 16;
  const encrypted_flow_data_body = flowDataBuffer.subarray(0, -TAG_LENGTH);
  const encrypted_flow_data_tag = flowDataBuffer.subarray(-TAG_LENGTH);
  const decipher = crypto.createDecipheriv("aes-128-gcm", decryptedAesKey, initialVectorBuffer);
  decipher.setAuthTag(encrypted_flow_data_tag);
  return {
    decryptedBody: JSON.parse(Buffer.concat([decipher.update(encrypted_flow_data_body), decipher.final()]).toString("utf-8")),
    aesKeyBuffer: decryptedAesKey,
    initialVectorBuffer
  };
};

const encryptResponse = (response, aesKeyBuffer, initialVectorBuffer) => {
  const flipped_iv = Buffer.from(initialVectorBuffer.map((byte) => ~byte));
  const cipher = crypto.createCipheriv("aes-128-gcm", aesKeyBuffer, flipped_iv);
  return Buffer.concat([cipher.update(JSON.stringify(response), "utf-8"), cipher.final(), cipher.getAuthTag()]).toString("base64");
};

app.post("/flow", async (req, res) => {
  try {
    if (!req.body.encrypted_flow_data) return res.status(200).send("OK");
    const { decryptedBody, aesKeyBuffer, initialVectorBuffer } = decryptRequest(req.body, PRIVATE_KEY);
    
    // --- Health Check (Ping) Fix ---
    if (decryptedBody.action === "ping") {
        const pingResponse = { data: { status: "active" } };
        console.log("✅ Health Check Ping Received");
        return res.send(encryptResponse(pingResponse, aesKeyBuffer, initialVectorBuffer));
    }

    console.log("✅ Decrypted Data:", decryptedBody);
    axios.post(N8N_WEBHOOK_URL, decryptedBody).catch(() => {});

    // Flow રિસ્પોન્સ
    const screenData = {
      version: "3.0",
      action: "complete", 
      screen: "SUMMARY", 
      data: {
        extension_message_response: {
          params: { "message": "Success" }
        }
      }
    };

    res.send(encryptResponse(screenData, aesKeyBuffer, initialVectorBuffer));
  } catch (error) {
    console.error("❌ Critical Error:", error.message);
    res.status(500).send("Internal Error");
  }
});

app.listen(PORT, '0.0.0.0', () => console.log(`🚀 App listening on port ${PORT}!`));

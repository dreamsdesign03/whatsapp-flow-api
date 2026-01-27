import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json({ limit: "5mb" }));

// 🔐 PRIVATE KEY (same pair as uploaded public key)
const PRIVATE_KEY = `
-----BEGIN PRIVATE KEY-----
MIIEpAIBAAKCAQEAme5LB3I4yh0u5mFdnNbXFMAPJAiUQ7pMSGG221TNVUqO8BFZ
2pgVYu3kFYJupLGp8YTnXlzblumrkh2R5pKju/zs7r0EUtRRNKOT3jAaWlbEF3Fa
1pcTcFtMPAhQpl6r1cMJqzYBo1yZGJbFFciLEtuMELufBvgz4QaZ0/Wi19lIf2A5
/op7Ix9lr0Hl9TesFjUX05djteZJkxjNBWkJiog1HNLSXQ3x+/pn0I5HCeBgSoxr
aNv517N26/QatBm939Mw/3gct7mIkP4CLPCpD2fNYLEuNTw8rm2GyzCZc35wvpv1
fLmvCwRpuUXi94wJWl/AKywcku3T4vQdErajoQIDAQABAoIBAAoIrntdxrXmERiT
YDbJClwf6NzAcmm3yyEsvW6uqHPW2Fptxx2orDw2pZeBWRUDP8CumSZdhzLfKH/t
zYTqKiIm6orlZ1K+5Ew6HXluSUl6Pm4IxZMXZfz89oszP46YvTrB6+9tJc4wSwp/
SXmSCP7BsO+mS0d5Bmi0tXJLoMHRHi7ol0AI9IrKSEPXwePa7RVonJn/YojBx+j2
F1m/dxfs/HU+CwmoKMRb5fkYHFfmyEr8CrhddlbmmnNbBzj0QUWFOLcqCtbdcsDv
2Y4OZJjTP9opqGHlt7epseYqaWqs8BFcjLB6Dt52HscWYTlNO5XKUbisP0qouJz9
rUwl7cECgYEA0NK5X9PRM1y+sYrptrRp0iPif/TtOrxobBRUFw3PDxa177NPza1Q
YlnmvVzUGkkrdltJpRr+mfso0xnCxwrnbR5ZMupm2+aVtONShS2CiYv7gXWvcICH
Vw33hr6got4fpGhH131xvPPAdRZ9T0Z9S9kkjlLSlq2u0wv8v7Ho8qsCgYEAvLTg
AuDiPAt7XfZSFpZUBv18qPjK95Z5/XNh74FCrU4vAx8OBxn50f/CgeIasBubA7dj
/aaK/sLWTeQU4z4U8EoyMCgUAnDDXs0ngPVdqhtm+4ijoD/YwVlszEg6p6gqYQ2p
kTtH/CCN8uK20ghmqDriiOqwS/QbVN838lzGYuMCgYAKDYr1DQpuMZHQlEJqFEdf
4XBe/piJElbolRXzQivsqwg5MOWvnh9XjMJp7VUcqtcXzI9ADouhOBEgEIZq9KBt
hV9/7v7iqTgdzC/Fz4oQOxfxhIvcm6NoUnjPGNA85vqY/JgwzI40LXvfZyTDMz6G
7z4uR9hxfo0DBfm19MelHwKBgQCjpDaeSGXnrA1PbkvBSpuTdD6mSRm5msQvBd/n
0jAAGcyq6ENB5US+1wvVlj2OemHy1xXe4I2oX014PlHevfdqaO0c1aSEeUTy8PVQ
33ZaDWlAtz0tujA9e07d18UFns8hWrexObcy7QgrmG7xtFdRi77m/J3lP8pzzx61
Db78AQKBgQDOC7zQiAvrw+zVNkFFNMpQFpjQIUpc0n0Wv6cdeo2xwILo5Z8gsNdr
A+svLf9KTGPxRy9leM46+VZrBUem8Rs9Ekdx+AKH4FQtL+Wb9Rw5mBxsYUeXLcON
NIhFIckFtvCogiXbkBnmvpav0J/IHC8KtM95jGHYjYtyg0SIHIP3uA==
-----END PRIVATE KEY-----
`;

function decryptAES(encryptedData, aesKey, iv) {
  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    aesKey,
    iv
  );
  let decrypted = decipher.update(encryptedData, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

function encryptAES(data, aesKey, iv) {
  const cipher = crypto.createCipheriv(
    "aes-256-cbc",
    aesKey,
    iv
  );
  let encrypted = cipher.update(data, "utf8", "base64");
  encrypted += cipher.final("base64");
  return encrypted;
}

app.post("/flow", (req, res) => {
  try {
    const {
      encrypted_flow_data,
      encrypted_aes_key,
      initial_vector,
    } = req.body;

    // 🛑 Meta strict validation
    if (!encrypted_flow_data || !encrypted_aes_key || !initial_vector) {
      return res.status(200).send("ERROR");
    }

    // 🔓 AES key decrypt (RSA)
    const aesKey = crypto.privateDecrypt(
      {
        key: PRIVATE_KEY,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(encrypted_aes_key, "base64")
    );

    const iv = Buffer.from(initial_vector, "base64");

    if (iv.length !== 16) {
      return res.status(200).send("ERROR");
    }

    // 🔓 Flow data decrypt
    const decrypted = decryptAES(
      encrypted_flow_data,
      aesKey,
      iv
    );

    console.log("✅ Decrypted Flow Payload:", decrypted);

    // 🟢 IMPORTANT:
    // Meta expects encrypted response EVEN recall ma
    const encryptedResponse = encryptAES("{}", aesKey, iv);

    res
      .status(200)
      .set("Content-Type", "text/plain")
      .send(encryptedResponse);

  } catch (err) {
    console.error("❌ Flow error:", err.message);
    // ❗ Meta still expects 200
    return res.status(200).send("ERROR");
  }
});

app.get("/", (req, res) => {
  res.send("Flow crypto server running");
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Flow crypto server running on port ${PORT}`);
});

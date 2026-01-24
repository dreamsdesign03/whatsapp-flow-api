import express from "express";

const app = express();
app.use(express.json());

app.post("/flow", (req, res) => {
  console.log("Incoming Flow Payload:", req.body);

  // FOR NOW just testing
  return res.json({
    status: "ok",
    message: "Flow API connected successfully"
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});

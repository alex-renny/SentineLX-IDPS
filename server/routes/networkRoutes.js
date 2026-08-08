import express from "express";
import { captureNetworkTraffic } from "../services/networkMonitor.js";

const router = express.Router();

router.get("/traffic", async (req, res) => {
  try {
    const traffic = await captureNetworkTraffic();

    res.json(traffic);
  } catch (error) {
    console.error(
      "Network monitoring error:",
      error.message
    );

    res.status(500).json({
      success: false,
      message: "Unable to capture network traffic",
      error: error.message,
    });
  }
});

export default router;
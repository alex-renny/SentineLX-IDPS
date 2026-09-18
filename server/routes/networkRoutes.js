import express from "express";
import { getNetworkTelemetry } from "../services/networkTelemetryService.js";

const router = express.Router();

router.get("/traffic", async (req, res) => {
  try {
    // Traffic is captured by the single detection worker. Returning its latest
    // scan prevents this endpoint from competing for the capture interface.
    res.json(getNetworkTelemetry());
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

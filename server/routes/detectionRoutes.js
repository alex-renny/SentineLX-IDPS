import express from "express";
import {
  runNetworkDetection
} from "../services/detectionService.js";
import { recordAuthFailure } from "../services/authEventService.js";

const router = express.Router();

router.get("/network", async (req, res) => {
  try {
    const result = await runNetworkDetection();

    res.json(result);
  } catch (error) {
    console.error(
      "Detection engine error:",
      error.message
    );

    res.status(500).json({
      success: false,
      message: "Detection engine failed",
      error: error.message
    });
  }
});

// Authentication services or log shippers submit failed SSH, FTP, HTTP, or
// RDP logins here. No usernames or passwords are accepted or stored.
router.post("/auth-events", async (req, res) => {
  try {
    const event = await recordAuthFailure(req.body || {});
    res.status(202).json({ success: true, event });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
});

export default router;

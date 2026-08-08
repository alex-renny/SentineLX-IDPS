import express from "express";
import {
  runNetworkDetection
} from "../services/detectionService.js";

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

export default router;
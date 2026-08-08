import express from "express";
import Alert from "../models/Alert.js";

const router = express.Router();

/*
|--------------------------------------------------------------------------
| Get alerts
|--------------------------------------------------------------------------
*/

router.get("/", async (req, res) => {
  try {
    const limit = Math.min(
      Number(req.query.limit) || 50,
      200
    );

    const alerts = await Alert.find()
      .sort({ detected_at: -1 })
      .limit(limit)
      .lean();

    res.json({
      success: true,
      count: alerts.length,
      alerts,
    });
  } catch (error) {
    console.error("Alert fetch error:", error);

    res.status(500).json({
      success: false,
      message: "Unable to fetch alerts",
    });
  }
});

/*
|--------------------------------------------------------------------------
| Alert statistics
|--------------------------------------------------------------------------
*/

router.get("/stats", async (req, res) => {
  try {
    const [
      total,
      critical,
      high,
      medium,
      low,
      blocked,
    ] = await Promise.all([
      Alert.countDocuments(),

      Alert.countDocuments({
        severity: "CRITICAL",
      }),

      Alert.countDocuments({
        severity: "HIGH",
      }),

      Alert.countDocuments({
        severity: "MEDIUM",
      }),

      Alert.countDocuments({
        severity: "LOW",
      }),

      Alert.countDocuments({
        status: "BLOCKED",
      }),
    ]);

    res.json({
      success: true,
      stats: {
        total,
        critical,
        high,
        medium,
        low,
        blocked,
      },
    });
  } catch (error) {
    console.error(
      "Alert statistics error:",
      error
    );

    res.status(500).json({
      success: false,
      message: "Unable to fetch alert statistics",
    });
  }
});

export default router;
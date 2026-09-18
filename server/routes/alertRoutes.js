import express from "express";
import Alert, { ALERT_TRANSITIONS } from "../models/Alert.js";
import { emitAlertUpdated } from "../services/alertService.js";
import {
  blockIp,
  getPreventionConfig,
  listFirewallRules,
  unblockIp,
} from "../services/preventionService.js";
import { audit } from "../services/auditService.js";
import { requireAdmin } from "../middleware/auth.js";

const router = express.Router();

function appendTimeline(alert, status, note) {
  alert.timeline = [
    ...(alert.timeline || []),
    {
      status,
      at: new Date(),
      note,
    },
  ];
}

async function transitionAlert(alert, nextStatus, note) {
  if (alert.status === nextStatus) {
    return alert;
  }

  if (!ALERT_TRANSITIONS[alert.status].includes(nextStatus)) {
    const error = new Error(
      `Cannot move from ${alert.status} to ${nextStatus}`
    );
    error.statusCode = 409;
    throw error;
  }

  alert.status = nextStatus;
  appendTimeline(alert, nextStatus, note);
  await alert.save();
  return alert;
}

router.get("/prevention", async (req, res) => {
  const prevention = getPreventionConfig();
  let rules = [];

  try {
    const listed = await listFirewallRules();
    if (listed?.success && Array.isArray(listed.rules)) {
      rules = listed.rules;
    }
  } catch (error) {
    console.error("Prevention rule list error:", error);
  }

  res.json({
    success: true,
    prevention: {
      ...prevention,
      rules,
    },
  });
});

router.post("/prevention/unblock", requireAdmin, async (req, res) => {
  try {
    const ip = String(req.body?.ip || "").trim();

    if (!ip) {
      return res.status(400).json({
        success: false,
        message: "IP address is required",
      });
    }

    const prevention = await unblockIp(ip);

    res.json({
      success: Boolean(prevention.success),
      prevention,
    });
  } catch (error) {
    console.error("Prevention unblock error:", error);

    res.status(500).json({
      success: false,
      message: error.message || "Unable to remove firewall rule",
    });
  }
});

router.get("/", async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 50, 200);
    const filter = {};

    if (req.query.status) {
      filter.status = String(req.query.status).toUpperCase();
    }

    const alerts = await Alert.find(filter)
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

router.get("/stats", async (req, res) => {
  try {
    const [
      total,
      critical,
      high,
      medium,
      low,
      detected,
      investigating,
      blocked,
      resolved,
    ] = await Promise.all([
      Alert.countDocuments(),
      Alert.countDocuments({ severity: "CRITICAL" }),
      Alert.countDocuments({ severity: "HIGH" }),
      Alert.countDocuments({ severity: "MEDIUM" }),
      Alert.countDocuments({ severity: "LOW" }),
      Alert.countDocuments({ status: "DETECTED" }),
      Alert.countDocuments({ status: "INVESTIGATING" }),
      Alert.countDocuments({ status: "BLOCKED" }),
      Alert.countDocuments({ status: "RESOLVED" }),
    ]);

    res.json({
      success: true,
      stats: {
        total,
        critical,
        high,
        medium,
        low,
        detected,
        investigating,
        blocked,
        resolved,
      },
    });
  } catch (error) {
    console.error("Alert statistics error:", error);

    res.status(500).json({
      success: false,
      message: "Unable to fetch alert statistics",
    });
  }
});

router.patch("/:id/status", requireAdmin, async (req, res) => {
  try {
    const nextStatus = String(req.body?.status || "").toUpperCase();
    const allowed = Object.keys(ALERT_TRANSITIONS);

    if (!allowed.includes(nextStatus)) {
      return res.status(400).json({
        success: false,
        message: "Invalid alert status",
      });
    }

    const alert = await Alert.findById(req.params.id);

    if (!alert) {
      return res.status(404).json({
        success: false,
        message: "Alert not found",
      });
    }

    const updated = await transitionAlert(
      alert,
      nextStatus,
      req.body?.note || `Status set to ${nextStatus}`
    );

    const payload = updated.toObject();
    emitAlertUpdated(payload);

    res.json({ success: true, alert: payload });
  } catch (error) {
    console.error("Alert status update error:", error);

    res.status(error.statusCode || 500).json({
      success: false,
      message: error.message || "Unable to update alert status",
    });
  }
});

router.post("/:id/investigate", requireAdmin, async (req, res) => {
  try {
    const alert = await Alert.findById(req.params.id);

    if (!alert) {
      return res.status(404).json({
        success: false,
        message: "Alert not found",
      });
    }

    const updated = await transitionAlert(
      alert,
      "INVESTIGATING",
      "Analyst opened investigation"
    );

    const payload = updated.toObject();
    emitAlertUpdated(payload);

    res.json({ success: true, alert: payload });
  } catch (error) {
    res.status(error.statusCode || 500).json({
      success: false,
      message: error.message || "Unable to investigate alert",
    });
  }
});

router.post("/:id/block", requireAdmin, async (req, res) => {
  try {
    const alert = await Alert.findById(req.params.id);

    if (!alert) {
      return res.status(404).json({
        success: false,
        message: "Alert not found",
      });
    }

    if (!alert.source_ip) {
      return res.status(400).json({
        success: false,
        message: "Alert has no source IP to block",
      });
    }

    const prevention = await blockIp(
      alert.source_ip,
      `Manual block for ${alert.type}`
    );
    audit(prevention.success ? "PREVENTION_TRIGGERED" : "PREVENTION_FAILED", {
      action: prevention.action,
      alertType: alert.type,
    });

    alert.prevention = prevention;
    alert.prevention_action = prevention.action || "NONE";

    if (!prevention.success) {
      await alert.save();
      emitAlertUpdated(alert.toObject());

      return res.status(502).json({
        success: false,
        message: prevention.reason || prevention.error || "Block failed",
        alert: alert.toObject(),
        prevention,
      });
    }

    const note =
      prevention.action === "BLOCK_SIMULATED"
        ? `Simulated firewall rule ${prevention.rule}`
        : `Windows Firewall rule ${prevention.rule}`;

    const updated = await transitionAlert(alert, "BLOCKED", note);
    const payload = updated.toObject();
    emitAlertUpdated(payload);

    res.json({
      success: true,
      alert: payload,
      prevention,
    });
  } catch (error) {
    console.error("Alert block error:", error);

    res.status(error.statusCode || 500).json({
      success: false,
      message: error.message || "Unable to block source IP",
    });
  }
});

router.post("/:id/resolve", requireAdmin, async (req, res) => {
  try {
    const alert = await Alert.findById(req.params.id);

    if (!alert) {
      return res.status(404).json({
        success: false,
        message: "Alert not found",
      });
    }

    const shouldUnblock = Boolean(req.body?.unblock);

    if (shouldUnblock && alert.source_ip) {
      const prevention = await unblockIp(alert.source_ip);
      alert.prevention = {
        ...(alert.prevention || {}),
        unblock: prevention,
      };
      alert.prevention_action = prevention.action || alert.prevention_action;

      if (!prevention.success) {
        await alert.save();
        emitAlertUpdated(alert.toObject());
        return res.status(502).json({
          success: false,
          message: prevention.reason || prevention.error || "Unable to remove firewall rule",
          alert: alert.toObject(),
          prevention,
        });
      }
    }

    const updated = await transitionAlert(
      alert,
      "RESOLVED",
      shouldUnblock
        ? "Resolved and firewall rule removed"
        : "Alert marked resolved"
    );

    const payload = updated.toObject();
    emitAlertUpdated(payload);

    res.json({ success: true, alert: payload });
  } catch (error) {
    console.error("Alert resolve error:", error);

    res.status(error.statusCode || 500).json({
      success: false,
      message: error.message || "Unable to resolve alert",
    });
  }
});

export default router;

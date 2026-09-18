import express from "express";
import { getSettings, saveSettings } from "../services/settingsService.js";
import { restartDetectionWorker } from "../services/detectionWorker.js";

const router = express.Router();
router.get("/", async (_req, res) => { try { res.json({ success: true, settings: await getSettings() }); } catch (error) { res.status(500).json({ success: false, message: "Unable to load settings" }); } });
router.put("/", async (req, res) => {
  try {
    if (req.body?.prevention?.mode === "active" && req.body?.enforcementConfirmation !== "ENABLE_ENFORCEMENT") return res.status(400).json({ success: false, message: "Enforcement mode requires explicit confirmation" });
    const settings = await saveSettings(req.body);
    restartDetectionWorker();
    res.json({ success: true, settings, message: "Configuration saved and detection engine restarted" });
  } catch (error) { res.status(error.statusCode || 500).json({ success: false, message: error.message || "Unable to save settings" }); }
});
export default router;

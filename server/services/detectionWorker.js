import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

import { broadcastAlert } from "./alertService.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const workerPath = path.resolve(
  __dirname,
  "../../detection-engine/worker.py"
);

let worker = null;

export function startDetectionWorker() {
  if (worker) {
    console.log("⚠️ Detection worker is already running");
    return;
  }

  console.log("🛡️ Starting SentinelX detection engine...");

  worker = spawn(
    "python",
    [workerPath],
    {
      cwd: path.dirname(workerPath),
      stdio: ["ignore", "pipe", "pipe"]
    }
  );

  worker.stdout.on("data", (data) => {
    const lines = data
      .toString()
      .split(/\r?\n/)
      .filter(Boolean);

    for (const line of lines) {
      try {
        const event = JSON.parse(line);

        if (event.type === "ENGINE_STATUS") {
          console.log(
            `🛡️ Detection Engine: ${event.status}`
          );
        }

        if (event.type === "SCAN_COMPLETE") {
          console.log(
            `📡 Network scan: ${event.packet_count} packets, ${event.alert_count} alerts`
          );
        }

        if (event.type === "SECURITY_ALERT") {
          console.log("🚨 SECURITY ALERT");

          broadcastAlert(event.alert);
        }

        if (event.type === "ENGINE_ERROR") {
          console.error(
            "❌ Detection Engine:",
            event.error
          );
        }
      } catch {
        console.log(
          "Detection engine output:",
          line
        );
      }
    }
  });

  worker.stderr.on("data", (data) => {
    console.error(
      "Detection Engine stderr:",
      data.toString()
    );
  });

  worker.on("error", (error) => {
    console.error(
      "❌ Failed to start detection engine:",
      error.message
    );

    worker = null;
  });

  worker.on("close", (code) => {
    console.log(
      `🛡️ Detection engine stopped with code ${code}`
    );

    worker = null;
  });
}

export function stopDetectionWorker() {
  if (!worker) {
    return;
  }

  console.log("🛑 Stopping detection engine...");

  worker.kill();

  worker = null;
}
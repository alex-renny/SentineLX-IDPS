import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const eventFile = path.resolve(
  __dirname,
  "../../detection-engine/data/auth-events.jsonl"
);
const supportedServices = new Set(["SSH", "FTP", "HTTP", "RDP"]);

export async function recordAuthFailure(input) {
  const service = String(input.service || "").toUpperCase();

  if (!input.source_ip || !supportedServices.has(service)) {
    throw new Error("source_ip and service (SSH, FTP, HTTP, or RDP) are required");
  }

  const event = {
    event_type: "AUTH_FAILURE",
    source_ip: input.source_ip,
    target: input.target || "unknown",
    service,
    timestamp: input.timestamp || new Date().toISOString(),
  };

  await fs.mkdir(path.dirname(eventFile), { recursive: true });
  await fs.appendFile(eventFile, `${JSON.stringify(event)}\n`, "utf8");

  return event;
}

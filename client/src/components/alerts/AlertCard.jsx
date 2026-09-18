import { useState } from "react";
import { ShieldAlert } from "lucide-react";
import api from "../../services/api";

const STATUS_STYLES = {
  DETECTED: "border-red-500/20 bg-red-500/10 text-red-400",
  INVESTIGATING: "border-amber-500/20 bg-amber-500/10 text-amber-300",
  BLOCKED: "border-emerald-500/20 bg-emerald-500/10 text-emerald-400",
  RESOLVED: "border-slate-500/20 bg-slate-500/10 text-slate-300",
};

const LIFECYCLE = ["DETECTED", "INVESTIGATING", "BLOCKED", "RESOLVED"];

export async function updateAlertWorkflow(alertId, action, body = {}) {
  const response = await api.post(`/alerts/${alertId}/${action}`, body, {
    timeout: 30000,
  });
  return response.data.alert;
}

function ruleNameFor(ip, prefix = "SentinelX-IDPS-BLOCK") {
  if (!ip) {
    return null;
  }

  return `${prefix}-${ip.replaceAll(".", "_")}`;
}

export default function AlertCard({
  alert,
  onUpdated,
  showTimeline = false,
  prevention,
}) {
  const status = alert.status || "DETECTED";
  const [busy, setBusy] = useState(false);
  const [confirmBlock, setConfirmBlock] = useState(false);
  const liveBlocking = Boolean(prevention?.live_blocking);
  const rule =
    alert.prevention?.rule ||
    ruleNameFor(alert.source_ip, prevention?.rule_prefix);

  const runAction = async (action, body) => {
    try {
      setBusy(true);
      const updated = await updateAlertWorkflow(
        alert._id || alert.id,
        action,
        body
      );
      onUpdated?.(updated);
    } catch (error) {
      console.error("Alert workflow error:", error);
      window.alert(
        error.response?.data?.message || "Unable to update this alert"
      );
    } finally {
      setBusy(false);
      setConfirmBlock(false);
    }
  };

  return (
    <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex items-start gap-3">
          <div className="rounded-lg bg-red-500/10 p-2 text-red-400">
            <ShieldAlert size={18} />
          </div>

          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-semibold text-red-400">
                {alert.type}
              </span>

              <span className="rounded-md bg-red-500/10 px-2 py-1 text-[10px] font-bold text-red-400">
                {alert.severity}
              </span>

              <span
                className={`rounded-md border px-2 py-1 text-[10px] font-bold ${
                  STATUS_STYLES[status] || STATUS_STYLES.DETECTED
                }`}
              >
                {status}
              </span>
            </div>

            <p className="mt-1 text-sm text-slate-400">
              {alert.message}
            </p>
          </div>
        </div>

        <div className="text-left sm:text-right">
          <p className="font-mono text-xs text-cyan-400">
            {alert.source_ip || "Unknown IP"}
          </p>

          <p className="mt-1 text-[10px] text-slate-600">
            {alert.detected_at || alert.received_at
              ? new Date(
                  alert.detected_at || alert.received_at
                ).toLocaleTimeString()
              : ""}
          </p>
        </div>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-2">
        {LIFECYCLE.map((step, index) => {
          const currentIndex = LIFECYCLE.indexOf(status);
          const reached = index <= currentIndex;

          return (
            <div key={step} className="flex items-center gap-2">
              {index > 0 && (
                <span className="text-[10px] text-slate-600">→</span>
              )}
              <span
                className={`rounded-md px-2 py-1 text-[10px] font-semibold ${
                  step === status
                    ? STATUS_STYLES[step]
                    : reached
                    ? "bg-slate-800 text-slate-300"
                    : "bg-slate-950 text-slate-600"
                }`}
              >
                {step}
              </span>
            </div>
          );
        })}
      </div>

      {(alert.ports_detected || alert.window_seconds || alert.attempts || alert.packets_per_second || alert.target) && (
        <div className="mt-3 flex flex-wrap gap-2">
          {alert.ports_detected > 0 && (
            <span className="rounded-lg border border-orange-500/10 bg-orange-500/5 px-3 py-1.5 text-[11px] text-orange-400">
              🔌 {alert.ports_detected} ports detected
            </span>
          )}

          {alert.window_seconds > 0 && (
            <span className="rounded-lg border border-purple-500/10 bg-purple-500/5 px-3 py-1.5 text-[11px] text-purple-400">
              ⏱️ {alert.window_seconds}s detection window
            </span>
          )}

          {alert.attempts > 0 && (
            <span className="rounded-lg border border-yellow-500/10 bg-yellow-500/5 px-3 py-1.5 text-[11px] text-yellow-300">
              🔐 {alert.attempts} failed {alert.service || "login"} attempts
            </span>
          )}

          {alert.packets_per_second > 0 && (
            <span className="rounded-lg border border-red-500/10 bg-red-500/5 px-3 py-1.5 text-[11px] text-red-300">
              🌊 {alert.packets_per_second} packets/s (limit {alert.threshold})
            </span>
          )}

          {alert.target && (
            <span className="rounded-lg border border-cyan-500/10 bg-cyan-500/5 px-3 py-1.5 text-[11px] text-cyan-300">
              Target: {alert.target}
            </span>
          )}
        </div>
      )}

      {alert.prevention && (
        <div className="mt-3 rounded-xl border border-emerald-500/10 bg-emerald-500/5 p-3">
          <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-xs">
            <span className="font-semibold text-emerald-400">
              🛡️ Prevention
            </span>

            <span className="text-slate-400">
              Action:
              <span className="ml-1 font-semibold text-emerald-300">
                {alert.prevention.action || alert.prevention_action || "PROCESSED"}
              </span>
            </span>

            {alert.prevention.mode && (
              <span className="text-slate-400">
                Mode:
                <span className="ml-1 font-semibold text-cyan-400">
                  {alert.prevention.mode}
                </span>
              </span>
            )}

            {rule && (
              <span className="font-mono text-slate-400">
                Rule:
                <span className="ml-1 text-cyan-400">
                  {rule}
                </span>
              </span>
            )}
          </div>

          {alert.prevention.message && (
            <p className="mt-2 text-[11px] text-slate-500">
              {alert.prevention.message}
            </p>
          )}
        </div>
      )}

      {showTimeline && alert.timeline?.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-2">
          {alert.timeline.map((item, index) => (
            <span
              key={`${item.status}-${index}`}
              className="rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-1.5 text-[11px] text-slate-400"
            >
              {item.status}
              {item.note ? ` · ${item.note}` : ""}
            </span>
          ))}
        </div>
      )}

      {confirmBlock && (
        <div className="mt-4 rounded-xl border border-red-500/30 bg-red-500/10 p-4">
          <p className="text-sm font-semibold text-red-300">
            {liveBlocking
              ? "Create a real Windows Firewall block?"
              : "Simulate a firewall block?"}
          </p>
          <p className="mt-2 text-xs leading-5 text-slate-400">
            Source IP <span className="font-mono text-cyan-400">{alert.source_ip}</span>
            {rule ? (
              <>
                {" "}will map to{" "}
                <span className="font-mono text-cyan-400">{rule}</span>
              </>
            ) : null}
            . {liveBlocking
              ? "This can interrupt traffic from that host until you unblock it."
              : "Test mode will not change Windows Firewall."}
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            <button
              disabled={busy}
              onClick={() => runAction("block")}
              className="rounded-lg border border-red-500/20 bg-red-500/20 px-3 py-1.5 text-xs font-medium text-red-200 hover:bg-red-500/30 disabled:opacity-50"
            >
              {busy ? "Applying..." : liveBlocking ? "Create firewall rule" : "Simulate block"}
            </button>
            <button
              disabled={busy}
              onClick={() => setConfirmBlock(false)}
              className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-800"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      <div className="mt-4 flex flex-wrap gap-2">
        {status === "DETECTED" && (
          <button
            disabled={busy}
            onClick={() => runAction("investigate")}
            className="rounded-lg border border-amber-500/20 bg-amber-500/10 px-3 py-1.5 text-xs font-medium text-amber-300 hover:bg-amber-500/20 disabled:opacity-50"
          >
            Investigate
          </button>
        )}

        {(status === "DETECTED" || status === "INVESTIGATING") && (
          <button
            disabled={busy}
            onClick={() => setConfirmBlock(true)}
            className="rounded-lg border border-red-500/20 bg-red-500/10 px-3 py-1.5 text-xs font-medium text-red-300 hover:bg-red-500/20 disabled:opacity-50"
          >
            Block IP
          </button>
        )}

        {status !== "RESOLVED" && (
          <button
            disabled={busy}
            onClick={() => runAction("resolve", { unblock: false })}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-800 disabled:opacity-50"
          >
            Resolve
          </button>
        )}

        {status === "BLOCKED" && (
          <button
            disabled={busy}
            onClick={() => runAction("resolve", { unblock: true })}
            className="rounded-lg border border-cyan-500/20 bg-cyan-500/10 px-3 py-1.5 text-xs font-medium text-cyan-300 hover:bg-cyan-500/20 disabled:opacity-50"
          >
            Unblock & Resolve
          </button>
        )}
      </div>
    </div>
  );
}

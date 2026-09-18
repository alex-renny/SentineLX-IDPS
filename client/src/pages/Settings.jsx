import { useEffect, useState } from "react";
import Layout from "../components/layout/Layout";
import api from "../services/api";

export default function Settings() {
  const [prevention, setPrevention] = useState(null);
  const [busyIp, setBusyIp] = useState("");

  const load = async () => {
    try {
      const response = await api.get("/alerts/prevention");
      if (response.data.success) {
        setPrevention(response.data.prevention);
      }
    } catch (error) {
      console.error("Prevention settings error:", error);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const unblock = async (ip) => {
    const confirmed = window.confirm(
      `Remove SentinelX firewall rule for ${ip}?`
    );

    if (!confirmed) {
      return;
    }

    try {
      setBusyIp(ip);
      const response = await api.post(
        "/alerts/prevention/unblock",
        { ip },
        { timeout: 30000 }
      );

      if (!response.data.success) {
        window.alert(
          response.data.prevention?.error ||
            "Unable to remove this firewall rule"
        );
      }

      await load();
    } catch (error) {
      window.alert(
        error.response?.data?.message || "Unable to remove this firewall rule"
      );
    } finally {
      setBusyIp("");
    }
  };

  return (
    <Layout>
      <section className="mb-6">
        <p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">
          Platform
        </p>
        <h1 className="text-2xl font-bold text-white">Settings</h1>
      </section>

      <div className="max-w-2xl rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
        <h2 className="font-semibold text-white">Prevention engine</h2>
        <p className="mt-2 text-sm text-slate-500">
          Real Windows Firewall blocking stays off until you opt in. Test
          mode only records <span className="font-mono">BLOCK_SIMULATED</span>.
          Active mode still waits for Block IP confirmation unless auto-block
          is enabled.
        </p>

        <div className="mt-5 rounded-xl border border-slate-800 bg-slate-950/50 p-4">
          <p className="text-xs uppercase tracking-wider text-slate-500">
            Current mode
          </p>
          <p className="mt-2 text-lg font-semibold text-cyan-400">
            {prevention?.mode || "Loading..."}
          </p>
          <p className="mt-2 text-sm text-slate-400">
            {prevention?.warning}
          </p>
          <p className="mt-3 font-mono text-xs text-slate-500">
            Rule prefix: {prevention?.rule_prefix || "SentinelX-IDPS-BLOCK"}
          </p>
          <p className="mt-1 font-mono text-xs text-slate-500">
            Auto-block: {prevention?.auto_block ? "enabled" : "disabled"}
          </p>
        </div>

        <div className="mt-5 text-sm leading-6 text-slate-400">
          <p>To enable real blocking:</p>
          <ol className="mt-2 list-decimal space-y-1 pl-5">
            <li>Run the server as Administrator</li>
            <li>
              Set <span className="font-mono">SENTINELX_PREVENTION_MODE=active</span> in{" "}
              <span className="font-mono">server/.env</span>
            </li>
            <li>
              Leave <span className="font-mono">SENTINELX_PREVENTION_AUTO_BLOCK=false</span>{" "}
              so only confirmed dashboard blocks create rules
            </li>
            <li>Restart the Node server so the detection worker inherits the mode</li>
          </ol>
        </div>
      </div>

      <div className="mt-6 max-w-2xl rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
        <h2 className="font-semibold text-white">SentinelX firewall rules</h2>
        <p className="mt-2 text-sm text-slate-500">
          Only rules named like{" "}
          <span className="font-mono">SentinelX-IDPS-BLOCK-192_168_1_100</span>{" "}
          are listed. Test mode will not create these.
        </p>

        <div className="mt-5 space-y-3">
          {(prevention?.rules || []).length === 0 ? (
            <p className="text-sm text-slate-500">
              No SentinelX firewall rules are present.
            </p>
          ) : (
            prevention.rules.map((rule) => (
              <div
                key={rule.name}
                className="flex flex-col gap-3 rounded-xl border border-slate-800 bg-slate-950/50 p-4 sm:flex-row sm:items-center sm:justify-between"
              >
                <div>
                  <p className="font-mono text-xs text-cyan-400">{rule.name}</p>
                  <p className="mt-1 text-xs text-slate-500">
                    {rule.remote_ip || "Unknown IP"}
                    {rule.direction ? ` · ${rule.direction}` : ""}
                    {rule.enabled ? ` · ${rule.enabled}` : ""}
                  </p>
                </div>
                {rule.remote_ip && (
                  <button
                    disabled={busyIp === rule.remote_ip}
                    onClick={() => unblock(rule.remote_ip)}
                    className="rounded-lg border border-cyan-500/20 bg-cyan-500/10 px-3 py-1.5 text-xs font-medium text-cyan-300 hover:bg-cyan-500/20 disabled:opacity-50"
                  >
                    {busyIp === rule.remote_ip ? "Removing..." : "Remove rule"}
                  </button>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </Layout>
  );
}

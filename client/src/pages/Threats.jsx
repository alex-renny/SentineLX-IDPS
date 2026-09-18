import { useEffect, useState } from "react";
import { ShieldAlert } from "lucide-react";

import Layout from "../components/layout/Layout";
import AlertCard from "../components/alerts/AlertCard";
import api from "../services/api";
import socket from "../services/socket";

const FILTERS = [
  "ALL",
  "DETECTED",
  "INVESTIGATING",
  "BLOCKED",
  "RESOLVED",
];

export default function Threats() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [filter, setFilter] = useState("ALL");
  const [prevention, setPrevention] = useState(null);

  const applyAlert = (updated) => {
    setAlerts((previous) =>
      previous.map((item) =>
        (item._id || item.id) === (updated._id || updated.id)
          ? { ...item, ...updated }
          : item
      )
    );
  };

  const fetchData = async () => {
    try {
      const [alertsResponse, statsResponse, preventionResponse] =
        await Promise.all([
          api.get("/alerts?limit=100"),
          api.get("/alerts/stats"),
          api.get("/alerts/prevention"),
        ]);

      if (alertsResponse.data.success) {
        setAlerts(alertsResponse.data.alerts || []);
      }

      if (statsResponse.data.success) {
        setStats(statsResponse.data.stats);
      }

      if (preventionResponse.data.success) {
        setPrevention(preventionResponse.data.prevention);
      }
    } catch (error) {
      console.error("Threats fetch error:", error);
    }
  };

  useEffect(() => {
    fetchData();

    const handleSecurityAlert = (data) => {
      const alert = data.alert || data;

      setAlerts((previous) => {
        const alertId = alert._id || alert.id;

        if (
          alertId &&
          previous.some((item) => (item._id || item.id) === alertId)
        ) {
          return previous;
        }

        return [alert, ...previous].slice(0, 100);
      });
    };

    const handleAlertUpdated = (alert) => {
      applyAlert(alert);
    };

    socket.on("security-alert", handleSecurityAlert);
    socket.on("alert-updated", handleAlertUpdated);

    return () => {
      socket.off("security-alert", handleSecurityAlert);
      socket.off("alert-updated", handleAlertUpdated);
    };
  }, []);

  const visibleAlerts =
    filter === "ALL"
      ? alerts
      : alerts.filter((alert) => (alert.status || "DETECTED") === filter);

  return (
    <Layout>
      <section className="mb-6">
        <p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">
          Alert Lifecycle
        </p>

        <h1 className="text-2xl font-bold tracking-tight text-white sm:text-3xl">
          Threats
        </h1>

        <p className="mt-2 max-w-2xl text-sm text-slate-500">
          Move each alert through DETECTED → INVESTIGATING → BLOCKED → RESOLVED.
          Real firewall rules are created only after you confirm Block IP in active mode.
        </p>
      </section>

      {prevention && (
        <div className="mb-6 rounded-2xl border border-slate-800 bg-slate-900/60 p-4 text-sm text-slate-400">
          Prevention mode:{" "}
          <span className="font-semibold text-cyan-400">
            {prevention.mode}
          </span>
          {prevention.live_blocking ? " · live firewall" : " · simulated"}
          {prevention.auto_block ? " · auto-block on" : " · operator confirmation"}
          <p className="mt-2 text-xs text-slate-500">
            {prevention.warning}
          </p>
        </div>
      )}

      <section className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[
          ["Detected", stats?.detected ?? 0],
          ["Investigating", stats?.investigating ?? 0],
          ["Blocked", stats?.blocked ?? 0],
          ["Resolved", stats?.resolved ?? 0],
        ].map(([label, value]) => (
          <div
            key={label}
            className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4"
          >
            <p className="text-xs uppercase tracking-wider text-slate-500">
              {label}
            </p>
            <p className="mt-2 text-2xl font-bold text-white">{value}</p>
          </div>
        ))}
      </section>

      <div className="mb-5 flex flex-wrap gap-2">
        {FILTERS.map((item) => (
          <button
            key={item}
            onClick={() => setFilter(item)}
            className={`rounded-xl px-4 py-2 text-xs font-medium ${
              filter === item
                ? "bg-cyan-500/10 text-cyan-400"
                : "border border-slate-800 text-slate-400 hover:text-white"
            }`}
          >
            {item}
          </button>
        ))}
      </div>

      {visibleAlerts.length === 0 ? (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-8 text-center">
          <ShieldAlert size={28} className="mx-auto text-slate-700" />
          <p className="mt-3 text-sm text-slate-500">
            No alerts in this status
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {visibleAlerts.map((alert) => (
            <AlertCard
              key={alert._id || alert.id}
              alert={alert}
              showTimeline
              prevention={prevention}
              onUpdated={applyAlert}
            />
          ))}
        </div>
      )}
    </Layout>
  );
}

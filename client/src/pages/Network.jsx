import { useEffect, useState } from "react";
import Layout from "../components/layout/Layout";
import TrafficOverview from "../components/network/TrafficOverview";
import api from "../services/api";
import socket from "../services/socket";

export default function Network() {
  const [traffic, setTraffic] = useState(null);
  const [history, setHistory] = useState([]);

  useEffect(() => {
    const applyTraffic = (nextTraffic) => {
      setTraffic(nextTraffic);
      const packets = nextTraffic.duration
        ? Math.round((nextTraffic.packet_count || 0) / nextTraffic.duration)
        : 0;
      const bytes = (nextTraffic.packets || []).reduce((sum, item) => sum + (Number(item.packet_size) || 0), 0);
      setHistory((previous) => [...previous, { time: new Date(nextTraffic.timestamp || Date.now()).toLocaleTimeString(), packets, bytes }].slice(-12));
    };
    api.get("/network/traffic").then((response) => response.data.success && applyTraffic(response.data)).catch(console.error);
    socket.on("NETWORK_TRAFFIC", applyTraffic);
    return () => socket.off("NETWORK_TRAFFIC", applyTraffic);
  }, []);

  return <Layout><section><p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">Network visibility</p><h1 className="text-2xl font-bold text-white sm:text-3xl">Network Monitor</h1><p className="mt-2 text-sm text-slate-500">Live packet telemetry from the detection engine.</p></section><TrafficOverview traffic={traffic} history={history} /></Layout>;
}

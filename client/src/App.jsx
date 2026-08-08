import { Routes, Route } from "react-router-dom";

import Dashboard from "./pages/Dashboard";
import Network from "./pages/Network";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";
import Login from "./pages/Login";
import { useEffect } from "react";
import socket from "./services/socket";

function App() {
  useEffect(() => {
  console.log("🔌 SentinelX Socket:", socket.connected);

  return () => {
    // Don't disconnect here because the socket
    // should remain available to the application.
  };
}, []);
  return (
    <Routes>
      <Route path="/" element={<Dashboard />} />
      <Route path="/network" element={<Network />} />
      <Route path="/reports" element={<Reports />} />
      <Route path="/settings" element={<Settings />} />
      <Route path="/login" element={<Login />} />
    </Routes>
  );
}

export default App;
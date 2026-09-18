import { Navigate, Routes, Route } from "react-router-dom";

import Dashboard from "./pages/Dashboard";
import Network from "./pages/Network";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";
import Threats from "./pages/Threats";
import Login from "./pages/Login";
import Users from "./pages/Users";
import { useAuth } from "./context/useAuth";
import { useEffect } from "react";
import socket from "./services/socket";
import { connectSocket } from "./services/socket";

function App() {
  useEffect(() => {
  if (sessionStorage.getItem("sentinelx_token")) connectSocket();
  console.log("🔌 SentinelX Socket:", socket.connected);

  return () => {
    // Don't disconnect here because the socket
    // should remain available to the application.
  };
}, []);
  return (
    <Routes>
      <Route path="/" element={<Protected><Dashboard /></Protected>} />
      <Route path="/network" element={<Protected><Network /></Protected>} />
      <Route path="/threats" element={<Protected><Threats /></Protected>} />
      <Route path="/reports" element={<Protected><Reports /></Protected>} />
      <Route path="/settings" element={<Protected roles={["admin"]}><Settings /></Protected>} />
      <Route path="/prevention" element={<Protected roles={["admin"]}><Threats /></Protected>} />
      <Route path="/users" element={<Protected roles={["admin"]}><Users /></Protected>} />
      <Route path="/login" element={<Login />} />
    </Routes>
  );
}

function Protected({ children, roles }) { const { user } = useAuth(); if (!sessionStorage.getItem("sentinelx_token")) return <Navigate to="/login" replace />; if (roles && !roles.includes(user?.role)) return <Navigate to="/" replace />; return children; }

export default App;

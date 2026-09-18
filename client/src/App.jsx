import { Navigate, Routes, Route } from "react-router-dom";

import Dashboard from "./pages/Dashboard";
import Network from "./pages/Network";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";
import Threats from "./pages/Threats";
import Login from "./pages/Login";
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
      <Route path="/settings" element={<Protected><Settings /></Protected>} />
      <Route path="/login" element={<Login />} />
    </Routes>
  );
}

function Protected({ children }) { return sessionStorage.getItem("sentinelx_token") ? children : <Navigate to="/login" replace />; }

export default App;

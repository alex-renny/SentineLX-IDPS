import { io } from "socket.io-client";

const socket = io("http://localhost:5000", {
  autoConnect: true,
  transports: ["websocket", "polling"],
});

socket.on("connect", () => {
  console.log("🔌 Connected to SentinelX Socket.IO:", socket.id);
});

socket.on("disconnect", () => {
  console.log("🔌 Disconnected from SentinelX Socket.IO");
});

socket.on("connect_error", (error) => {
  console.error("❌ Socket.IO connection error:", error.message);
});

export default socket;
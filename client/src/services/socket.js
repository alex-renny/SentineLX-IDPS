import { io } from "socket.io-client";

const socket = io("http://localhost:5000", {
  autoConnect: true,
});

socket.on("connect", () => {
  console.log("🔌 Connected to SentinelX Socket.IO");
});

socket.on("disconnect", () => {
  console.log("🔌 Disconnected from SentinelX Socket.IO");
});

export default socket;
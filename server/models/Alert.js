import mongoose from "mongoose";

const alertSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      required: true,
      index: true,
    },

    severity: {
      type: String,
      enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
      default: "MEDIUM",
      index: true,
    },

    source_ip: {
      type: String,
      default: null,
      index: true,
    },

    destination_ip: {
      type: String,
      default: null,
    },

    ports_detected: {
      type: Number,
      default: 0,
    },

    window_seconds: {
      type: Number,
      default: 0,
    },

    message: {
      type: String,
      required: true,
    },

    status: {
      type: String,
      enum: ["DETECTED", "INVESTIGATING", "BLOCKED", "RESOLVED"],
      default: "DETECTED",
      index: true,
    },

    prevention_action: {
      type: String,
      default: "NONE",
    },

    detected_at: {
      type: Date,
      default: Date.now,
      index: true,
    },
  },
  {
    timestamps: true,
  }
);

export default mongoose.model("Alert", alertSchema);
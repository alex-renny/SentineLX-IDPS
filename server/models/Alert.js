import mongoose from "mongoose";

const timelineSchema = new mongoose.Schema(
  {
    status: {
      type: String,
      enum: ["DETECTED", "INVESTIGATING", "BLOCKED", "RESOLVED"],
      required: true,
    },
    at: {
      type: Date,
      default: Date.now,
    },
    note: {
      type: String,
      default: "",
    },
  },
  { _id: false }
);

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

    attempts: {
      type: Number,
      default: 0,
    },

    packets_per_second: {
      type: Number,
      default: 0,
    },

    peak_packets_per_second: { type: Number, default: 0 },

    sustained_packets_per_second: { type: Number, default: 0 },

    sustained_window_seconds: { type: Number, default: 0 },

    ddos_peak_threshold: { type: Number, default: 0 },

    sustained_threshold: { type: Number, default: 0 },

    classification: { type: String, default: "UNKNOWN" },

    validation_reason: { type: String, default: "" },

    threshold: {
      type: Number,
      default: 0,
    },

    target: {
      type: String,
      default: null,
    },

    service: {
      type: String,
      default: null,
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

    prevention: {
      type: mongoose.Schema.Types.Mixed,
      default: null,
    },

    timeline: {
      type: [timelineSchema],
      default: [],
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

export const ALERT_TRANSITIONS = {
  DETECTED: ["INVESTIGATING", "BLOCKED", "RESOLVED"],
  INVESTIGATING: ["BLOCKED", "RESOLVED"],
  BLOCKED: ["RESOLVED"],
  RESOLVED: [],
};

export default mongoose.model("Alert", alertSchema);

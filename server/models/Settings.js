import mongoose from "mongoose";

const settingsSchema = new mongoose.Schema({
  key: { type: String, unique: true, default: "global" },
  config: { type: mongoose.Schema.Types.Mixed, required: true },
}, { timestamps: true });

export default mongoose.model("Settings", settingsSchema);

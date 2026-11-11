import mongoose from "mongoose";
const { Schema } = mongoose;

const alertSchema = new Schema({
  flowId: { type: Schema.Types.ObjectId, ref: "Flow" },
  srcIp: { type: String, required: true, index: true },
  dstIp: { type: String, required: true },
  srcPort: Number, dstPort: Number, protocol: String,
  supervisedLabel: { type: String, required: true },
  supervisedConfidence: { type: Number, required: true },
  anomalyScore: { type: Number, required: true },
  anomalyFlag: Boolean,
  verdict: { type: String, enum: ["benign", "suspicious", "malicious"], required: true },
  severity: { type: String, enum: ["low", "medium", "high", "critical"], required: true },
  severityRank: Number,
  shapTopFeatures: [{ _id: false, feature: String, contribution: Number }],
  anomalyTopFeatures: [{ _id: false, feature: String, contribution: Number }],
  features: Schema.Types.Mixed,
  modelVersion: String,
  processingMs: Number,
  status: { type: String, enum: ["new", "acknowledged", "blocked", "resolved", "false_positive"], default: "new" },
  statusReason: String,
  statusUpdatedBy: Number,
  blockRuleId: Number,
  assignedToUserId: Number, // references Prisma User.id
  createdAt: { type: Date, default: Date.now },
}, { collection: "alerts" });
alertSchema.index({ severity: 1, status: 1, createdAt: -1 });
alertSchema.index({ severityRank: -1, createdAt: -1 });

const flowSchema = new Schema({}, { strict: false, collection: "flows" });

const intelSchema = new Schema({
  ip: { type: String, unique: true }, abuseScore: Number, country: String,
  lastReportedAt: String, source: String, lastChecked: Date,
}, { collection: "threatintel" });

const notificationSchema = new Schema({
  userId: { type: Number, index: true }, alertId: String, type: String, message: String,
  readFlag: { type: Boolean, default: false }, createdAt: { type: Date, default: Date.now },
}, { collection: "notifications" });
notificationSchema.index({ userId: 1, alertId: 1, type: 1 }, { unique: true }); // idempotent: one per event per user

const configSchema = new Schema({ _id: String }, { strict: false, collection: "config" });

export const Alert = mongoose.model("Alert", alertSchema);
export const Flow = mongoose.model("Flow", flowSchema);
export const ThreatIntel = mongoose.model("ThreatIntel", intelSchema);
export const Notification = mongoose.model("Notification", notificationSchema);
export const Config = mongoose.model("Config", configSchema);

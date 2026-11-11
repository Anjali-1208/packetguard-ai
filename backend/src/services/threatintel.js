import crypto from "crypto";
import { config } from "../config.js";
import { ThreatIntel } from "../models/index.js";

const DAY = 24 * 3600 * 1000;
const isPrivate = (ip) => /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);
const COUNTRIES = ["RU", "CN", "US", "BR", "IN", "NL", "DE", "VN", "KR", "FR"];

function simulated(ip) {
  const h = crypto.createHash("md5").update(ip).digest();
  return { abuseScore: isPrivate(ip) ? 0 : 35 + (h[0] % 66), country: isPrivate(ip) ? "-" : COUNTRIES[h[1] % COUNTRIES.length],
           lastReportedAt: new Date(Date.now() - (h[2] % 72) * 3600 * 1000).toISOString(), source: "simulated (set ABUSEIPDB_API_KEY for live data)" };
}
const strip = ({ _id, __v, ...r }) => r;

/** Cached 24h lookup. Returns {available:false} instead of throwing if the provider is down (FR-INTEL-03). */
export async function lookup(ip, { force = false } = {}) {
  const cached = await ThreatIntel.findOne({ ip }).lean();
  if (cached && !force && Date.now() - new Date(cached.lastChecked).getTime() < DAY) return { available: true, cached: true, ...strip(cached) };
  try {
    let data;
    if (config.abuseIpdbKey && !isPrivate(ip)) {
      const r = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
        { headers: { Key: config.abuseIpdbKey, Accept: "application/json" }, signal: AbortSignal.timeout(5000) });
      if (!r.ok) throw new Error("provider status " + r.status);
      const d = (await r.json()).data;
      data = { abuseScore: d.abuseConfidenceScore, country: d.countryCode || "-", lastReportedAt: d.lastReportedAt || null, source: "AbuseIPDB" };
    } else data = simulated(ip);
    const doc = await ThreatIntel.findOneAndUpdate({ ip }, { ...data, ip, lastChecked: new Date() }, { upsert: true, new: true }).lean();
    return { available: true, cached: false, ...strip(doc) };
  } catch (e) {
    console.warn("[threatintel] lookup failed:", e.message);
    return cached ? { available: true, cached: true, stale: true, ...strip(cached) } : { available: false };
  }
}

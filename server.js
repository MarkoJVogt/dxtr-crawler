import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runScan } from "./lib/scanner.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 80;

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Simple In-Memory Rate-Limit: max. 5 Scans pro IP pro 10 Minuten.
// Für Produktivbetrieb mit mehr Last: durch Redis-basiertes Limit ersetzen.
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000;
const RATE_LIMIT_MAX = 5;

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip) || { count: 0, windowStart: now };
  if (now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    entry.count = 0;
    entry.windowStart = now;
  }
  entry.count += 1;
  rateLimitMap.set(ip, entry);
  return entry.count <= RATE_LIMIT_MAX;
}

app.post("/api/scan", async (req, res) => {
  const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress;
  if (!checkRateLimit(ip)) {
    return res.status(429).json({ error: "Zu viele Scans. Bitte in einigen Minuten erneut versuchen." });
  }

  const { url } = req.body || {};
  if (!url || typeof url !== "string") {
    return res.status(400).json({ error: "Bitte eine gültige URL angeben." });
  }

  try {
    const result = await runScan(url);
    res.json(result);
  } catch (e) {
    res.status(400).json({ error: e.message || "Scan fehlgeschlagen." });
  }
});

app.get("/api/health", (_req, res) => res.json({ status: "ok" }));

app.listen(PORT, () => {
  console.log(`DXTR-Crawler läuft auf Port ${PORT}`);
});

import dns from "node:dns/promises";
import net from "node:net";

// Blockiert private, interne und link-local Adressbereiche, damit der
// Crawler nicht dazu missbraucht werden kann, interne Server, Docker-Netze
// oder Cloud-Metadaten-Endpunkte (z.B. 169.254.169.254) anzusprechen.
const BLOCKED_RANGES = [
  { start: "10.0.0.0", end: "10.255.255.255" },
  { start: "172.16.0.0", end: "172.31.255.255" },
  { start: "192.168.0.0", end: "192.168.255.255" },
  { start: "127.0.0.0", end: "127.255.255.255" },
  { start: "169.254.0.0", end: "169.254.255.255" },
  { start: "0.0.0.0", end: "0.255.255.255" },
];

function ipToLong(ip) {
  return ip.split(".").reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function isBlockedIPv4(ip) {
  const val = ipToLong(ip);
  return BLOCKED_RANGES.some((r) => val >= ipToLong(r.start) && val <= ipToLong(r.end));
}

export async function assertPublicHttpUrl(rawUrl) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error("Ungültige URL.");
  }
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Nur http/https-URLs sind erlaubt.");
  }
  if (url.hostname === "localhost" || url.hostname.endsWith(".local")) {
    throw new Error("Interne Adressen sind nicht erlaubt.");
  }
  if (net.isIP(url.hostname) === 4 && isBlockedIPv4(url.hostname)) {
    throw new Error("Private IP-Adressen sind nicht erlaubt.");
  }

  let addresses;
  try {
    addresses = await dns.lookup(url.hostname, { all: true });
  } catch {
    throw new Error("Domain konnte nicht aufgelöst werden.");
  }
  for (const addr of addresses) {
    if (addr.family === 4 && isBlockedIPv4(addr.address)) {
      throw new Error("Domain zeigt auf eine private/interne Adresse — Scan abgelehnt.");
    }
  }
  return url;
}

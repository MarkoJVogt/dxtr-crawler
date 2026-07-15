import { chromium } from "playwright";
import { parse as parseDomain } from "tldts";
import dns from "node:dns/promises";
import { classifyDomain } from "./trackerDatabase.js";
import { assertPublicHttpUrl } from "./ssrfGuard.js";

const NAV_TIMEOUT_MS = 20000;
const SCAN_TIMEOUT_MS = 35000;

const CONSENT_SIGNATURES = [
  "cookiebot.com",
  "onetrust.com",
  "usercentrics.eu",
  "usercentrics.com",
  "borlabs-cookie",
  "complianz",
  "cookieyes.com",
  "iubenda.com",
  "termly.io",
  "consentmanager.net",
];

const CONSENT_TEXT_PATTERNS = [
  /alle\s+akzeptieren/i,
  /cookies?\s+akzeptieren/i,
  /zustimmen/i,
  /einstellungen\s+verwalten/i,
  /accept\s+all/i,
  /manage\s+(cookie\s+)?preferences/i,
];

const LEGAL_LINK_PATTERNS = {
  impressum: /impressum|imprint|legal\s*notice/i,
  datenschutz: /datenschutz|privacy\s*policy|privacy\s*notice/i,
};

async function geolocateIp(ip) {
  try {
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,query`, {
      signal: AbortSignal.timeout(4000),
    });
    const data = await res.json();
    if (data.status === "success") return { country: data.country, countryCode: data.countryCode };
  } catch {
    /* ignore — geolocation is best-effort */
  }
  return null;
}

const EU_EWR = new Set([
  "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU",
  "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES",
  "SE", "IS", "LI", "NO",
]);

// Anycast-/CDN-Betreiber: die IP, die eine DNS-Auflösung liefert, zeigt bei
// diesen Anbietern oft nur den Firmensitz oder einen zufälligen Edge-Knoten,
// nicht den physischen Standort des tatsächlich antwortenden Servers. Eine
// harte Länderaussage ("Server steht in den USA") wäre hier irreführend.
// Diese Domains werden separat ausgewiesen statt in die Drittland-Bewertung
// einzufließen.
const ANYCAST_CDN_DOMAINS = new Set([
  "googleapis.com",
  "gstatic.com",
  "cloudflare.com",
  "cloudflareinsights.com",
  "akamai.net",
  "akamaized.net",
  "fastly.net",
  "jsdelivr.net",
  "unpkg.com",
  "cloudfront.net",
  "azureedge.net",
  "amazonaws.com",
]);

function isAnycastCdn(hostname) {
  const root = parseDomain(hostname).domain;
  return root ? ANYCAST_CDN_DOMAINS.has(root) : false;
}

export async function runScan(targetUrlRaw) {
  const targetUrl = await assertPublicHttpUrl(targetUrlRaw);
  const rootDomain = parseDomain(targetUrl.hostname).domain;

  const browser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
  const context = await browser.newContext({
    userAgent: "DXTR-Compliance-Scanner/0.1 (+https://dxtr.de)",
  });
  const page = await context.newPage();

  const requests = [];
  page.on("request", (req) => {
    try {
      const u = new URL(req.url());
      requests.push({ url: req.url(), host: u.hostname, resourceType: req.resourceType(), ts: Date.now() });
    } catch {
      /* ignore malformed URLs */
    }
  });

  let pageHtml = "";
  let navError = null;

  try {
    await Promise.race([
      (async () => {
        await page.goto(targetUrl.toString(), { waitUntil: "networkidle", timeout: NAV_TIMEOUT_MS });
        pageHtml = await page.content();
      })(),
      new Promise((_, reject) => setTimeout(() => reject(new Error("Scan-Timeout")), SCAN_TIMEOUT_MS)),
    ]);
  } catch (e) {
    navError = e.message;
    try {
      pageHtml = await page.content();
    } catch {
      pageHtml = "";
    }
  }

  const cookies = await context.cookies();
  await browser.close();

  // Third-Party-Requests klassifizieren
  const seenHosts = new Map();
  for (const r of requests) {
    const hostRoot = parseDomain(r.host).domain || r.host;
    if (hostRoot === rootDomain) continue; // first-party
    if (!seenHosts.has(r.host)) seenHosts.set(r.host, { host: r.host, count: 0, resourceTypes: new Set() });
    const entry = seenHosts.get(r.host);
    entry.count += 1;
    entry.resourceTypes.add(r.resourceType);
  }

  const thirdPartyHosts = [...seenHosts.values()];
  const knownTrackers = [];
  const unknownThirdParty = [];
  for (const h of thirdPartyHosts) {
    const cls = classifyDomain(h.host);
    if (cls) knownTrackers.push({ ...h, ...cls, resourceTypes: [...h.resourceTypes] });
    else unknownThirdParty.push({ ...h, resourceTypes: [...h.resourceTypes] });
  }

  // Geolokalisierung für eine begrenzte Auswahl an Third-Party-Hosts (Rate-Limit-schonend)
  const hostsToLocate = [...knownTrackers, ...unknownThirdParty].slice(0, 15);
  const geoResults = [];
  const cdnUncertainHosts = [];
  for (const h of hostsToLocate) {
    if (isAnycastCdn(h.host)) {
      cdnUncertainHosts.push({ host: h.host });
      continue;
    }
    try {
      const addr = await dns.lookup(h.host);
      const geo = await geolocateIp(addr.address);
      if (geo) geoResults.push({ host: h.host, ...geo });
    } catch {
      /* Host nicht auflösbar — überspringen */
    }
  }
  const nonEuHosts = geoResults.filter((g) => g.countryCode && !EU_EWR.has(g.countryCode));

  // Consent-Banner erkennen
  const hasConsentTool = knownTrackers.some((t) => t.category === "Consent-Management")
    || CONSENT_SIGNATURES.some((sig) => pageHtml.includes(sig));
  const hasConsentText = CONSENT_TEXT_PATTERNS.some((re) => re.test(pageHtml));
  const consentBannerDetected = hasConsentTool || hasConsentText;

  // Impressum / Datenschutz-Links erkennen
  const hasImpressum = LEGAL_LINK_PATTERNS.impressum.test(pageHtml);
  const hasDatenschutz = LEGAL_LINK_PATTERNS.datenschutz.test(pageHtml);

  // Trackende Requests, die bereits vor Seitenaufbau-Ende (networkidle) gefeuert haben,
  // gelten hier als "vor jeder möglichen Nutzerinteraktion" geladen.
  const trackersPreConsent = knownTrackers.filter((t) =>
    ["Analytics", "Advertising", "Advertising/Social", "Session Recording"].includes(t.category)
  );

  const evaluation = evaluate({
    trackersPreConsent,
    consentBannerDetected,
    nonEuHosts,
    cdnUncertainHosts,
    hasImpressum,
    hasDatenschutz,
  });

  return {
    targetUrl: targetUrl.toString(),
    scannedAt: new Date().toISOString(),
    navError,
    findings: {
      cookies: cookies.map((c) => ({ name: c.name, domain: c.domain, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite })),
      knownTrackers,
      unknownThirdParty,
      nonEuHosts,
      cdnUncertainHosts,
      consentBannerDetected,
      hasImpressum,
      hasDatenschutz,
      totalThirdPartyHosts: thirdPartyHosts.length,
    },
    evaluation,
  };
}

function evaluate({ trackersPreConsent, consentBannerDetected, nonEuHosts, cdnUncertainHosts, hasImpressum, hasDatenschutz }) {
  const sections = [];

  if (trackersPreConsent.length > 0 && !consentBannerDetected) {
    sections.push({
      id: "tracking_vor_consent",
      title: "Tracking vor Consent",
      level: "red",
      reason: `${trackersPreConsent.length} bekannte Tracking-/Analyse-Dienst(e) laden, ohne dass ein Consent-Banner erkannt wurde.`,
      legalQuestion: "Werden Tracking-Skripte technisch erst nach aktiver Einwilligung geladen (Opt-in), oder bereits beim Seitenaufruf?",
    });
  } else if (trackersPreConsent.length > 0 && consentBannerDetected) {
    sections.push({
      id: "tracking_vor_consent",
      title: "Tracking vor Consent",
      level: "yellow",
      reason: `Ein Consent-Banner wurde erkannt, es sind aber ${trackersPreConsent.length} Tracking-Dienst(e) im Seitenaufruf sichtbar. Ob diese technisch erst nach Einwilligung feuern (echtes Opt-in) oder nur die Anzeige gesteuert wird, kann der Scan allein nicht zuverlässig unterscheiden.`,
      legalQuestion: "Ist das Consent-Tool so konfiguriert, dass Skripte technisch blockiert werden, bis eine Einwilligung vorliegt?",
    });
  } else {
    sections.push({
      id: "tracking_vor_consent",
      title: "Tracking vor Consent",
      level: "green",
      reason: "Keine bekannten Tracking-Dienste vor Consent-Interaktion erkannt.",
      legalQuestion: null,
    });
  }

  sections.push({
    id: "consent_banner",
    title: "Consent-Banner vorhanden",
    level: consentBannerDetected ? "green" : "red",
    reason: consentBannerDetected
      ? "Es wurde ein Cookie-/Consent-Banner bzw. -Tool erkannt."
      : "Es konnte kein Cookie-/Consent-Banner erkannt werden.",
    legalQuestion: consentBannerDetected ? null : "Ist ein rechtlich ausreichendes Consent-Management-System vorgesehen oder bereits im Einsatz, aber technisch nicht erkennbar?",
  });

  if (nonEuHosts.length > 0) {
    sections.push({
      id: "drittlandtransfer",
      title: "Server außerhalb der EU/des EWR",
      level: "yellow",
      reason: `${nonEuHosts.length} eingebundene(r) Drittanbieter-Server liegen laut IP-Geolokalisierung außerhalb der EU/des EWR.`,
      legalQuestion: "Liegen für die betroffenen Anbieter geeignete Transferinstrumente vor (z.B. Standardvertragsklauseln, Angemessenheitsbeschluss)?",
    });
  } else {
    sections.push({
      id: "drittlandtransfer",
      title: "Server außerhalb der EU/des EWR",
      level: "green",
      reason: "Keine eingebundenen Drittanbieter-Server außerhalb der EU/des EWR erkannt (im Rahmen der geprüften Hosts).",
      legalQuestion: null,
    });
  }

  if (cdnUncertainHosts.length > 0) {
    sections.push({
      id: "cdn_hinweis",
      title: "CDN-/Anycast-Anbieter eingebunden",
      level: "yellow",
      reason: `${cdnUncertainHosts.length} eingebundene Ressource(n) (z.B. ${cdnUncertainHosts.map((h) => h.host).join(", ")}) laufen über global verteilte CDN-Netzwerke. Der Serverstandort lässt sich per IP-Geolokalisierung hier nicht zuverlässig bestimmen — es kann daher keine automatische Aussage zu EU/Drittland getroffen werden.`,
      legalQuestion: "Liegen für die eingebundenen CDN-Anbieter Auftragsverarbeitungsverträge bzw. geeignete Transferinstrumente vor (unabhängig vom technisch ermittelten Serverstandort)?",
    });
  }

  const missingLegal = [];
  if (!hasImpressum) missingLegal.push("Impressum");
  if (!hasDatenschutz) missingLegal.push("Datenschutzerklärung");
  sections.push({
    id: "pflichtangaben",
    title: "Impressum & Datenschutzerklärung auffindbar",
    level: missingLegal.length === 0 ? "green" : "red",
    reason: missingLegal.length === 0
      ? "Links zu Impressum und Datenschutzerklärung wurden gefunden."
      : `Kein auffindbarer Link zu: ${missingLegal.join(", ")}.`,
    legalQuestion: missingLegal.length === 0 ? null : "Sind die fehlenden Pflichtangaben tatsächlich nicht vorhanden, oder nur technisch (z.B. per JavaScript nachgeladen) nicht erkennbar?",
  });

  return sections;
}

# DXTR Live-Crawler — Deployment auf Coolify

## Was das ist
Node.js/Express-Backend mit Playwright (echter Headless-Browser), das eine
Ziel-URL aufruft, Netzwerk-Requests, Cookies, Tracker und Consent-Signale
erfasst. Enthält SSRF-Schutz (blockiert interne/private Adressen) und ein
einfaches In-Memory-Rate-Limit (5 Scans / 10 Min pro IP).

**Wichtig — Build-Dauer:** Das Docker-Image basiert auf dem offiziellen
Playwright-Image (enthält Chromium + Abhängigkeiten) und ist entsprechend
groß (~1,5–2 GB). Der erste Build dauert je nach Server-Leistung mehrere
Minuten — das ist normal, kein Fehler.

## Schritt 1: In GitHub hochladen
Gleiches Vorgehen wie beim Fragebogen:
1. Neues Repo anlegen, z.B. `dxtr-crawler` (öffentlich, wie beim ersten Mal —
   spart den Deploy-Key-Umweg; im Code stehen keine Geheimnisse)
2. Diesen kompletten Ordner-Inhalt hochladen (alle Dateien, inkl. `lib/` und
   `public/` als Unterordner)

## Schritt 2: In Coolify anlegen
1. **My first project** → **+ Add Resource** → **Public Repository**
2. Repository-URL: `https://github.com/MarkoJVogt/dxtr-crawler`
3. Branch: `main`
4. Build Pack: **Dockerfile**
5. Base Directory: `/` (diesmal NICHT in einen Unterordner hochladen —
   `Dockerfile`, `package.json`, `server.js` etc. sollen direkt im Root des
   Repos liegen)
6. Port-Feld verschwindet automatisch bei Dockerfile-Buildpack (kommt aus
   `EXPOSE 80` im Dockerfile) — nichts weiter einstellen
7. **Continue**, dann **Deploy**

## Schritt 3: Domain setzen
1. Bei der neuen Application → Configuration → General
2. Domains-Feld: `https://scan.dxtr.de` (mit `https://` davor!)
3. **Save**, dann **Redeploy**

DNS für `scan.dxtr.de` steht schon (A-Record auf 178.105.170.226 wurde
bereits bei `check.dxtr.de` mit angelegt — falls noch nicht, gleiches
Vorgehen wie bei `check.dxtr.de` bei Strato nachholen).

## Bekannte Grenzen dieser Version (Prototyp)
- Tracker-Datenbank ist eine Muster-Liste, nicht vollständig
- Geolokalisierung von Server-Standorten läuft über einen kostenlosen
  externen Dienst (ip-api.com) — sendet dabei die öffentlichen IP-Adressen
  der gefundenen Drittanbieter-Server (keine personenbezogenen Daten) an
  diesen Dienst. Für den internen Test okay; für Produktivbetrieb ggf.
  durch einen selbst gehosteten GeoIP-Datensatz ersetzen.
- Erkennt keine Consent-Banner, die erst nach komplexer Nutzerinteraktion
  (z.B. Scroll-Trigger) erscheinen
- Kein Login-geschützter Bereich wird gescannt (nur öffentlich erreichbare
  Startseite/URL)

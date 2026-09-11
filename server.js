// Embedded ASS/SSA Subtitle Extractor — Stremio/Nuvio-compatible addon
// v19 — universal embedded-text extraction: MKV Range/stream parser + MP4 moov/sample-table Range extractor; requires streamManifestUrl to end with /manifest.json (fixes AIOStreams 404) (debug-aio), no video access + comprehensive security + correctness pass (see README for the full
// list). This is a single consolidated version, not an incremental patch.

const express = require('express');
const fetch = require('node-fetch');
const { extractMp4Tracks } = require('./mp4-subtitles.js');
const { extractMkvTracks } = require('./mkv-range.js');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const dns = require('dns').promises;
const net = require('net');
const { MANIFEST_HOST_ALLOWLIST, CACHE_KEY_RE, redact, isPrivateOrReservedIp, isManifestHostAllowed, cleanAssText, looksLikeJsonResponse, looksLikeMatroska, classifyContainer, rankStreamCandidates, hasManifestSuffix, buildStreamUrl } = require('./lib.js');

const app = express();
app.set('trust proxy', 1); // Render sits behind one reverse-proxy hop — this
// makes req.ip reflect the real client IP from X-Forwarded-For instead of
// the proxy's own address, so rate limiting isn't shared across all users.

app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', '*');
  next();
});

// ---------------------------------------------------------------------------
// Config / constants
// ---------------------------------------------------------------------------

const CACHE_DIR = path.join(__dirname, 'cache');
if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR);

// No artificial candidate-count cap: every stream returned by the upstream manifest is eligible.
// This is intentionally uncapped so a good subtitle-bearing source at position 21+
// is never missed just because earlier sources were video-only/unsupported.
const MAX_CANDIDATES = Infinity;
const EXTRACT_TIMEOUT_MS = 8 * 60 * 1000;
const RESPONSE_WAIT_MS = 45000;
const MAX_REDIRECTS = 5;
const MAX_CONCURRENT_EXTRACTIONS = 2;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 20; // per IP per window, across debug + subtitles endpoints
const CACHE_TTL_MS = 48 * 60 * 60 * 1000; // 48h — successful results
const NEGATIVE_CACHE_TTL_MS = 30 * 60 * 1000; // 30 min — confirmed no embedded text subtitle results
const MAX_CUES = 50000; // safety ceiling, not a realistic episode's cue count
const MAX_DOWNLOAD_BYTES = 3 * 1024 * 1024 * 1024; // 3GB safety ceiling while scanning for cues

// Only Torrentio is a trusted source of the stream *manifest* itself (see
// lib.js MANIFEST_HOST_ALLOWLIST). Video URLs discovered THROUGH Torrentio
// (Real-Debrid/CDN links) are NOT restricted to this list — they still go
// through full SSRF/redirect validation, just not a domain allowlist, since
// debrid/CDN hosts vary.

const UPSTREAM_HEADERS = {
  Accept: 'application/json, text/plain, */*',
  'User-Agent': 'Mozilla/5.0 (SmartTV; Nuvio-compatible subtitle addon)'
};

const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || null;
if (!PUBLIC_BASE_URL) {
  console.error(
    'FATAL: PUBLIC_BASE_URL environment variable is required (e.g. https://your-app.onrender.com). ' +
      'Refusing to start without it — the req.get("host") header is not trustworthy for building subtitle URLs.'
  );
  process.exit(1);
}

const inProgress = new Map();
let activeExtractions = 0;
const rateLimitBuckets = new Map(); // ip -> [timestamps]

// ---------------------------------------------------------------------------
// Logging (with secret redaction — redact() comes from lib.js)
// ---------------------------------------------------------------------------

function log(id, ...args) {
  const safeArgs = args.map(a => (typeof a === 'string' ? redact(a) : a));
  console.log(`[${new Date().toISOString()}] [${id}]`, ...safeArgs);
}

function decodeConfig(configStr) {
  try {
    return JSON.parse(Buffer.from(configStr, 'base64').toString('utf8'));
  } catch (e) {
    return null;
  }
}

// ---------------------------------------------------------------------------
// SSRF protection: single safe-fetch layer for ALL outbound requests
// (isPrivateOrReservedIp comes from lib.js)
// ---------------------------------------------------------------------------

// Resolves a hostname and returns the list of validated (public) addresses,
// or throws if the host is unsafe/unresolvable. Exported for reuse so we can
// "pin" the exact address we validated when making the actual request,
// closing the DNS-rebinding gap between check-time and connect-time.
async function resolvePublicHost(hostname) {
  if (net.isIP(hostname)) {
    if (isPrivateOrReservedIp(hostname)) throw new Error(`Refused: ${hostname} is a private/reserved address`);
    return [hostname];
  }
  const records = await dns.lookup(hostname, { all: true });
  if (!records.length) throw new Error(`Refused: ${hostname} did not resolve`);
  const addresses = records.map(r => r.address);
  if (addresses.some(isPrivateOrReservedIp)) {
    throw new Error(`Refused: ${hostname} resolves to a private/reserved address`);
  }
  return addresses;
}

// The ONE path all outbound HTTP requests in this app go through. Handles:
//  - https-only enforcement
//  - localhost/private/reserved IP blocking (with DNS re-check)
//  - manual redirect following, re-validating + re-pinning DNS at each hop
//  - a hard cap on redirect count
async function safeFetch(urlStr, options = {}, cacheKeyForLog = 'safe-fetch', hopsLeft = MAX_REDIRECTS) {
  let u;
  try {
    u = new URL(urlStr);
  } catch (e) {
    throw new Error('Refused: malformed URL');
  }
  if (u.protocol !== 'https:') {
    throw new Error('Refused: only https is permitted');
  }
  if (u.hostname.toLowerCase() === 'localhost') {
    throw new Error('Refused: localhost is not permitted');
  }

  let pinnedAddresses;
  try {
    pinnedAddresses = await resolvePublicHost(u.hostname);
  } catch (err) {
    log(cacheKeyForLog, `Blocked request: ${err.message} (${redact(urlStr)})`);
    throw err;
  }

  // Pin the DNS resolution to the address(es) we just validated, so a
  // rebinding attack between our check and the actual connection can't
  // redirect traffic to a different (possibly private) address.
  const pinnedLookup = (hostname, opts, callback) => {
    const family = net.isIPv6(pinnedAddresses[0]) ? 6 : 4;
    callback(null, pinnedAddresses[0], family);
  };

  const finalOptions = { ...options, redirect: 'manual', lookup: pinnedLookup };
  const response = await fetch(urlStr, finalOptions);

  if ([301, 302, 303, 307, 308].includes(response.status)) {
    if (hopsLeft <= 0) {
      throw new Error('Refused: too many redirects');
    }
    const location = response.headers.get('location');
    if (!location) {
      throw new Error('Refused: redirect with no Location header');
    }
    const nextUrl = new URL(location, urlStr).toString();
    log(cacheKeyForLog, `Following validated redirect (${hopsLeft} hops left): ${redact(nextUrl)}`);
    return safeFetch(nextUrl, options, cacheKeyForLog, hopsLeft - 1);
  }

  return response;
}

// (isManifestHostAllowed comes from lib.js)

// ---------------------------------------------------------------------------
// Rate limiting / concurrency guard
// ---------------------------------------------------------------------------

function checkRateLimit(req, res) {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const now = Date.now();
  const bucket = (rateLimitBuckets.get(ip) || []).filter(t => now - t < RATE_LIMIT_WINDOW_MS);
  bucket.push(now);
  rateLimitBuckets.set(ip, bucket);
  if (bucket.length > RATE_LIMIT_MAX_REQUESTS) {
    res.status(429).json({ error: 'Too many requests, slow down.' });
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Cache paths + atomic writes
// ---------------------------------------------------------------------------

function srtPath(cacheKey) {
  return path.join(CACHE_DIR, `${cacheKey}.srt`);
}
function metaPath(cacheKey) {
  return path.join(CACHE_DIR, `${cacheKey}.meta.json`);
}
function urlFingerprint(url) {
  return crypto.createHash('sha1').update(url).digest('hex').slice(0, 16);
}
function configFingerprint(streamManifestUrl) {
  return crypto.createHash('sha1').update(streamManifestUrl).digest('hex').slice(0, 10);
}

// Cache keys are always a 32-char hex md5 hash (CACHE_KEY_RE, from lib.js)
// — this doubles as our path-traversal defense for /subs/:file below.

function atomicWrite(filePath, content) {
  const tmp = `${filePath}.tmp-${crypto.randomBytes(6).toString('hex')}`;
  fs.writeFileSync(tmp, content, 'utf8');
  fs.renameSync(tmp, filePath);
}

function writeCacheAtomic(cacheKey, srtContent, meta) {
  atomicWrite(srtPath(cacheKey), srtContent);
  atomicWrite(metaPath(cacheKey), JSON.stringify(meta));
}

function readMetaSafely(cacheKey) {
  try {
    if (!fs.existsSync(metaPath(cacheKey))) return null;
    return JSON.parse(fs.readFileSync(metaPath(cacheKey), 'utf8'));
  } catch (e) {
    log(cacheKey, `meta.json unreadable/corrupted (${e.message}) — discarding cache.`);
    try {
      if (fs.existsSync(srtPath(cacheKey))) fs.unlinkSync(srtPath(cacheKey));
      if (fs.existsSync(metaPath(cacheKey))) fs.unlinkSync(metaPath(cacheKey));
    } catch (_) {}
    return null;
  }
}

// Periodic cache cleanup: removes anything past its TTL (positive results:
// 48h; negative "not found" results: 30min, handled via meta.notFound).
function cleanupCacheOnce() {
  let removed = 0;
  for (const file of fs.readdirSync(CACHE_DIR)) {
    if (!file.endsWith('.meta.json')) continue;
    const cacheKey = file.replace('.meta.json', '');
    const meta = readMetaSafely(cacheKey);
    if (!meta) continue;
    const age = Date.now() - (meta.extractedAt || 0);
    const ttl = meta.notFound ? NEGATIVE_CACHE_TTL_MS : CACHE_TTL_MS;
    if (age > ttl) {
      try {
        fs.unlinkSync(srtPath(cacheKey));
        fs.unlinkSync(metaPath(cacheKey));
        removed++;
      } catch (_) {}
    }
  }
  if (removed) log('cache-cleanup', `Removed ${removed} expired cache entr${removed === 1 ? 'y' : 'ies'}.`);
}
setInterval(cleanupCacheOnce, 60 * 60 * 1000); // hourly
cleanupCacheOnce();

// (cleanAssText comes from lib.js)

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

app.get('/:config/manifest.json', (req, res) => {
  res.json({
    id: 'com.khalid.embeddedass',
    version: '17.0.0',
    name: 'Embedded ASS Extractor',
    description: 'Extracts embedded text subtitle tracks from remote MKV/MP4 streams and serves a web-compatible SRT.',
    resources: ['subtitles'],
    types: ['movie', 'series'],
    idPrefixes: ['tt'],
    catalogs: [],
    behaviorHints: { configurable: true, configurationRequired: false }
  });
});

// ---------------------------------------------------------------------------
// Debug Test 1: Render -> Torrentio -> JSON
// ---------------------------------------------------------------------------

app.get('/:config/debug/:type/:id', async (req, res) => {
  if (!checkRateLimit(req, res)) return;

  const config = decodeConfig(req.params.config);
  if (!config || !config.streamManifestUrl) {
    return res.status(400).json({ error: 'Invalid or missing config' });
  }
  if (!isManifestHostAllowed(config.streamManifestUrl)) {
    return res.status(403).json({ error: 'streamManifestUrl host is not on the allowlist' });
  }
  if (!hasManifestSuffix(config.streamManifestUrl)) {
    return res.status(400).json({
      error: 'streamManifestUrl must end with "/manifest.json" exactly (e.g. .../profile/secret/manifest.json) — this is required to correctly build the stream endpoint URL.'
    });
  }

  const { type, id } = req.params;
  const url = buildStreamUrl(config.streamManifestUrl, type, id);

  try {
    const upstreamRes = await safeFetch(url, { headers: UPSTREAM_HEADERS }, 'debug');
    const contentType = upstreamRes.headers.get('content-type') || '';
    const bodyText = await upstreamRes.text();
    const looksLikeJson = looksLikeJsonResponse(contentType, bodyText);

    let streamCount = null;
    if (looksLikeJson) {
      try {
        streamCount = (JSON.parse(bodyText).streams || []).length;
      } catch (_) {}
    }

    res.json({
      requestedUrl: redact(url),
      httpStatus: upstreamRes.status,
      contentType,
      looksLikeJson,
      streamCount,
      bodySnippet: looksLikeJson ? undefined : redact(bodyText.slice(0, 300))
    });
  } catch (err) {
    res.status(500).json({ requestedUrl: redact(url), error: redact(err.message) });
  }
});

// ---------------------------------------------------------------------------
// Debug: list what an upstream (e.g. AIOStreams) actually returns, WITHOUT
// touching any video URL at all — no download, no MKV probing, no
// extraction. Just: did we get a valid stream list, and does each entry
// look usable (has a URL, has subtitle metadata or not)? This answers
// "does Render -> AIOStreams -> stream list work" in isolation, before
// trusting anything downstream of it.
// ---------------------------------------------------------------------------
app.get('/:config/debug-aio/:type/:id', async (req, res) => {
  if (!checkRateLimit(req, res)) return;

  const config = decodeConfig(req.params.config);
  if (!config || !config.streamManifestUrl) {
    return res.status(400).json({ error: 'Invalid or missing config' });
  }
  if (!isManifestHostAllowed(config.streamManifestUrl)) {
    return res.status(403).json({ error: 'streamManifestUrl host is not on the allowlist' });
  }
  if (!hasManifestSuffix(config.streamManifestUrl)) {
    return res.status(400).json({
      error: 'streamManifestUrl must end with "/manifest.json" exactly (e.g. .../profile/secret/manifest.json) — this is required to correctly build the stream endpoint URL.'
    });
  }

  const { type, id } = req.params;
  const url = buildStreamUrl(config.streamManifestUrl, type, id);

  try {
    const upstreamRes = await safeFetch(url, { headers: UPSTREAM_HEADERS }, 'debug-aio');
    const contentType = upstreamRes.headers.get('content-type') || '';
    const bodyText = await upstreamRes.text();
    const looksLikeJson = looksLikeJsonResponse(contentType, bodyText);

    if (!looksLikeJson) {
      return res.json({
        requestedUrl: redact(url),
        httpStatus: upstreamRes.status,
        contentType,
        looksLikeJson: false,
        bodySnippet: redact(bodyText.slice(0, 300))
      });
    }

    let data;
    try {
      data = JSON.parse(bodyText);
    } catch (e) {
      return res.json({
        requestedUrl: redact(url),
        httpStatus: upstreamRes.status,
        contentType,
        looksLikeJson: true,
        jsonParseError: true,
        bodySnippet: redact(bodyText.slice(0, 300))
      });
    }

    const rawStreams = data.streams || [];
    // Sanitized summary only — never echo the actual url (it may embed
    // debrid credentials in the path), and never fetch it.
    const streamsSummary = rawStreams.map((s, i) => ({
      index: i,
      name: s.name || null,
      title: s.title || null,
      hasUrl: Boolean(s.url),
      urlHostRedactedPath: s.url ? safeUrlHostOnly(s.url) : null,
      hasSubtitlesMetadata: Array.isArray(s.subtitles),
      subtitleLanguages: Array.isArray(s.subtitles) ? s.subtitles.map(String) : null,
      confirmedArabic: Array.isArray(s.subtitles) && s.subtitles.some(c => /^ar(a)?$/i.test(String(c).trim()))
    }));

    res.json({
      requestedUrl: redact(url),
      httpStatus: upstreamRes.status,
      contentType,
      looksLikeJson: true,
      streamCount: rawStreams.length,
      streams: streamsSummary
    });
  } catch (err) {
    res.status(500).json({ requestedUrl: redact(url), error: redact(err.message) });
  }
});

// Returns only the hostname of a URL (e.g. "real-debrid.com") — used so the
// debug-aio endpoint can show WHERE a stream URL points without ever
// exposing the full URL (which may contain an API key/token in its path).
function safeUrlHostOnly(urlStr) {
  try {
    return new URL(urlStr).hostname;
  } catch (e) {
    return '(unparseable)';
  }
}

// ---------------------------------------------------------------------------
// Debug Test 2: Render -> stream URL -> first bytes, verified as Matroska
// ---------------------------------------------------------------------------

app.get('/:config/debug-stream/:type/:id', async (req, res) => {
  if (!checkRateLimit(req, res)) return;

  const config = decodeConfig(req.params.config);
  if (!config || !config.streamManifestUrl) {
    return res.status(400).json({ error: 'Invalid or missing config' });
  }
  if (!isManifestHostAllowed(config.streamManifestUrl)) {
    return res.status(403).json({ error: 'streamManifestUrl host is not on the allowlist' });
  }
  if (!hasManifestSuffix(config.streamManifestUrl)) {
    return res.status(400).json({
      error: 'streamManifestUrl must end with "/manifest.json" exactly (e.g. .../profile/secret/manifest.json) — this is required to correctly build the stream endpoint URL.'
    });
  }

  const { type, id } = req.params;

  let streams;
  try {
    streams = await getCandidates(config.streamManifestUrl, type, id, 'debug-stream');
  } catch (err) {
    return res.status(500).json({ stage: 'fetching stream list', error: redact(err.message) });
  }

  const top = streams.find(s => s.url);
  if (!top) return res.status(404).json({ error: 'No stream with a URL found in upstream response' });

  try {
    const { headers, firstBytes } = await peekStream(top.url, 'debug-stream');
    const hex = firstBytes.toString('hex');
    res.json({
      streamLabel: top.name || top.title || '(unnamed)',
      httpStatus: headers.status,
      contentType: headers.contentType,
      contentLength: headers.contentLength,
      acceptRanges: headers.acceptRanges,
      rangeHonored: headers.status === 206,
      firstBytesHex: hex,
      looksLikeMatroska: looksLikeMatroska(firstBytes)
    });
  } catch (err) {
    res.status(500).json({ stage: 'reading stream bytes', streamLabel: top.name || top.title, error: redact(err.message) });
  }
});

// Fetches only the first ~64 bytes of a URL via safeFetch (Range request),
// used by both debug-stream and the real extraction pipeline to verify the
// source looks like Matroska before committing to a full parse. Always
// destroys the underlying connection once it has what it needs — even if
// the server ignored our Range header and started sending a much larger
// response — so we never leave sockets open needlessly (important on
// Render's free tier, and doubly so when trying several candidates).
async function peekStream(videoUrl, cacheKey) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  let res;
  try {
    res = await safeFetch(videoUrl, { headers: { ...UPSTREAM_HEADERS, Range: 'bytes=0-63' }, signal: controller.signal }, cacheKey);
    const chunks = [];
    let received = 0;
    for await (const chunk of res.body) {
      chunks.push(chunk);
      received += chunk.length;
      if (received >= 64) break;
    }
    return {
      headers: {
        status: res.status,
        contentType: res.headers.get('content-type'),
        contentLength: res.headers.get('content-length'),
        acceptRanges: res.headers.get('accept-ranges')
      },
      firstBytes: Buffer.concat(chunks).slice(0, 64)
    };
  } finally {
    clearTimeout(timer);
    // Always close the connection explicitly — the `for await` loop above
    // only stops pulling chunks, it doesn't tell the underlying socket to
    // close on its own, especially if the server didn't honor our Range
    // request and is still trying to send the rest of a multi-GB file.
    if (res && res.body && typeof res.body.destroy === 'function') {
      res.body.destroy();
    }
  }
}

// ---------------------------------------------------------------------------
// Subtitles resource
// ---------------------------------------------------------------------------

app.get('/:config/subtitles/:type/:id/:extra?.json', async (req, res) => {
  if (!checkRateLimit(req, res)) return;

  const config = decodeConfig(req.params.config);
  if (!config || !config.streamManifestUrl) {
    return res.json({ subtitles: [] });
  }
  if (!isManifestHostAllowed(config.streamManifestUrl)) {
    log('subtitles', `Rejected config: host not on allowlist (${redact(config.streamManifestUrl)})`);
    return res.json({ subtitles: [] });
  }
  if (!hasManifestSuffix(config.streamManifestUrl)) {
    log('subtitles', `Rejected config: streamManifestUrl does not end with /manifest.json (${redact(config.streamManifestUrl)})`);
    return res.json({ subtitles: [] });
  }

  const streamManifestUrl = config.streamManifestUrl;
  const { type, id } = req.params;
  const lang = config.lang || 'ara';
  const cfgFp = configFingerprint(streamManifestUrl);
  const cacheKey = crypto.createHash('md5').update(`${cfgFp}:${type}:${id}:${lang}`).digest('hex');

  let streams = null;
  let upstreamReachable = true;
  try {
    streams = await getCandidates(streamManifestUrl, type, id, cacheKey);
  } catch (err) {
    upstreamReachable = false;
    log(cacheKey, `Could not fetch upstream candidates: ${err.message}`);
  }

  const currentFingerprints = new Set((streams || []).filter(s => s.url).map(s => urlFingerprint(s.url)));

  if (upstreamReachable && fs.existsSync(srtPath(cacheKey))) {
    const meta = readMetaSafely(cacheKey);
    const ttl = meta && meta.notFound ? NEGATIVE_CACHE_TTL_MS : CACHE_TTL_MS;
    const notExpired = meta && Date.now() - meta.extractedAt < ttl;
    const sourceStillValid =
      meta && (meta.notFound || !currentFingerprints.size || (meta.sourceFingerprint && currentFingerprints.has(meta.sourceFingerprint)));

    if (meta && notExpired && sourceStillValid) {
      log(cacheKey, `Serving cached result (${meta.notFound ? 'negative' : 'positive'}, unexpired).`);
      if (meta.notFound) return res.json({ subtitles: [] });
      return res.json(subtitleResponse(req, cacheKey, lang));
    }
    if (meta) log(cacheKey, 'Cached result expired or source changed — re-extracting.');
  }

  if (upstreamReachable && streams && streams.length && !inProgress.has(cacheKey)) {
    if (activeExtractions >= MAX_CONCURRENT_EXTRACTIONS) {
      log(cacheKey, `At concurrency limit (${MAX_CONCURRENT_EXTRACTIONS}) — skipping this attempt, will retry next request.`);
    } else {
      activeExtractions++;
      const task = processRequest(streams, cacheKey)
        .catch(err => log(cacheKey, 'FAILED:', err.message))
        .finally(() => {
          activeExtractions--;
          inProgress.delete(cacheKey);
        });
      inProgress.set(cacheKey, task);
    }
  }

  const ready = await waitForFile(srtPath(cacheKey), RESPONSE_WAIT_MS);
  if (ready) {
    const meta = readMetaSafely(cacheKey);
    if (meta && meta.notFound) return res.json({ subtitles: [] });
    return res.json(subtitleResponse(req, cacheKey, lang));
  }

  log(cacheKey, `Still working after ${RESPONSE_WAIT_MS}ms — responding empty this call.`);
  return res.json({ subtitles: [] });
});

function subtitleResponse(req, cacheKey, lang) {
  const base = PUBLIC_BASE_URL; // required at startup — no Host-header fallback
  return {
    subtitles: [{ id: cacheKey, url: `${base}/subs/${cacheKey}.srt`, lang }]
  };
}

// Path-traversal-safe: only a literal 32-char hex cache key + ".srt" is
// ever accepted. Anything else is rejected before touching the filesystem.
app.get('/subs/:file', (req, res) => {
  const match = /^([a-f0-9]{32})\.srt$/.exec(req.params.file);
  if (!match) return res.status(400).end();
  const cacheKey = match[1];
  if (!CACHE_KEY_RE.test(cacheKey)) return res.status(400).end();

  const filePath = srtPath(cacheKey);
  if (!fs.existsSync(filePath)) return res.status(404).end();
  res.set('Content-Type', 'text/plain; charset=utf-8');
  res.set('Access-Control-Allow-Origin', '*');
  fs.createReadStream(filePath).pipe(res);
});

app.get('/', (req, res) => res.send('Embedded Subtitle Extractor v19 is running.'));

function waitForFile(filePath, timeoutMs) {
  return new Promise(resolve => {
    const start = Date.now();
    const check = () => {
      if (fs.existsSync(filePath)) return resolve(true);
      if (Date.now() - start > timeoutMs) return resolve(false);
      setTimeout(check, 500);
    };
    check();
  });
}

// ---------------------------------------------------------------------------
// Upstream (Torrentio) stream list
// ---------------------------------------------------------------------------

async function getCandidates(streamManifestUrl, type, id, cacheKey) {
  const url = buildStreamUrl(streamManifestUrl, type, id);

  log(cacheKey, `Fetching upstream: ${redact(url)}`);
  const streamRes = await safeFetch(url, { headers: UPSTREAM_HEADERS }, cacheKey);

  const contentType = streamRes.headers.get('content-type') || '';
  log(cacheKey, `Upstream response: HTTP ${streamRes.status}, Content-Type: ${contentType || '(none)'}`);

  const bodyText = await streamRes.text();
  const looksLikeJson = looksLikeJsonResponse(contentType, bodyText);

  if (!streamRes.ok || !looksLikeJson) {
    log(cacheKey, `Upstream did NOT return usable JSON. Snippet: ${redact(bodyText.slice(0, 200)).replace(/\n/g, ' ')}`);
    throw new Error(`Upstream returned non-JSON response (HTTP ${streamRes.status}, content-type: ${contentType})`);
  }

  let data;
  try {
    data = JSON.parse(bodyText);
  } catch (e) {
    log(cacheKey, `Upstream claimed JSON but failed to parse. Snippet: ${redact(bodyText.slice(0, 200))}`);
    throw new Error('Upstream response could not be parsed as JSON');
  }

  const ordered = rankStreamCandidates(data.streams || []);
  // Do not slice/truncate: process every upstream stream.
  const streams = ordered;
  const confirmedCount = (data.streams || []).filter(
    s => Array.isArray(s.subtitles) && s.subtitles.some(c => /^ar(a)?$/i.test(String(c).trim()))
  ).length;
  log(
    cacheKey,
    `Upstream returned ${data.streams ? data.streams.length : 0} stream(s) (${confirmedCount} with confirmed Arabic subtitle metadata), trying all ${streams.length} after ranking (Arabic metadata + MKV/MP4 filename hints).`
  );
  return streams;
}

// ---------------------------------------------------------------------------
// Core extraction pipeline
// ---------------------------------------------------------------------------

function parseTimecode(s) {
  const m = String(s).trim().replace(',', '.').match(/^(\d+):(\d{2}):(\d{2})\.(\d{1,3})$/);
  if (!m) return null;
  const frac = m[4].padEnd(3, '0');
  return (((Number(m[1]) * 60 + Number(m[2])) * 60 + Number(m[3])) * 1000) + Number(frac);
}

function parseSrtBytes(bytes) {
  const text = Buffer.from(bytes).toString('utf8').replace(/^\uFEFF/, '');
  const blocks = text.split(/\r?\n\s*\r?\n/);
  const cues = [];
  for (const block of blocks) {
    const lines = block.split(/\r?\n/);
    const ti = lines.findIndex(x => /\d{2}:\d{2}:\d{2}[,.]\d{3}\s*-->\s*\d{2}:\d{2}:\d{2}[,.]\d{3}/.test(x));
    if (ti < 0) continue;
    const m = lines[ti].match(/(\d{2}:\d{2}:\d{2}[,.]\d{3})\s*-->\s*(\d{2}:\d{2}:\d{2}[,.]\d{3})/);
    if (!m) continue;
    const start = parseTimecode(m[1].replace(',', '.'));
    const end = parseTimecode(m[2].replace(',', '.'));
    if (start == null || end == null || end <= start) continue;
    const body = lines.slice(ti + 1).join('\n').trim();
    if (body) cues.push({ time: start, duration: end - start, text: body });
  }
  return cues;
}

function parseAssBytes(bytes) {
  const text = Buffer.from(bytes).toString('utf8').replace(/^\uFEFF/, '');
  const lines = text.split(/\r?\n/);
  let format = null;
  const cues = [];
  for (const line of lines) {
    if (/^\s*Format\s*:/i.test(line)) {
      format = line.replace(/^\s*Format\s*:/i, '').split(',').map(x => x.trim().toLowerCase());
      continue;
    }
    if (!/^\s*Dialogue\s*:/i.test(line)) continue;
    const payload = line.replace(/^\s*Dialogue\s*:/i, '').trim();
    const parts = [];
    let rest = payload;
    const fieldCount = format?.length || 10;
    for (let i = 0; i < fieldCount - 1; i++) {
      const idx = rest.indexOf(',');
      if (idx < 0) break;
      parts.push(rest.slice(0, idx));
      rest = rest.slice(idx + 1);
    }
    parts.push(rest);
    const idxStart = format ? format.indexOf('start') : 1;
    const idxEnd = format ? format.indexOf('end') : 2;
    const idxText = format ? format.indexOf('text') : parts.length - 1;
    if (idxStart < 0 || idxEnd < 0 || idxText < 0) continue;
    const start = parseAssTime(parts[idxStart]);
    const end = parseAssTime(parts[idxEnd]);
    const body = parts[idxText] || '';
    if (start == null || end == null || end <= start || !body) continue;
    cues.push({ time: start, duration: end - start, text: body });
  }
  return cues;
}

function parseAssTime(s) {
  const m = String(s || '').trim().match(/^(\d+):(\d{1,2}):(\d{2})[.](\d{1,2})$/);
  if (!m) return null;
  return (((Number(m[1]) * 60 + Number(m[2])) * 60 + Number(m[3])) * 1000) + Number(m[4].padEnd(2, '0')) * 10;
}

function parseVttBytes(bytes) {
  const text = Buffer.from(bytes).toString('utf8').replace(/^\uFEFF/, '');
  const blocks = text.split(/\r?\n\s*\r?\n/);
  const cues = [];
  for (const block of blocks) {
    const lines = block.split(/\r?\n/);
    const ti = lines.findIndex(x => /\d{2}:\d{2}:\d{2}\.\d{3}\s*-->\s*/.test(x));
    if (ti < 0) continue;
    const m = lines[ti].match(/(\d{2}:\d{2}:\d{2}\.\d{3})\s*-->\s*(\d{2}:\d{2}:\d{2}\.\d{3})/);
    if (!m) continue;
    const start = parseTimecode(m[1]);
    const end = parseTimecode(m[2]);
    const body = lines.slice(ti + 1).join('\n').trim();
    if (start != null && end != null && end > start && body) cues.push({ time: start, duration: end - start, text: body });
  }
  return cues;
}

function trackBytesToCues(track) {
  if (!track?.bytes?.length) return [];
  if (track.type === 'srt' || track.type === 'subrip' || track.type === 'utf8') return parseSrtBytes(track.bytes);
  if (track.type === 'ass' || track.type === 'ssa') return parseAssBytes(track.bytes);
  if (track.type === 'vtt' || track.type === 'webvtt') return parseVttBytes(track.bytes);
  return [];
}

function isRequestedLanguage(track, requested) {
  if (!requested) return false;
  const want = String(requested).toLowerCase();
  const lang = String(track.language || '').toLowerCase();
  return lang === want || (want === 'ara' && lang === 'ar') || (want === 'ar' && lang === 'ara');
}

function trackLabel(t) {
  return `[#${t.trackNumber ?? t.index ?? '?'}] type=${t.type || '?'} lang=${t.language || '?'} name="${t.name || ''}" cues=${t.cues?.length || 0}`;
}

function chooseTrack(tracks, requestedLang) {
  const usable = tracks.filter(t => t && t.cues && t.cues.length);
  if (!usable.length) return null;
  return usable.find(t => isRequestedLanguage(t, requestedLang)) ||
    usable.find(t => /arabic|عرب/i.test(t.name || '')) ||
    usable[0];
}

async function processRequest(streams, cacheKey) {
  let probedAtLeastOne = false;

  for (let i = 0; i < streams.length; i++) {
    const s = streams[i];
    const label = s.name || s.title || `stream #${i + 1}`;
    const videoUrl = s.url;
    if (!videoUrl) continue;

    log(cacheKey, `--- Checking candidate ${i + 1}/${streams.length}: ${label}`);
    try {
      const { headers, firstBytes } = await peekStream(videoUrl, cacheKey);
      const container = classifyContainer(headers.contentType, firstBytes);
      let tracks = [];

      if (container === 'mp4') {
        log(cacheKey, `"${label}" is MP4 — reading embedded text subtitle tracks with HTTP Range.`);
        tracks = await extractMp4Tracks(safeFetch, videoUrl, cacheKey);
      } else if (container === 'mkv') {
        log(cacheKey, `"${label}" is Matroska — reading embedded subtitle tracks with MKV Range extractor.`);
        tracks = await extractMkvTracks(videoUrl, safeFetch, cacheKey);
      } else {
        log(cacheKey, `"${label}" is not a supported text-subtitle container — skipping.`);
        continue;
      }

      probedAtLeastOne = true;
      log(cacheKey, `Discovered ${tracks.length} embedded subtitle track(s) in "${label}": ${tracks.map(trackLabel).join(' | ') || '(none)'}`);
      const selected = chooseTrack(tracks, 'ara');
      if (!selected) {
        log(cacheKey, `No usable text subtitle track in "${label}". Trying next source...`);
        continue;
      }

      log(cacheKey, `Selected embedded track: ${trackLabel(selected)}. Arabic is preferred when present; otherwise first usable track is used for diagnosis.`);
      const srt = buildSrt(selected.cues);
      if (!srt.trim()) {
        log(cacheKey, `Selected track produced empty SRT. Trying next source...`);
        continue;
      }
      writeCacheAtomic(cacheKey, srt, {
        sourceFingerprint: urlFingerprint(videoUrl),
        sourceLabel: label,
        track: { index: selected.index, trackNumber: selected.trackNumber, type: selected.type, language: selected.language, name: selected.name },
        extractedAt: Date.now(),
        notFound: false
      });
      log(cacheKey, `Embedded subtitle extraction succeeded (${selected.cues.length} cues) from "${label}".`);
      return;
    } catch (err) {
      log(cacheKey, `Could not read "${label}": ${err.message}`);
    }
  }

  if (probedAtLeastOne) {
    log(cacheKey, 'No usable embedded text subtitle track found in any readable candidate — caching short-lived negative result.');
    writeCacheAtomic(cacheKey, '', { sourceFingerprint: null, sourceLabel: null, extractedAt: Date.now(), notFound: true });
  } else {
    log(cacheKey, 'No readable supported subtitle containers found. Not caching — will retry next request.');
  }
}

// ---------------------------------------------------------------------------
// SRT building
// ---------------------------------------------------------------------------

function pad(n, len = 2) {
  return String(n).padStart(len, '0');
}
function msToSrtTime(ms) {
  const h = Math.floor(ms / 3600000);
  const m = Math.floor((ms % 3600000) / 60000);
  const s = Math.floor((ms % 60000) / 1000);
  return `${pad(h)}:${pad(m)}:${pad(s)},${pad(ms % 1000, 3)}`;
}
function buildSrt(cues) {
  const sorted = [...cues].sort((a, b) => a.time - b.time);
  return sorted
    .map((c, i) => {
      const text = cleanAssText(c.text);
      const start = msToSrtTime(c.time);
      const end = msToSrtTime(c.time + (c.duration || 2000));
      return `${i + 1}\n${start} --> ${end}\n${text}\n`;
    })
    .join('\n');
}

const PORT = process.env.PORT || 7005;
app.listen(PORT, () => {
  console.log('Embedded Subtitle Extractor v19 running on port', PORT);
});

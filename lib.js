// Pure logic, no network/Express dependencies — kept separate so tests can
// exercise this logic without booting the actual HTTP server, and so the
// "decide" functions are reusable/testable independently from the "do
// network I/O" functions in server.js.

const net = require('net');

// Torrentio kept as a fallback option; AIOStreams instances (self-hosted or
// third-party) are now also trusted, since a self-hosted AIOStreams
// instance is the one talking to Torrentio server-side (not Render
// directly), which sidesteps a 403 that specifically targets Render's
// outbound IP hitting torrentio.strem.fun. Add your own AIOStreams
// instance's hostname here.
const MANIFEST_HOST_ALLOWLIST = ['torrentio.strem.fun', 'aiostreamsfortheweebs.midnightignite.me'];
const CACHE_KEY_RE = /^[a-f0-9]{32}$/;

function redact(text) {
  if (!text) return text;
  return text.replace(/(realdebrid|real_debrid|apikey|api_key|token|access_token|key)=([^&|/\s"']+)/gi, '$1=[REDACTED]');
}

// Comprehensive private/reserved/special-use IPv4 + IPv6 detection.
// Covers everything from the original version PLUS (per review):
//   - 100.64.0.0/10   Carrier-Grade NAT (CGNAT)
//   - 192.0.0.0/24    IETF protocol assignments
//   - 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24   TEST-NET-1/2/3
//   - 192.88.99.0/24  6to4 relay anycast (historic)
//   - 198.18.0.0/15   benchmarking
//   - 224.0.0.0/4     multicast
//   - 240.0.0.0/4 and 255.255.255.255   reserved / broadcast
//   - IPv6 :: (unspecified), ff00::/8 (multicast), full fe80::/10 link-local
//   - IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) — unwrapped and checked
//     against the same IPv4 rules recursively.
function isPrivateOrReservedIp(ip) {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    const [a, b, c] = parts;
    if (parts.some(n => Number.isNaN(n) || n < 0 || n > 255)) return true; // malformed — treat as unsafe

    if (a === 0) return true; // "this network" / unspecified
    if (a === 10) return true; // RFC1918
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT RFC6598
    if (a === 127) return true; // loopback
    if (a === 169 && b === 254) return true; // link-local
    if (a === 172 && b >= 16 && b <= 31) return true; // RFC1918
    if (a === 192 && b === 0 && c === 0) return true; // IETF protocol assignments
    if (a === 192 && b === 0 && c === 2) return true; // TEST-NET-1
    if (a === 192 && b === 88 && c === 99) return true; // 6to4 relay anycast
    if (a === 192 && b === 168) return true; // RFC1918
    if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
    if (a === 198 && b === 51 && c === 100) return true; // TEST-NET-2
    if (a === 203 && b === 0 && c === 113) return true; // TEST-NET-3
    if (a >= 224 && a <= 239) return true; // multicast
    if (a >= 240) return true; // reserved (240-255, includes broadcast 255.255.255.255)
    return false;
  }

  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();

    // IPv4-mapped IPv6 (::ffff:a.b.c.d) — unwrap and re-check as IPv4.
    const mapped = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(lower);
    if (mapped) return isPrivateOrReservedIp(mapped[1]);

    if (lower === '::' || lower === '0:0:0:0:0:0:0:0') return true; // unspecified
    if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return true; // loopback
    if (lower.startsWith('ff')) return true; // ff00::/8 multicast
    // fe80::/10 link-local spans fe80 through febf
    if (/^fe[89ab][0-9a-f]:/.test(lower)) return true;
    // fc00::/7 unique local spans fc00 through fdff
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
    return false;
  }

  return true; // unknown format — treat as unsafe
}

function isManifestHostAllowed(urlStr) {
  try {
    const u = new URL(urlStr);
    return MANIFEST_HOST_ALLOWLIST.includes(u.hostname.toLowerCase());
  } catch (e) {
    return false;
  }
}

function cleanAssText(rawText) {
  if (!rawText) return '';
  return rawText
    .replace(/\{[^}]*\}/g, '') // strip override tags like {\an8}, {\pos(x,y)}, {\i1}
    .replace(/\\N/g, '\n') // ASS hard line break
    .replace(/\\n/g, '\n') // soft line break
    .replace(/\\h/g, ' ') // ASS "hard space"
    .trim();
}

// Classifies an upstream response body as JSON-like or not, given its
// Content-Type header and raw body text. Extracted as a pure function so it
// can be unit/integration-tested against real HTTP responses without going
// through the SSRF-guarded network layer.
function looksLikeJsonResponse(contentType, bodyText) {
  return Boolean((contentType || '').includes('application/json') || (bodyText || '').trim().startsWith('{'));
}

// Checks whether a buffer of bytes starts with the Matroska/WebM EBML
// signature (1A 45 DF A3).
function looksLikeMatroska(buffer) {
  return Buffer.isBuffer(buffer) && buffer.length >= 4 && buffer.slice(0, 4).toString('hex') === '1a45dfa3';
}

// Detects an MP4/ISO-BMFF container from its bytes: a valid MP4 starts with
// a 4-byte box size, then the ASCII bytes "ftyp" at offset 4. Checking this
// directly (not just trusting the Content-Type header) lets us fast-skip an
// MP4 candidate even if a server mislabels its content type.
function looksLikeMp4(buffer) {
  return Buffer.isBuffer(buffer) && buffer.length >= 8 && buffer.slice(4, 8).toString('ascii') === 'ftyp';
}

// Combines Content-Type and the actual first bytes into one classification.
// We only ever want to proceed to full extraction for 'mkv' — everything
// else (mp4, unknown/other) is skipped immediately without wasting time on
// a full matroska-subtitles parse attempt that can never find an ASS/SSA
// track in a non-Matroska container.
function classifyContainer(contentType, firstBytes) {
  if (looksLikeMatroska(firstBytes)) return 'mkv';
  if ((contentType && /mp4/i.test(contentType)) || looksLikeMp4(firstBytes)) return 'mp4';
  return 'unknown';
}

// Best-effort guess of a stream's container from whatever text metadata is
// available (filename, name, title) — used ONLY to influence try-order
// before we've made any network request. This is a hint, never a final
// decision: classifyContainer() (from real bytes) is always the actual
// gate before extraction is attempted.
function guessContainerHint(stream) {
  const haystack = [stream.filename, stream.name, stream.title, stream.behaviorHints && stream.behaviorHints.filename]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
  if (/\.mkv\b/.test(haystack)) return 'mkv';
  if (/\.mp4\b/.test(haystack)) return 'mp4';
  return 'unknown';
}

// Final candidate ordering used before any network calls: combines two
// independent signals —
//   (a) confirmed Arabic subtitle metadata (from prioritizeKnownArabicSubtitles)
//   (b) a filename/title hint that the container is MKV vs MP4
// into one score, highest first. Nothing is ever dropped — a stream with no
// useful hints at all just stays in its original relative position among
// other "unknown" entries (stable sort).
function rankStreamCandidates(streams) {
  const isArabicConfirmed = s =>
    Array.isArray(s.subtitles) && s.subtitles.some(code => /^ar(a)?$/i.test(String(code).trim()));

  const scored = streams.map((s, originalIndex) => {
    const containerHint = guessContainerHint(s);
    let score = 0;
    if (isArabicConfirmed(s)) score += 2;
    if (containerHint === 'mkv') score += 1;
    if (containerHint === 'mp4') score -= 1;
    return { s, score, originalIndex };
  });

  // Stable sort by score descending; ties keep original relative order.
  scored.sort((a, b) => b.score - a.score || a.originalIndex - b.originalIndex);
  return scored.map(x => x.s);
}

// AIOStreams (via StremThru-probed results) sometimes includes a real,
// FFmpeg-probed `subtitles` array on each stream object listing the
// language codes of subtitle tracks actually embedded in that file — not
// just guessed from the filename. When present, we use it to try
// already-confirmed-Arabic sources FIRST, before falling back to the
// upstream's own default order. This is purely an ordering optimization:
// streams without this metadata (e.g. plain Torrentio results) are left in
// their original relative order at the end, so nothing is ever skipped.
function prioritizeKnownArabicSubtitles(streams) {
  const hasConfirmedArabic = s =>
    Array.isArray(s.subtitles) && s.subtitles.some(code => /^ar(a)?$/i.test(String(code).trim()));

  const confirmed = streams.filter(hasConfirmedArabic);
  const rest = streams.filter(s => !hasConfirmedArabic(s));
  return [...confirmed, ...rest];
}

// The stream-manifest URL MUST end with exactly "/manifest.json" — that's
// what getCandidates() strips off to build the stream endpoint. If it's
// missing, stripping does nothing and the stream path gets concatenated
// onto the raw URL with no separating slash (e.g. ".../secretstream/..."),
// producing a broken path that upstream correctly 404s on. Validating this
// up front turns that into a clear, immediate error instead of a confusing
// 404 three steps later.
function hasManifestSuffix(urlStr) {
  return typeof urlStr === 'string' && /\/manifest\.json$/.test(urlStr);
}

// Given a valid manifest URL (see hasManifestSuffix), builds the Stremio
// stream endpoint for a given type/id, preserving every path segment before
// "manifest.json" (profile IDs, secrets, config tokens, etc.) untouched.
function buildStreamUrl(streamManifestUrl, type, id) {
  const base = streamManifestUrl.replace(/manifest\.json$/, '');
  return `${base}stream/${type}/${id}.json`;
}

module.exports = {
  MANIFEST_HOST_ALLOWLIST,
  CACHE_KEY_RE,
  redact,
  isPrivateOrReservedIp,
  isManifestHostAllowed,
  cleanAssText,
  looksLikeJsonResponse,
  looksLikeMatroska,
  looksLikeMp4,
  classifyContainer,
  guessContainerHint,
  rankStreamCandidates,
  prioritizeKnownArabicSubtitles,
  hasManifestSuffix,
  buildStreamUrl
};

// Pure logic, no network/Express dependencies — kept separate so tests can
// exercise this logic without booting the actual HTTP server, and so the
// "decide" functions are reusable/testable independently from the "do
// network I/O" functions in server.js.

const net = require('net');

const MANIFEST_HOST_ALLOWLIST = ['torrentio.strem.fun'];
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

module.exports = {
  MANIFEST_HOST_ALLOWLIST,
  CACHE_KEY_RE,
  redact,
  isPrivateOrReservedIp,
  isManifestHostAllowed,
  cleanAssText,
  looksLikeJsonResponse,
  looksLikeMatroska
};

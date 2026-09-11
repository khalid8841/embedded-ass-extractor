// Resolving a Torrentio /resolve/realdebrid/... link to the ACTUAL final
// CDN URL, then verifying Range support on that final URL.
//
// WHY THIS EXISTS:
// The Render logs showed the MKV extractor reporting "does not support HTTP
// Range requests" and the MP4 extractor getting HTTP 403 — on a URL that an
// earlier direct probe had answered with 206 + Accept-Ranges: bytes. Those
// two facts can't both be true of the same endpoint, which points at the
// nature of the URL rather than at Range support:
//
//   torrentio.strem.fun/resolve/realdebrid/<token>/<hash>/... is not the
//   media file. It is a resolver endpoint that redirects to a Real-Debrid
//   CDN link. Hitting the resolver repeatedly (once for our probe, then
//   again from inside the extractor library, then again for MP4) is what
//   produces 403s and Range-capability checks that read as "unsupported" —
//   the library is inspecting the resolver's response, not the media
//   server's.
//
// The fix: walk the redirect chain ONCE here, keep the final URL, confirm
// Range works on THAT url, and hand the resolved URL to the extractors so
// every subsequent request goes straight to the CDN.

const MAX_RESOLVE_HOPS = 6;

// Follows redirects manually (through the caller's safeFetch, so all SSRF /
// DNS-pinning / https-only protections still apply at every hop) and returns
// the final URL plus what we learned about it.
async function resolveFinalUrl(startUrl, safeFetch, cacheKey, log) {
  let current = startUrl;

  for (let hop = 0; hop < MAX_RESOLVE_HOPS; hop++) {
    // A ranged GET is used rather than HEAD: some CDNs (and Real-Debrid in
    // particular) answer HEAD differently from GET, or reject it outright,
    // which is exactly the kind of mismatch that produced misleading
    // "Range unsupported" conclusions before.
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 20000);
    let res;
    try {
      res = await safeFetch(
        current,
        { headers: { Range: 'bytes=0-1' }, redirect: 'manual', signal: controller.signal },
        cacheKey
      );
    } finally {
      clearTimeout(timer);
    }

    const status = res.status;
    const location = res.headers.get('location');

    if ([301, 302, 303, 307, 308].includes(status) && location) {
      const next = new URL(location, current).toString();
      let nextHost = '(unparseable)';
      try {
        nextHost = new URL(next).hostname;
      } catch (_) {}
      log(cacheKey, `RESOLVE hop ${hop + 1}: ${status} -> redirects to host ${nextHost}`);
      if (res.body && typeof res.body.destroy === 'function') res.body.destroy();
      current = next;
      continue;
    }

    // Not a redirect — this is the endpoint that actually serves bytes.
    const acceptRanges = res.headers.get('accept-ranges');
    const contentRange = res.headers.get('content-range');
    const contentLength = res.headers.get('content-length');
    const contentType = res.headers.get('content-type');
    if (res.body && typeof res.body.destroy === 'function') res.body.destroy();

    let host = '(unparseable)';
    try {
      host = new URL(current).hostname;
    } catch (_) {}

    // Real Range support is proven by a 206 with a Content-Range header.
    // Accept-Ranges alone is advisory; some servers advertise it and then
    // ignore ranges, others omit it and honor ranges perfectly.
    const rangeWorks = status === 206 && Boolean(contentRange);

    // totalSize comes from Content-Range ("bytes 0-1/123456789") when
    // present, since Content-Length on a ranged response is the slice size.
    let totalSize = null;
    if (contentRange) {
      const m = /\/(\d+)\s*$/.exec(contentRange);
      if (m) totalSize = Number(m[1]);
    } else if (contentLength && status === 200) {
      totalSize = Number(contentLength);
    }

    log(
      cacheKey,
      `RESOLVE final: host=${host} status=${status} rangeWorks=${rangeWorks} contentRange=${contentRange || '(none)'} acceptRanges=${acceptRanges || '(none)'} contentType=${contentType || '(none)'} totalSize=${totalSize ?? 'unknown'} hops=${hop}`
    );

    return { url: current, status, rangeWorks, acceptRanges, contentRange, contentType, totalSize, hops: hop };
  }

  throw new Error('Too many redirect hops while resolving the stream URL');
}

module.exports = { resolveFinalUrl };

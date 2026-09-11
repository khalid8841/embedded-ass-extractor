// Local self-tests — no network required. Run with: node selftest.js
// Exercises the pure logic functions directly: SSRF/private-IP detection,
// the /subs/:file path-traversal guard pattern, ASS->SRT text cleaning,
// and the Torrentio-only manifest allowlist.

const assert = require('assert');
const { cleanAssText, isPrivateOrReservedIp, CACHE_KEY_RE, isManifestHostAllowed } = require('./lib.js');

let passed = 0;
function test(name, fn) {
  try {
    fn();
    console.log(`  ✅ ${name}`);
    passed++;
  } catch (err) {
    console.log(`  ❌ ${name}\n     ${err.message}`);
  }
}

console.log('\n--- SSRF / private IP detection ---');
test('blocks loopback 127.0.0.1', () => assert.strictEqual(isPrivateOrReservedIp('127.0.0.1'), true));
test('blocks 10.0.0.0/8', () => assert.strictEqual(isPrivateOrReservedIp('10.5.1.1'), true));
test('blocks 172.16.0.0/12', () => assert.strictEqual(isPrivateOrReservedIp('172.20.3.4'), true));
test('does NOT block 172.15.x (outside the private range)', () => assert.strictEqual(isPrivateOrReservedIp('172.15.3.4'), false));
test('blocks 192.168.0.0/16', () => assert.strictEqual(isPrivateOrReservedIp('192.168.1.1'), true));
test('blocks link-local 169.254.x', () => assert.strictEqual(isPrivateOrReservedIp('169.254.1.1'), true));
test('allows a normal public IP', () => assert.strictEqual(isPrivateOrReservedIp('8.8.8.8'), false));
test('blocks IPv6 loopback ::1', () => assert.strictEqual(isPrivateOrReservedIp('::1'), true));
test('blocks IPv6 unique-local fd00::/8', () => assert.strictEqual(isPrivateOrReservedIp('fd12:3456::1'), true));
test('allows a normal public IPv6', () => assert.strictEqual(isPrivateOrReservedIp('2606:4700:4700::1111'), false));
test('blocks CGNAT 100.64.0.0/10', () => assert.strictEqual(isPrivateOrReservedIp('100.100.1.1'), true));
test('does NOT block 100.63.x (just outside CGNAT range)', () => assert.strictEqual(isPrivateOrReservedIp('100.63.1.1'), false));
test('blocks TEST-NET-1 192.0.2.0/24', () => assert.strictEqual(isPrivateOrReservedIp('192.0.2.5'), true));
test('blocks TEST-NET-2 198.51.100.0/24', () => assert.strictEqual(isPrivateOrReservedIp('198.51.100.5'), true));
test('blocks TEST-NET-3 203.0.113.0/24', () => assert.strictEqual(isPrivateOrReservedIp('203.0.113.5'), true));
test('blocks benchmarking 198.18.0.0/15', () => assert.strictEqual(isPrivateOrReservedIp('198.19.0.1'), true));
test('blocks multicast 224.0.0.0/4', () => assert.strictEqual(isPrivateOrReservedIp('230.1.2.3'), true));
test('blocks reserved 240.0.0.0/4 and broadcast', () => {
  assert.strictEqual(isPrivateOrReservedIp('250.1.1.1'), true);
  assert.strictEqual(isPrivateOrReservedIp('255.255.255.255'), true);
});
test('blocks IPv6 unspecified ::', () => assert.strictEqual(isPrivateOrReservedIp('::'), true));
test('blocks IPv6 multicast ff00::/8', () => assert.strictEqual(isPrivateOrReservedIp('ff02::1'), true));
test('blocks full fe80::/10 link-local range (not just literal fe80 prefix)', () =>
  assert.strictEqual(isPrivateOrReservedIp('febf::1'), true));
test('unwraps IPv4-mapped IPv6 and blocks if the embedded IPv4 is private', () =>
  assert.strictEqual(isPrivateOrReservedIp('::ffff:192.168.1.1'), true));
test('unwraps IPv4-mapped IPv6 and allows if the embedded IPv4 is public', () =>
  assert.strictEqual(isPrivateOrReservedIp('::ffff:8.8.8.8'), false));

console.log('\n--- Path traversal guard (cache key format) ---');
test('accepts a valid 32-char hex cache key', () => assert.strictEqual(CACHE_KEY_RE.test('a'.repeat(32)), true));
test('rejects a traversal attempt', () => assert.strictEqual(CACHE_KEY_RE.test('../server.js'), false));
test('rejects a short/invalid key', () => assert.strictEqual(CACHE_KEY_RE.test('abc123'), false));
test('rejects a key with extra characters', () => assert.strictEqual(CACHE_KEY_RE.test('a'.repeat(32) + '.js'), false));

console.log('\n--- ASS -> SRT text cleaning ---');
test('strips a simple override tag', () => assert.strictEqual(cleanAssText('{\\an8}مرحبا'), 'مرحبا'));
test('strips a positioning tag', () => assert.strictEqual(cleanAssText('{\\pos(100,200)}نص'), 'نص'));
test('converts \\N to a real newline', () => assert.strictEqual(cleanAssText('سطر واحد\\Nسطر ثاني'), 'سطر واحد\nسطر ثاني'));
test('converts \\h to a space', () => assert.strictEqual(cleanAssText('كلمة\\hثانية'), 'كلمة ثانية'));
test('strips multiple tags and preserves Arabic text', () =>
  assert.strictEqual(cleanAssText('{\\i1}{\\an8}هذا نص عربي{\\i0}'), 'هذا نص عربي'));
test('handles empty/undefined input safely', () => {
  assert.strictEqual(cleanAssText(''), '');
  assert.strictEqual(cleanAssText(undefined), '');
});

console.log('\n--- Manifest host allowlist ---');
test('allows torrentio.strem.fun', () => assert.strictEqual(isManifestHostAllowed('https://torrentio.strem.fun/realdebrid=KEY/manifest.json'), true));
test('rejects an arbitrary/attacker-supplied host', () => assert.strictEqual(isManifestHostAllowed('https://evil.example.com/manifest.json'), false));
test('rejects a malformed URL', () => assert.strictEqual(isManifestHostAllowed('not-a-url'), false));
test('also allows a configured AIOStreams instance hostname', () =>
  assert.strictEqual(isManifestHostAllowed('https://aiostreamsfortheweebs.midnightignite.me/some/config/manifest.json'), true));

console.log('\n--- AIOStreams confirmed-subtitle prioritization ---');
{
  const { prioritizeKnownArabicSubtitles } = require('./lib.js');
  test('moves a stream with confirmed Arabic subtitle metadata to the front', () => {
    const streams = [
      { name: 'no metadata #1' },
      { name: 'has German', subtitles: ['ger'] },
      { name: 'has Arabic', subtitles: ['ara', 'eng'] },
      { name: 'no metadata #2' }
    ];
    const result = prioritizeKnownArabicSubtitles(streams);
    assert.strictEqual(result[0].name, 'has Arabic');
    assert.strictEqual(result.length, 4); // nothing dropped
  });
  test('preserves relative order among streams without confirmed metadata', () => {
    const streams = [{ name: 'a' }, { name: 'b' }, { name: 'c', subtitles: ['ara'] }, { name: 'd' }];
    const result = prioritizeKnownArabicSubtitles(streams);
    assert.deepStrictEqual(
      result.map(s => s.name),
      ['c', 'a', 'b', 'd']
    );
  });
  test('handles no confirmed-Arabic streams at all (order unchanged)', () => {
    const streams = [{ name: 'a' }, { name: 'b', subtitles: ['eng'] }];
    const result = prioritizeKnownArabicSubtitles(streams);
    assert.deepStrictEqual(
      result.map(s => s.name),
      ['a', 'b']
    );
  });
}

console.log('\n--- Manifest URL -> stream endpoint building ---');
{
  const { hasManifestSuffix, buildStreamUrl } = require('./lib.js');

  test('accepts a URL ending in /manifest.json', () =>
    assert.strictEqual(hasManifestSuffix('https://host/stremio/profile/secret/manifest.json'), true));
  test('rejects a URL missing /manifest.json (the actual bug that caused the AIOStreams 404)', () =>
    assert.strictEqual(hasManifestSuffix('https://host/stremio/profile/secret'), false));
  test('rejects a URL with manifest.json not at the very end', () =>
    assert.strictEqual(hasManifestSuffix('https://host/manifest.json?foo=bar'), false));

  test('preserves every path segment (profile + secret) when building the stream URL', () => {
    const input = 'https://host/stremio/profile/secret/manifest.json';
    const result = buildStreamUrl(input, 'series', 'tt9679542:4:15');
    assert.strictEqual(result, 'https://host/stremio/profile/secret/stream/series/tt9679542:4:15.json');
  });
  test('works the same way for a simple Torrentio-style URL (no regression)', () => {
    const input = 'https://torrentio.strem.fun/realdebrid=FAKEKEY/manifest.json';
    const result = buildStreamUrl(input, 'movie', 'tt1234567');
    assert.strictEqual(result, 'https://torrentio.strem.fun/realdebrid=FAKEKEY/stream/movie/tt1234567.json');
  });
}

console.log(`\n${passed} test(s) passed.\n`);

console.log('--- Notes on what is NOT covered by these offline tests ---');
console.log('  - Live redirect-following behavior (safeFetch) needs a real network call to verify end-to-end.');
console.log('  - Cache TTL/negative-cache expiry is time-based; verify by inspecting cache/*.meta.json "extractedAt" after a real run.');
console.log('  - Rate limiting and concurrency caps are exercised only under real concurrent requests to a running server.');

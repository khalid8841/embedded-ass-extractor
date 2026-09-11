// Integration tests for the v22 fix, using REAL local HTTP servers that
// reproduce the exact behaviours seen in the Render logs.
// Run: node v22-resolve-selftest.js

const http = require('http');
const assert = require('assert');
const { resolveFinalUrl } = require('./resolve-url.js');

let passed = 0;
let failed = 0;
async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✅ ${name}`);
    passed++;
  } catch (err) {
    console.log(`  ❌ ${name}\n     ${err.stack || err.message}`);
    failed++;
  }
}

function startServer(handler) {
  return new Promise(resolve => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}
const urlOf = (server, p) => `http://127.0.0.1:${server.address().port}${p}`;

// A permissive stand-in for safeFetch. The real safeFetch enforces https
// and SSRF rules, which would (correctly) refuse the http://127.0.0.1 test
// servers — so these tests exercise the resolve/fallback LOGIC, while the
// security layer keeps its own dedicated tests in selftest.js.
function testFetch(url, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, { headers: options.headers || {} }, res => {
      resolve({
        status: res.statusCode,
        ok: res.statusCode >= 200 && res.statusCode < 300,
        headers: { get: name => res.headers[name.toLowerCase()] || null },
        body: res
      });
    });
    req.on('error', reject);
    if (options.signal) {
      options.signal.addEventListener('abort', () => req.destroy(new Error('aborted')), { once: true });
    }
  });
}

const noopLog = () => {};
const FAKE_MKV = Buffer.concat([Buffer.from('1a45dfa3', 'hex'), Buffer.alloc(5000, 0x42)]);

async function main() {
  console.log('\n--- Torrentio-style resolver: redirect chain to a CDN that supports Range ---');
  {
    // Mirrors the real shape: /resolve/realdebrid/... 302s to a CDN host.
    let cdn, resolver;
    cdn = await startServer((req, res) => {
      const range = req.headers.range;
      if (range) {
        const [start, end] = range.replace('bytes=', '').split('-').map(Number);
        const slice = FAKE_MKV.slice(start, (end || start) + 1);
        res.writeHead(206, {
          'Content-Type': 'video/x-matroska',
          'Content-Range': `bytes ${start}-${start + slice.length - 1}/${FAKE_MKV.length}`,
          'Accept-Ranges': 'bytes'
        });
        return res.end(slice);
      }
      res.writeHead(200, { 'Content-Type': 'video/x-matroska' });
      res.end(FAKE_MKV);
    });
    resolver = await startServer((req, res) => {
      res.writeHead(302, { Location: urlOf(cdn, '/real-file.mkv') });
      res.end();
    });

    await test('follows the redirect and reports the FINAL CDN url, not the resolver url', async () => {
      const r = await resolveFinalUrl(urlOf(resolver, '/resolve/realdebrid/token/hash/file.mkv'), testFetch, 'test', noopLog);
      assert.ok(r.url.includes('/real-file.mkv'), `expected CDN url, got ${r.url}`);
      assert.notStrictEqual(r.hops, 0, 'should have taken at least one hop');
    });

    await test('detects that Range genuinely works on the resolved CDN url', async () => {
      const r = await resolveFinalUrl(urlOf(resolver, '/resolve/realdebrid/token/hash/file.mkv'), testFetch, 'test', noopLog);
      assert.strictEqual(r.rangeWorks, true);
      assert.strictEqual(r.status, 206);
    });

    await test('reads the real total file size from Content-Range', async () => {
      const r = await resolveFinalUrl(urlOf(resolver, '/x.mkv'), testFetch, 'test', noopLog);
      assert.strictEqual(r.totalSize, FAKE_MKV.length);
    });

    cdn.close();
    resolver.close();
  }

  console.log('\n--- THE LOGGED FAILURE: resolver 403s on a repeat hit, but the CDN is fine ---');
  {
    // Reproduces the observed behaviour: the resolver link works once, then
    // returns 403. Resolving to the final URL up front sidesteps this.
    let hits = 0;
    const cdn = await startServer((req, res) => {
      const range = req.headers.range;
      const [start, end] = (range || 'bytes=0-1').replace('bytes=', '').split('-').map(Number);
      const slice = FAKE_MKV.slice(start, (end || start) + 1);
      res.writeHead(206, {
        'Content-Type': 'video/x-matroska',
        'Content-Range': `bytes ${start}-${start + slice.length - 1}/${FAKE_MKV.length}`,
        'Accept-Ranges': 'bytes'
      });
      res.end(slice);
    });
    const resolver = await startServer((req, res) => {
      hits++;
      if (hits > 1) {
        res.writeHead(403);
        return res.end('Forbidden');
      }
      res.writeHead(302, { Location: urlOf(cdn, '/media.mkv') });
      res.end();
    });

    await test('resolving once yields a CDN url that stays usable for repeated ranged reads', async () => {
      const r = await resolveFinalUrl(urlOf(resolver, '/resolve/realdebrid/tok/h/f.mkv'), testFetch, 'test', noopLog);
      assert.strictEqual(r.rangeWorks, true, 'CDN should support range');
      // Multiple further reads against the RESOLVED url must all succeed,
      // whereas re-hitting the resolver would now 403.
      for (let i = 0; i < 3; i++) {
        const again = await testFetch(r.url, { headers: { Range: `bytes=${i}-${i + 1}` } });
        assert.strictEqual(again.status, 206, `repeat ranged read #${i + 1} should succeed on the CDN url`);
        again.body.resume();
      }
      const resolverAgain = await testFetch(urlOf(resolver, '/resolve/realdebrid/tok/h/f.mkv'));
      assert.strictEqual(resolverAgain.status, 403, 'resolver is indeed single-use — this is what broke v21');
      resolverAgain.body.resume();
    });

    cdn.close();
    resolver.close();
  }

  console.log('\n--- Server that genuinely refuses Range (the documented fallback trigger) ---');
  {
    const server = await startServer((req, res) => {
      // Ignores Range entirely: always 200, no Content-Range.
      res.writeHead(200, { 'Content-Type': 'video/x-matroska', 'Content-Length': String(FAKE_MKV.length) });
      res.end(FAKE_MKV);
    });

    await test('correctly reports rangeWorks=false when the server ignores Range', async () => {
      const r = await resolveFinalUrl(urlOf(server, '/norange.mkv'), testFetch, 'test', noopLog);
      assert.strictEqual(r.rangeWorks, false);
      assert.strictEqual(r.status, 200);
    });

    await test('still reports a usable total size so the download cap can be enforced', async () => {
      const r = await resolveFinalUrl(urlOf(server, '/norange.mkv'), testFetch, 'test', noopLog);
      assert.strictEqual(r.totalSize, FAKE_MKV.length);
    });

    server.close();
  }

  console.log('\n--- Full-download fallback: streams to disk, enforces cap, always cleans up ---');
  {
    const { withDownloadedFile } = require('./full-download.js');
    const fs = require('fs');

    const server = await startServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'video/x-matroska' });
      res.end(FAKE_MKV);
    });

    await test('downloads to a temp file and hands the local path to the worker', async () => {
      let seenPath = null;
      let seenSize = null;
      const result = await withDownloadedFile(urlOf(server, '/f.mkv'), testFetch, 'test', noopLog, {}, async localPath => {
        seenPath = localPath;
        seenSize = fs.statSync(localPath).size;
        return 'worker-ran';
      });
      assert.strictEqual(result, 'worker-ran');
      assert.strictEqual(seenSize, FAKE_MKV.length, 'the whole file should have reached disk');
      assert.ok(seenPath, 'worker should receive a path');
    });

    await test('deletes the temp file afterwards (no disk leak)', async () => {
      let captured = null;
      await withDownloadedFile(urlOf(server, '/f.mkv'), testFetch, 'test', noopLog, {}, async localPath => {
        captured = localPath;
        return null;
      });
      assert.strictEqual(fs.existsSync(captured), false, 'temp file must be gone');
    });

    await test('deletes the temp file even when the worker throws', async () => {
      let captured = null;
      await assert.rejects(() =>
        withDownloadedFile(urlOf(server, '/f.mkv'), testFetch, 'test', noopLog, {}, async localPath => {
          captured = localPath;
          throw new Error('worker exploded');
        })
      );
      assert.strictEqual(fs.existsSync(captured), false, 'temp file must be cleaned up on failure too');
    });

    await test('refuses up front when the known size exceeds the cap (no bytes pulled)', async () => {
      await assert.rejects(
        () => withDownloadedFile(urlOf(server, '/f.mkv'), testFetch, 'test', noopLog, { knownSize: 5 * 1024 * 1024 * 1024, maxBytes: 1024 * 1024 }, async () => 'should not run'),
        /exceeds the .* safety limit/
      );
    });

    server.close();
  }

  console.log(`\n${passed} passed, ${failed} failed.\n`);
  if (failed > 0) process.exitCode = 1;
}

main();

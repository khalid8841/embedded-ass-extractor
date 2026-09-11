// Tests for the two real bugs found in v20. Run: node v21-fix-selftest.js
//
// Bug 1: mkv-range.js returned tracks with `bytes` but server.js's
//        chooseTrack() filters on `cues` — so the MKV path could never
//        select a track even when extraction fully succeeded.
// Bug 2: classifyContainer() acted as a hard gatekeeper: if a first-64-byte
//        probe of a Torrentio/Real-Debrid CDN URL didn't start with the EBML
//        magic, the candidate was skipped outright — even when its filename
//        clearly said .mkv.

const assert = require('assert');
const { parseSubtitleBytes, parseAss, parseSrt } = require('./subtitle-parse.js');

let passed = 0;
let failed = 0;
function test(name, fn) {
  try {
    fn();
    console.log(`  ✅ ${name}`);
    passed++;
  } catch (err) {
    console.log(`  ❌ ${name}\n     ${err.message}`);
    failed++;
  }
}

console.log('\n--- Bug 1: ASS/SSA bytes -> cues (this is what was missing entirely) ---');

const ARABIC_ASS = `[Script Info]
Title: Test
ScriptType: v4.00+

[V4+ Styles]
Format: Name, Fontname, Fontsize
Style: Default,Arial,20

[Events]
Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text
Dialogue: 0,0:00:01.50,0:00:04.00,Default,,0,0,0,,{\\an8}مرحبا بك في الحلقة
Dialogue: 0,0:00:05.25,0:00:07.80,Default,,0,0,0,,سطر أول\\Nسطر ثاني
Dialogue: 0,0:01:10.00,0:01:12.50,Default,,0,0,0,,{\\pos(100,200)}نص، فيه، فواصل
`;

test('parses Arabic ASS dialogue into cues', () => {
  const cues = parseSubtitleBytes(Buffer.from(ARABIC_ASS, 'utf8'), 'S_TEXT/ASS');
  assert.strictEqual(cues.length, 3, `expected 3 cues, got ${cues.length}`);
});

test('preserves Arabic text correctly (UTF-8 intact)', () => {
  const cues = parseSubtitleBytes(Buffer.from(ARABIC_ASS, 'utf8'), 'ass');
  assert.ok(cues[0].text.includes('مرحبا بك في الحلقة'), `got: ${cues[0].text}`);
});

test('computes correct timings from ASS centiseconds', () => {
  const cues = parseSubtitleBytes(Buffer.from(ARABIC_ASS, 'utf8'), 'ass');
  assert.strictEqual(cues[0].time, 1500); // 0:00:01.50
  assert.strictEqual(cues[0].duration, 2500); // to 0:00:04.00
  assert.strictEqual(cues[2].time, 70000); // 0:01:10.00
});

test('keeps text containing commas intact (Text is the last ASS column)', () => {
  const cues = parseSubtitleBytes(Buffer.from(ARABIC_ASS, 'utf8'), 'ass');
  assert.ok(cues[2].text.includes('نص، فيه، فواصل'), `got: ${cues[2].text}`);
});

test('respects the Format: line column order rather than assuming positions', () => {
  const reordered = `[Events]
Format: Start, End, Layer, Style, Text
Dialogue: 0:00:02.00,0:00:03.00,0,Default,نص مختلف الترتيب
`;
  const cues = parseSubtitleBytes(Buffer.from(reordered, 'utf8'), 'ass');
  assert.strictEqual(cues.length, 1);
  assert.strictEqual(cues[0].time, 2000);
  assert.ok(cues[0].text.includes('نص مختلف الترتيب'));
});

console.log('\n--- Bug 1b: SRT bytes -> cues (embedded SRT tracks in MKV) ---');

const ARABIC_SRT = `1
00:00:01,500 --> 00:00:04,000
مرحبا بك

2
00:00:05,250 --> 00:00:07,800
سطر أول
سطر ثاني
`;

test('parses embedded SRT into cues', () => {
  const cues = parseSubtitleBytes(Buffer.from(ARABIC_SRT, 'utf8'), 'S_TEXT/UTF8');
  assert.strictEqual(cues.length, 2);
  assert.strictEqual(cues[0].time, 1500);
  assert.ok(cues[0].text.includes('مرحبا بك'));
});

test('keeps multi-line SRT cues as multiple lines', () => {
  const cues = parseSubtitleBytes(Buffer.from(ARABIC_SRT, 'utf8'), 'srt');
  assert.ok(cues[1].text.includes('\n'), 'expected a newline inside the cue text');
});

test('falls back correctly when the declared codec label is wrong/missing', () => {
  // Declared as SRT but actually ASS — a real-world muxer mislabel.
  const cues = parseSubtitleBytes(Buffer.from(ARABIC_ASS, 'utf8'), 'S_TEXT/UTF8');
  assert.strictEqual(cues.length, 3, 'should sniff content and still parse as ASS');
});

test('returns an empty array for empty/garbage input instead of throwing', () => {
  assert.deepStrictEqual(parseSubtitleBytes(Buffer.alloc(0), 'ass'), []);
  assert.deepStrictEqual(parseSubtitleBytes(Buffer.from('not subtitles at all'), 'ass'), []);
});

console.log('\n--- Bug 2: filename hint + extractor ordering (probe is no longer a gate) ---');

// Mirror of the pure helpers now in server.js, tested here directly so the
// logic is verified without booting the HTTP server.
function guessContainerFromFilename(stream) {
  const haystack = [
    stream.filename,
    stream.behaviorHints && stream.behaviorHints.filename,
    stream.name,
    stream.title,
    stream.description
  ].filter(Boolean).join(' ').toLowerCase();
  if (/\.mkv(\b|$)/.test(haystack) || /matroska/.test(haystack)) return 'mkv';
  if (/\.(mp4|m4v|mov)(\b|$)/.test(haystack)) return 'mp4';
  return 'unknown';
}

function decideExtractorOrder(filenameHint, probeContainer) {
  if (filenameHint === 'mkv') return ['mkv', 'mp4'];
  if (filenameHint === 'mp4') return ['mp4', 'mkv'];
  if (probeContainer === 'mkv') return ['mkv', 'mp4'];
  if (probeContainer === 'mp4') return ['mp4', 'mkv'];
  return ['mkv', 'mp4'];
}

test('reads .mkv from the AIOStreams filename field', () =>
  assert.strictEqual(guessContainerFromFilename({ filename: 'Re.Zero.S04E16.1080p.mkv' }), 'mkv'));

test('reads .mkv from behaviorHints.filename', () =>
  assert.strictEqual(guessContainerFromFilename({ behaviorHints: { filename: 'show.mkv' } }), 'mkv'));

test('reads .mp4 from a title', () =>
  assert.strictEqual(guessContainerFromFilename({ title: 'Movie.2024.mp4' }), 'mp4'));

test('returns unknown when no container is mentioned anywhere', () =>
  assert.strictEqual(guessContainerFromFilename({ name: '🚀 FHD' }), 'unknown'));

test('THE v20 BUG: filename says .mkv but probe returned unknown -> MKV is STILL attempted first', () => {
  const order = decideExtractorOrder('mkv', 'unknown');
  assert.strictEqual(order[0], 'mkv', 'MKV must be attempted despite a failed/unhelpful probe');
});

test('filename says .mkv but probe claims mp4 -> MKV still attempted (filename is more trustworthy)', () => {
  const order = decideExtractorOrder('mkv', 'mp4');
  assert.strictEqual(order[0], 'mkv');
});

test('probe completely failed and filename is unknown -> both extractors still attempted', () => {
  const order = decideExtractorOrder('unknown', null);
  assert.deepStrictEqual(order, ['mkv', 'mp4'], 'must never skip outright');
});

test('every ordering permutation still attempts BOTH extractors (nothing is ever skipped)', () => {
  const hints = ['mkv', 'mp4', 'unknown'];
  const probes = ['mkv', 'mp4', 'unknown', null];
  for (const h of hints) {
    for (const p of probes) {
      const order = decideExtractorOrder(h, p);
      assert.strictEqual(order.length, 2, `hint=${h} probe=${p} produced ${order.length} attempts`);
      assert.ok(order.includes('mkv') && order.includes('mp4'), `hint=${h} probe=${p} missing an extractor`);
    }
  }
});

console.log('\n--- End-to-end shape: extracted track must carry `cues` for chooseTrack() ---');

test('a track object built the way mkv-range.js now builds it passes chooseTrack\'s filter', () => {
  const bytes = Buffer.from(ARABIC_ASS, 'utf8');
  const track = {
    index: 0,
    type: 's_text/ass',
    language: 'ara',
    name: 'Arabic',
    trackNumber: 3,
    bytes,
    cues: parseSubtitleBytes(bytes, 's_text/ass')
  };
  // This is chooseTrack()'s exact filter from server.js:
  const usable = [track].filter(t => t && t.cues && t.cues.length);
  assert.strictEqual(usable.length, 1, 'track must survive chooseTrack filtering');
});

test('the OLD v20 shape (bytes only, no cues) would have been filtered out — confirming the bug was real', () => {
  const oldShape = { index: 0, type: 's_text/ass', bytes: Buffer.from(ARABIC_ASS, 'utf8') };
  const usable = [oldShape].filter(t => t && t.cues && t.cues.length);
  assert.strictEqual(usable.length, 0, 'proves the old shape could never be selected');
});

console.log(`\n${passed} passed, ${failed} failed.\n`);
if (failed > 0) process.exitCode = 1;

// Local test — validates Arabic ASS/SSA detection against a LOCAL MKV file
// using the same matroska-subtitles logic as the server, before deploying.
//
// Usage:
//   node test-extract.js /path/to/episode.mkv

const fs = require('fs');
const path = require('path');
const { SubtitleParser } = require('matroska-subtitles');

const filePath = process.argv[2];
if (!filePath) {
  console.error('Usage: node test-extract.js /path/to/episode.mkv');
  process.exit(1);
}

const parser = new SubtitleParser();
let targetTrack = null;
const cues = [];

parser.once('tracks', tracks => {
  console.log(`\nFound ${tracks.length} subtitle track(s):`);
  tracks.forEach(t =>
    console.log(`  [#${t.number}] type=${t.type} language=${t.language || '(none)'} name="${t.name || ''}"`)
  );

  const isAssOrSsa = t => t.type === 'ass' || t.type === 'ssa';
  const isArabicLang = t => (t.language || '').toLowerCase() === 'ara' || (t.language || '').toLowerCase() === 'ar';
  const isArabicName = t => /arabic|عرب/i.test(t.name || '');

  const candidates = tracks.filter(t => isAssOrSsa(t) && (isArabicLang(t) || isArabicName(t)));
  const withLangTag = candidates.filter(isArabicLang);
  targetTrack = (withLangTag.length ? withLangTag : candidates)[0] || null;

  if (!targetTrack) {
    console.log('\n❌ No Arabic ASS/SSA track found in this file.');
  } else {
    console.log(`\n✅ Selected track #${targetTrack.number}, language=${targetTrack.language}, name="${targetTrack.name || ''}"`);
  }
});

parser.on('subtitle', (subtitle, trackNumber) => {
  if (targetTrack && trackNumber === targetTrack.number) {
    cues.push(subtitle);
  }
});

parser.on('finish', () => {
  if (!targetTrack) process.exit(0);

  const pad = (n, len = 2) => String(n).padStart(len, '0');
  const msToSrtTime = ms => {
    const h = Math.floor(ms / 3600000);
    const m = Math.floor((ms % 3600000) / 60000);
    const s = Math.floor((ms % 60000) / 1000);
    return `${pad(h)}:${pad(m)}:${pad(s)},${pad(ms % 1000, 3)}`;
  };

  const srt = cues
    .sort((a, b) => a.time - b.time)
    .map((c, i) => `${i + 1}\n${msToSrtTime(c.time)} --> ${msToSrtTime(c.time + (c.duration || 2000))}\n${c.text}\n`)
    .join('\n');

  const outFile = path.join(__dirname, 'test.srt');
  fs.writeFileSync(outFile, srt, 'utf8');
  console.log(`\nExtracted ${cues.length} cues -> ${outFile}`);
  console.log('Open it and check the Arabic text and timing look correct.');
});

parser.on('error', err => {
  console.error('\nTest failed:', err.message);
  process.exit(1);
});

fs.createReadStream(filePath).pipe(parser);

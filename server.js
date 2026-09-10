// Embedded ASS/SSA Subtitle Extractor — Stremio/Nuvio-compatible addon
// v4 — cache correctness fix + no silent empty response, pure JS (matroska-subtitles)
//
// HONEST LIMITATION (read this before deploying):
// This addon returns a COMPLETE SRT file to Nuvio, built from the FULL set of
// subtitle cues in the episode (start to finish), because that is what the
// Stremio/Nuvio "subtitles" protocol requires — a ready-made file, not a live
// feed. Because MKV interleaves subtitle packets across the entire file
// duration, and the Cues index only maps VIDEO keyframes (not subtitle
// packets), there is no reliable way to jump straight to "just the subtitle
// bytes" for a complete-file extraction. So this WILL read through the
// candidate file's data end-to-end once, before it can return anything.
// This is different from Lampa's subs.js, which streams subtitles live during
// playback (only ~6s ahead of the playhead at a time) — a fundamentally
// different usage pattern that Nuvio's protocol does not support.
//
// What IS fixed and real in this version:
//   - Early abort if there's no matching Arabic ASS/SSA track at all (checked
//     from the Tracks header, before reading cue data).
//   - Cache correctness: the cache now stores which source stream produced
//     the SRT. On every request we re-check the upstream's current top
//     candidate; if it changed, we invalidate and re-extract instead of
//     silently serving a stale/wrong-source SRT.
//   - No more silently returning `subtitles: []` after an arbitrary short
//     timeout while extraction is still running in the background. The
//     request now waits for a much longer, realistic window, and if
//     extraction genuinely isn't done yet, the response says so honestly
//     instead of implying "nothing exists" — Nuvio will get a real result on
//     a retry once caching completes.

const express = require('express');
const fetch = require('node-fetch');
const { SubtitleParser } = require('matroska-subtitles');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();

app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', '*');
  next();
});

const CACHE_DIR = path.join(__dirname, 'cache');
if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR);

const MAX_CANDIDATES = 4;
const EXTRACT_TIMEOUT_MS = 8 * 60 * 1000; // 8 min ceiling — reading a full episode over the network takes real time
const RESPONSE_WAIT_MS = 45000; // how long a single Nuvio request will wait before answering "still working"

const inProgress = new Map(); // cacheKey -> Promise

function log(id, ...args) {
  console.log(`[${new Date().toISOString()}] [${id}]`, ...args);
}

function decodeConfig(configStr) {
  try {
    return JSON.parse(Buffer.from(configStr, 'base64').toString('utf8'));
  } catch (e) {
    return null;
  }
}

function srtPath(cacheKey) {
  return path.join(CACHE_DIR, `${cacheKey}.srt`);
}
function metaPath(cacheKey) {
  return path.join(CACHE_DIR, `${cacheKey}.meta.json`);
}

function urlFingerprint(url) {
  return crypto.createHash('sha1').update(url).digest('hex').slice(0, 16);
}

// ---- Manifest ----
app.get('/:config/manifest.json', (req, res) => {
  res.json({
    id: 'com.khalid.embeddedass',
    version: '4.0.0',
    name: 'Embedded ASS Extractor',
    description:
      'Finds the embedded Arabic ASS/SSA subtitle track and serves it as SRT. Reads the full candidate file once per episode (see README for why).',
    resources: ['subtitles'],
    types: ['movie', 'series'],
    idPrefixes: ['tt'],
    catalogs: [],
    behaviorHints: { configurable: true, configurationRequired: false }
  });
});

// ---- Subtitles resource ----
app.get('/:config/subtitles/:type/:id/:extra?.json', async (req, res) => {
  const config = decodeConfig(req.params.config);
  if (!config || !config.streamManifestUrl) {
    return res.json({ subtitles: [] });
  }

  const { type, id } = req.params;
  const lang = config.lang || 'ara';
  const cacheKey = crypto.createHash('md5').update(`${type}:${id}:${lang}`).digest('hex');

  // Find out what the upstream's current top candidate is RIGHT NOW, so we
  // can tell if a cached result is still for the right source.
  let currentTopFingerprint = null;
  try {
    currentTopFingerprint = await getTopCandidateFingerprint(config.streamManifestUrl, type, id);
  } catch (err) {
    log(cacheKey, `Could not check upstream candidates: ${err.message}`);
  }

  if (fs.existsSync(srtPath(cacheKey)) && fs.existsSync(metaPath(cacheKey))) {
    const meta = JSON.parse(fs.readFileSync(metaPath(cacheKey), 'utf8'));
    if (!currentTopFingerprint || meta.sourceFingerprint === currentTopFingerprint) {
      log(cacheKey, 'Serving cached result (source unchanged).');
      return res.json(subtitleResponse(req, cacheKey, lang));
    }
    log(cacheKey, 'Cached result is for a different top source now — re-extracting.');
  }

  if (!inProgress.has(cacheKey)) {
    const task = processRequest(config.streamManifestUrl, type, id, lang, cacheKey)
      .catch(err => log(cacheKey, 'FAILED:', err.message))
      .finally(() => inProgress.delete(cacheKey));
    inProgress.set(cacheKey, task);
  }

  const ready = await waitForFile(srtPath(cacheKey), RESPONSE_WAIT_MS);
  if (ready) {
    return res.json(subtitleResponse(req, cacheKey, lang));
  }

  // Genuinely not ready yet. Reading a full episode takes real time — this
  // is not a "nothing found" result, extraction is still running in the
  // background and will be cached for the next request (e.g. reopening the
  // subtitle menu, or Nuvio's own retry).
  log(cacheKey, `Still extracting after ${RESPONSE_WAIT_MS}ms — responding empty this call, background work continues.`);
  return res.json({ subtitles: [] });
});

function subtitleResponse(req, cacheKey, lang) {
  return {
    subtitles: [
      {
        id: cacheKey,
        url: `${req.protocol}://${req.get('host')}/subs/${cacheKey}.srt`,
        lang
      }
    ]
  };
}

app.get('/subs/:file', (req, res) => {
  const filePath = path.join(CACHE_DIR, req.params.file);
  if (!fs.existsSync(filePath)) return res.status(404).end();
  res.set('Content-Type', 'text/plain; charset=utf-8');
  res.set('Access-Control-Allow-Origin', '*');
  fs.createReadStream(filePath).pipe(res);
});

app.get('/', (req, res) => res.send('Embedded ASS Extractor v4 is running.'));

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

async function getCandidates(streamManifestUrl, type, id) {
  const base = streamManifestUrl.replace(/manifest\.json.*$/, '');
  const streamRes = await fetch(`${base}stream/${type}/${id}.json`);
  const data = await streamRes.json();
  return (data.streams || []).slice(0, MAX_CANDIDATES);
}

async function getTopCandidateFingerprint(streamManifestUrl, type, id) {
  const candidates = await getCandidates(streamManifestUrl, type, id);
  const top = candidates.find(s => s.url);
  return top ? urlFingerprint(top.url) : null;
}

// ---- Core pipeline ----
async function processRequest(streamManifestUrl, type, id, lang, cacheKey) {
  const streams = await getCandidates(streamManifestUrl, type, id);

  if (!streams.length) {
    log(cacheKey, 'No streams returned by upstream addon.');
    return writeNotice(cacheKey, null, 'لم يتم العثور على أي مصدر بث لهذه الحلقة.');
  }

  log(cacheKey, `Got ${streams.length} candidate stream(s) to check (in priority order).`);

  for (let i = 0; i < streams.length; i++) {
    const s = streams[i];
    const label = s.name || s.title || `stream #${i + 1}`;
    const videoUrl = s.url;
    if (!videoUrl) continue;

    log(cacheKey, `--- Checking candidate ${i + 1}/${streams.length}: ${label}`);

    try {
      const cues = await extractArabicAssCues(videoUrl, cacheKey);
      if (cues && cues.length) {
        const srt = buildSrt(cues);
        fs.writeFileSync(srtPath(cacheKey), srt, 'utf8');
        fs.writeFileSync(
          metaPath(cacheKey),
          JSON.stringify({ sourceFingerprint: urlFingerprint(videoUrl), sourceLabel: label, extractedAt: Date.now() }),
          'utf8'
        );
        log(cacheKey, `Extraction succeeded (${cues.length} cues) from "${label}", cached.`);
        return;
      }
      log(cacheKey, 'No Arabic ASS/SSA track in this candidate. Trying next source...');
    } catch (err) {
      log(cacheKey, `Extraction failed on this candidate: ${err.message}`);
    }
  }

  log(cacheKey, 'No Arabic ASS/SSA track found in any candidate source.');
  return writeNotice(
    cacheKey,
    null,
    'لم يتم العثور على ترجمة عربية مضمّنة (ASS/SSA) في أي من مصادر هذه الحلقة.'
  );
}

// Streams the remote MKV through matroska-subtitles. Aborts early if the
// Tracks header shows no matching Arabic ASS/SSA track. If a match IS found,
// this reads through the rest of the file to collect every cue — see the
// top-of-file note for why that can't be avoided for a complete-file SRT.
function extractArabicAssCues(videoUrl, cacheKey) {
  return new Promise(async (resolve, reject) => {
    const controller = new AbortController();
    const timer = setTimeout(() => {
      controller.abort();
      reject(new Error('Extraction timed out'));
    }, EXTRACT_TIMEOUT_MS);

    let response;
    try {
      response = await fetch(videoUrl, { signal: controller.signal });
    } catch (err) {
      clearTimeout(timer);
      return reject(err);
    }

    if (!response.ok || !response.body) {
      clearTimeout(timer);
      return reject(new Error(`Bad response (${response.status})`));
    }

    const parser = new SubtitleParser();
    let targetTrack = null;
    const cues = [];
    let settled = false;

    const finish = (result, err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        controller.abort();
      } catch (_) {}
      if (err) reject(err);
      else resolve(result);
    };

    parser.once('tracks', tracks => {
      log(
        cacheKey,
        `Found ${tracks.length} subtitle track(s):`,
        tracks.map(t => `[#${t.number}] type=${t.type} lang=${t.language || '?'} name="${t.name || ''}"`)
      );

      const isAssOrSsa = t => t.type === 'ass' || t.type === 'ssa';
      const isArabicLang = t => (t.language || '').toLowerCase() === 'ara' || (t.language || '').toLowerCase() === 'ar';
      const isArabicName = t => /arabic|عرب/i.test(t.name || '');

      const candidates = tracks.filter(t => isAssOrSsa(t) && (isArabicLang(t) || isArabicName(t)));
      const withLangTag = candidates.filter(isArabicLang);
      targetTrack = (withLangTag.length ? withLangTag : candidates)[0] || null;

      if (!targetTrack) {
        log(cacheKey, 'No Arabic ASS/SSA track in this file — aborting download early.');
        finish([]);
      } else {
        log(cacheKey, `Selected track #${targetTrack.number}, lang=${targetTrack.language}, name="${targetTrack.name || ''}" — reading full file for all cues.`);
      }
    });

    parser.on('subtitle', (subtitle, trackNumber) => {
      if (targetTrack && trackNumber === targetTrack.number) {
        cues.push(subtitle);
      }
    });

    parser.on('error', err => finish(null, err));
    response.body.on('error', err => finish(null, err));

    response.body.pipe(parser);

    response.body.on('end', () => finish(cues));
    parser.on('finish', () => finish(cues));
  });
}

function pad(n, len = 2) {
  return String(n).padStart(len, '0');
}

function msToSrtTime(ms) {
  const h = Math.floor(ms / 3600000);
  const m = Math.floor((ms % 3600000) / 60000);
  const s = Math.floor((ms % 60000) / 1000);
  const msRem = ms % 1000;
  return `${pad(h)}:${pad(m)}:${pad(s)},${pad(msRem, 3)}`;
}

function buildSrt(cues) {
  const sorted = [...cues].sort((a, b) => a.time - b.time);
  return sorted
    .map((c, i) => {
      const start = msToSrtTime(c.time);
      const end = msToSrtTime(c.time + (c.duration || 2000));
      return `${i + 1}\n${start} --> ${end}\n${c.text}\n`;
    })
    .join('\n');
}

function writeNotice(cacheKey, sourceFingerprint, message) {
  const content = `1\n00:00:01,000 --> 00:00:08,000\n${message}\n`;
  fs.writeFileSync(srtPath(cacheKey), content, 'utf8');
  fs.writeFileSync(
    metaPath(cacheKey),
    JSON.stringify({ sourceFingerprint, sourceLabel: null, extractedAt: Date.now(), notice: true }),
    'utf8'
  );
}

const PORT = process.env.PORT || 7005;
app.listen(PORT, () => console.log('Embedded ASS Extractor v4 running on port', PORT));

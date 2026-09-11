// MKV extraction using the actively maintained Range-based extractor.
// It returns ALL text subtitle tracks; language filtering happens only when
// selecting the output track, never during discovery.
const { parseSubtitleBytes } = require('./subtitle-parse.js');

let extractorPromise;

async function getExtractor() {
  if (!extractorPromise) {
    extractorPromise = import('@cryguy/mkv-subtitle-extractor');
  }
  const mod = await extractorPromise;
  return mod.extractSubtitles || mod.default?.extractSubtitles || mod.default;
}

async function extractMkvTracks(url, safeFetch, cacheKey) {
  const extractSubtitles = await getExtractor();
  if (typeof extractSubtitles !== 'function') throw new Error('MKV Range extractor API not found');

  const customFetch = (requestUrl, options = {}) => {
    const headers = options.headers || {};
    return safeFetch(requestUrl, { ...options, headers }, cacheKey);
  };

  const tracks = await extractSubtitles(url, {
    languages: undefined,
    allowFullDownload: false,
    concurrency: 2,
    fetch: customFetch,
    verbose: false,
  });

  return (tracks || []).map((t, i) => {
    const type = String(t.type || '').toLowerCase();
    const bytes = Buffer.from(t.output?.subtitle || []);
    // CRITICAL: the rest of the pipeline (chooseTrack/buildSrt) works on
    // `cues`, not raw bytes. Without this conversion the MKV path silently
    // yielded zero usable tracks no matter how well extraction worked.
    const cues = parseSubtitleBytes(bytes, type);
    return {
      index: i,
      type,
      language: t.metadata?.language,
      name: t.metadata?.trackName,
      trackNumber: t.metadata?.trackNumber,
      bytes,
      cues,
    };
  }).filter(t => t.bytes.length);
}

// Extracts subtitle tracks from a LOCAL file path, used by the
// full-download fallback when the remote server refuses Range requests.
// Uses the streaming matroska-subtitles parser over a plain read stream —
// no Range needed, and the file is read once from disk rather than held in
// memory.
async function extractMkvTracksFromFile(localPath, cacheKey) {
  const fs = require('fs');
  const { SubtitleParser } = require('matroska-subtitles');

  return new Promise((resolve, reject) => {
    const parser = new SubtitleParser();
    const byTrack = new Map();
    let trackMeta = [];

    parser.once('tracks', tracks => {
      trackMeta = tracks || [];
    });

    parser.on('subtitle', (subtitle, trackNumber) => {
      if (!byTrack.has(trackNumber)) byTrack.set(trackNumber, []);
      byTrack.get(trackNumber).push(subtitle);
    });

    parser.on('error', reject);
    parser.on('finish', () => {
      const out = [];
      for (const meta of trackMeta) {
        const cues = byTrack.get(meta.number) || [];
        if (!cues.length) continue;
        out.push({
          index: out.length,
          type: String(meta.type || '').toLowerCase(),
          language: meta.language,
          name: meta.name,
          trackNumber: meta.number,
          bytes: Buffer.alloc(0),
          cues: cues.map(c => ({ time: c.time, duration: c.duration, text: c.text })),
        });
      }
      resolve(out);
    });

    fs.createReadStream(localPath).on('error', reject).pipe(parser);
  });
}

module.exports = { extractMkvTracks, extractMkvTracksFromFile };

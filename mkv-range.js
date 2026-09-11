// MKV extraction using the actively maintained Range-based extractor.
// It returns ALL text subtitle tracks; language filtering happens only when
// selecting the output track, never during discovery.
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

  return (tracks || []).map((t, i) => ({
    index: i,
    type: String(t.type || '').toLowerCase(),
    language: t.metadata?.language,
    name: t.metadata?.trackName,
    trackNumber: t.metadata?.trackNumber,
    bytes: Buffer.from(t.output?.subtitle || []),
  })).filter(t => t.bytes.length);
}

module.exports = { extractMkvTracks };

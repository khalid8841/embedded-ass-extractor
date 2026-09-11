const MAX_HEADER_BYTES = 16 * 1024 * 1024;
const INITIAL_RANGE = 1024 * 1024;
const MAX_GROUP_BYTES = 4 * 1024 * 1024;
const MAX_SAMPLES = 50000;

function u32(b, o) { return b.readUInt32BE(o); }
function u64(b, o) { return Number(b.readBigUInt64BE(o)); }
function boxHeader(buf, off) {
  if (off + 8 > buf.length) return null;
  let size = u32(buf, off);
  const type = buf.toString('ascii', off + 4, off + 8);
  let header = 8;
  if (size === 1) {
    if (off + 16 > buf.length) return null;
    size = u64(buf, off + 8);
    header = 16;
  } else if (size === 0) {
    size = buf.length - off;
  }
  if (size < header || off + size > buf.length) return null;
  return { size, type, header, start: off, dataStart: off + header, end: off + size };
}

function children(buf, start, end) {
  const out = [];
  let p = start;
  while (p + 8 <= end) {
    const h = boxHeader(buf, p);
    if (!h || h.end > end) break;
    out.push(h);
    p = h.end;
  }
  return out;
}

function findChild(buf, parent, path) {
  let nodes = [parent];
  for (const type of path) {
    const next = [];
    for (const n of nodes) next.push(...children(buf, n.dataStart, n.end).filter(x => x.type === type));
    nodes = next;
    if (!nodes.length) return null;
  }
  return nodes[0] || null;
}

function findChildren(buf, parent, type) {
  return children(buf, parent.dataStart, parent.end).filter(x => x.type === type);
}

function parseMdhd(buf, box) {
  const version = buf[box.dataStart];
  let p = box.dataStart + 4;
  if (version === 1) p += 8 + 8;
  else p += 4 + 4;
  if (p + 8 > box.end) return { timescale: 1000, language: undefined };
  const timescale = u32(buf, p); p += 4;
  p += version === 1 ? 8 : 4;
  if (p + 2 > box.end) return { timescale: timescale || 1000, language: undefined };
  const langWord = buf.readUInt16BE(p);
  return { timescale: timescale || 1000, language: decodeQtLanguage(langWord) };
}

function decodeQtLanguage(v) {
  if (!v) return undefined;
  const a = ((v >> 10) & 0x1f) + 0x60;
  const b = ((v >> 5) & 0x1f) + 0x60;
  const c = (v & 0x1f) + 0x60;
  const s = String.fromCharCode(a, b, c);
  return /^[a-z]{3}$/.test(s) ? s : undefined;
}

function parseHandler(buf, box) {
  if (box.end < box.dataStart + 12) return undefined;
  return buf.toString('ascii', box.dataStart + 8, box.dataStart + 12);
}

function parseStts(buf, box) {
  const p = box.dataStart + 4;
  if (p + 4 > box.end) return [];
  const count = Math.min(u32(buf, p), MAX_SAMPLES);
  let q = p + 4;
  const out = [];
  for (let i = 0; i < count && q + 8 <= box.end; i++) {
    out.push({ sampleCount: u32(buf, q), delta: u32(buf, q + 4) }); q += 8;
  }
  return out;
}

function parseStsc(buf, box) {
  const p = box.dataStart + 4;
  if (p + 4 > box.end) return [];
  const count = Math.min(u32(buf, p), MAX_SAMPLES);
  let q = p + 4;
  const out = [];
  for (let i = 0; i < count && q + 12 <= box.end; i++) {
    out.push({ firstChunk: u32(buf, q), samplesPerChunk: u32(buf, q + 4), sampleDescriptionIndex: u32(buf, q + 8) }); q += 12;
  }
  return out;
}

function parseStsz(buf, box) {
  const p = box.dataStart + 4;
  if (p + 8 > box.end) return { sampleSize: 0, sizes: [] };
  const sampleSize = u32(buf, p);
  const count = Math.min(u32(buf, p + 4), MAX_SAMPLES);
  let q = p + 8;
  if (sampleSize) return { sampleSize, sizes: new Array(count).fill(sampleSize) };
  const sizes = [];
  for (let i = 0; i < count && q + 4 <= box.end; i++) { sizes.push(u32(buf, q)); q += 4; }
  return { sampleSize: 0, sizes };
}

function parseOffsets(buf, box, co64) {
  const p = box.dataStart + 4;
  if (p + 4 > box.end) return [];
  const count = Math.min(u32(buf, p), MAX_SAMPLES);
  let q = p + 4;
  const out = [];
  const stride = co64 ? 8 : 4;
  for (let i = 0; i < count && q + stride <= box.end; i++) {
    out.push(co64 ? u64(buf, q) : u32(buf, q)); q += stride;
  }
  return out;
}

function parseStsd(buf, box) {
  const p = box.dataStart + 4;
  if (p + 4 > box.end) return [];
  const count = Math.min(u32(buf, p), 32);
  let q = p + 4;
  const entries = [];
  for (let i = 0; i < count && q + 8 <= box.end; i++) {
    const size = u32(buf, q);
    const type = buf.toString('ascii', q + 4, q + 8);
    if (size < 8 || q + size > box.end) break;
    entries.push({ type, size, start: q, end: q + size }); q += size;
  }
  return entries;
}

function findTextInBox(buf, box) {
  for (const c of children(buf, box.dataStart, box.end)) {
    if (c.type === '©nam' || c.type === 'name') {
      const data = findChild(buf, c, ['data']);
      if (data && data.end > data.dataStart + 8) return buf.toString('utf8', data.dataStart + 8, data.end).replace(/\0/g, '').trim();
    }
    const nested = findTextInBox(buf, c);
    if (nested) return nested;
  }
  return '';
}

function buildSampleTimes(stts, count, timescale) {
  const out = new Array(count);
  let idx = 0, decode = 0;
  for (const run of stts) {
    for (let i = 0; i < run.sampleCount && idx < count; i++) {
      out[idx++] = { start: decode, duration: run.delta };
      decode += run.delta;
    }
  }
  while (idx < count) { out[idx++] = { start: decode, duration: 1 }; decode += 1; }
  return out.map(x => ({ startMs: Math.round(x.start * 1000 / timescale), durationMs: Math.max(1, Math.round(x.duration * 1000 / timescale)) }));
}

function buildSampleLocations(stsc, offsets, sizes) {
  if (!stsc.length || !offsets.length || !sizes.length) return [];
  const samples = [];
  let sampleIndex = 0;
  for (let chunkIdx = 1; chunkIdx <= offsets.length && sampleIndex < sizes.length; chunkIdx++) {
    let entry = stsc[0];
    for (let i = stsc.length - 1; i >= 0; i--) {
      if (chunkIdx >= stsc[i].firstChunk) { entry = stsc[i]; break; }
    }
    let pos = offsets[chunkIdx - 1];
    for (let s = 0; s < entry.samplesPerChunk && sampleIndex < sizes.length && samples.length < MAX_SAMPLES; s++) {
      const size = sizes[sampleIndex];
      samples.push({ index: sampleIndex, offset: pos, size });
      pos += size; sampleIndex++;
    }
  }
  return samples;
}

function parseMoov(buffer) {
  const top = children(buffer, 0, buffer.length);
  const moov = top.find(x => x.type === 'moov');
  if (!moov) return { tracks: [] };
  const tracks = [];
  for (const trak of findChildren(buffer, moov, 'trak')) {
    const mdia = findChild(buffer, trak, ['mdia']);
    if (!mdia) continue;
    const hdlr = findChild(buffer, mdia, ['hdlr']);
    const handler = hdlr ? parseHandler(buffer, hdlr) : undefined;
    if (!['text', 'sbtl', 'subt'].includes(handler)) continue;
    const mdhd = findChild(buffer, mdia, ['mdhd']);
    const stbl = findChild(buffer, mdia, ['minf', 'stbl']);
    if (!stbl || !mdhd) continue;
    const stsd = findChild(buffer, stbl, ['stsd']);
    const stts = findChild(buffer, stbl, ['stts']);
    const stsc = findChild(buffer, stbl, ['stsc']);
    const stsz = findChild(buffer, stbl, ['stsz']);
    const stco = findChild(buffer, stbl, ['stco']);
    const co64 = findChild(buffer, stbl, ['co64']);
    if (!stsd || !stts || !stsc || !stsz || (!stco && !co64)) continue;
    const entries = parseStsd(buffer, stsd);
    const entry = entries.find(e => ['tx3g', 'text', 'wvtt'].includes(e.type));
    if (!entry) continue;
    const meta = parseMdhd(buffer, mdhd);
    const sizes = parseStsz(buffer, stsz).sizes;
    const offsets = parseOffsets(buffer, stco || co64, !!co64);
    const chunkMap = parseStsc(buffer, stsc);
    const samples = buildSampleLocations(chunkMap, offsets, sizes);
    const times = buildSampleTimes(parseStts(buffer, stts), samples.length, meta.timescale);
    const udta = findChild(buffer, trak, ['udta']);
    const name = udta ? findTextInBox(buffer, udta) : '';
    tracks.push({ format: entry.type, language: meta.language, name, samples, times });
  }
  return { tracks };
}

function extractTextFromSample(buf, format) {
  if (!buf || !buf.length) return '';
  if (format === 'wvtt') {
    let p = 0, text = '';
    while (p + 8 <= buf.length) {
      const size = buf.readUInt32BE(p);
      const type = buf.toString('ascii', p + 4, p + 8);
      if (size < 8 || p + size > buf.length) break;
      if (type === 'vttc') text += extractTextFromSample(buf.slice(p + 8, p + size), 'wvtt') + ' ';
      else if (type === 'payl') text += innerText(buf.slice(p + 8, p + size));
      p += size;
    }
    return text.trim();
  }
  return innerText(buf);
}

function innerText(buf) {
  if (!buf || !buf.length) return '';
  if (buf.length >= 2) {
    const n = buf.readUInt16BE(0);
    if (n <= buf.length - 2) return buf.slice(2, 2 + n).toString('utf8').replace(/\0/g, '').trim();
  }
  return buf.toString('utf8').replace(/\0/g, '').trim();
}

function headerTotal(headers) {
  const cr = headers.get('content-range');
  if (cr) {
    const m = cr.match(/\/(\d+)$/);
    if (m) return Number(m[1]);
  }
  const cl = headers.get('content-length');
  return cl ? Number(cl) : undefined;
}

async function responseBuffer(res, maxBytes = MAX_HEADER_BYTES) {
  const len = Number(res.headers.get('content-length') || 0);
  if (len && len > maxBytes) throw new Error(`Range response too large (${len} bytes)`);
  const ab = await res.arrayBuffer();
  const b = Buffer.from(ab);
  if (b.length > maxBytes) throw new Error(`Range response too large (${b.length} bytes)`);
  return b;
}

async function fetchRange(safeFetch, url, start, end, cacheKey) {
  if (start < 0 || end < start) throw new Error('Invalid MP4 range');
  const requested = end - start + 1;
  if (requested > MAX_GROUP_BYTES && end !== start + requested - 1) throw new Error('MP4 range too large');
  const res = await safeFetch(url, {
    method: 'GET',
    headers: { Range: `bytes=${start}-${end}`, Accept: 'video/mp4,application/octet-stream,*/*' }
  }, cacheKey);
  if (!res.ok && res.status !== 206) throw new Error(`MP4 range HTTP ${res.status}`);
  const buf = await responseBuffer(res, Math.max(MAX_GROUP_BYTES + 1024, requested + 1024));
  const cr = res.headers.get('content-range');
  if (res.status === 206 && cr) {
    const m = cr.match(/^bytes\s+(\d+)-(\d+)\/(\d+|\*)$/i);
    if (m) {
      const actualStart = Number(m[1]);
      if (actualStart !== start) throw new Error(`Unexpected MP4 range start ${actualStart}, wanted ${start}`);
      return { buf, start: actualStart, end: Number(m[2]), total: m[3] === '*' ? undefined : Number(m[3]) };
    }
  }
  if (res.status === 200) {
    if (start !== 0) throw new Error('Upstream ignored Range for a non-zero MP4 range');
    return { buf, start: 0, end: buf.length - 1, total: headerTotal(res.headers) || buf.length };
  }
  return { buf, start, end: start + buf.length - 1, total: headerTotal(res.headers) };
}

function findPartialTopLevelMoov(buf) {
  let p = 0;
  while (p + 8 <= buf.length) {
    const size32 = u32(buf, p);
    const type = buf.toString('ascii', p + 4, p + 8);
    let size = size32;
    let header = 8;
    if (size32 === 1) {
      if (p + 16 > buf.length) return null;
      size = u64(buf, p + 8);
      header = 16;
    } else if (size32 === 0) {
      size = buf.length - p;
    }
    if (size < header) return null;
    if (type === 'moov') return { start: p, size, header, complete: p + size <= buf.length };
    if (p + size > buf.length) return null;
    p += size;
  }
  return null;
}

async function loadMoov(safeFetch, url, cacheKey) {
  const first = await fetchRange(safeFetch, url, 0, INITIAL_RANGE - 1, cacheKey);
  const partialMoov = findPartialTopLevelMoov(first.buf);
  if (partialMoov) {
    if (partialMoov.complete) return { parsed: parseMoov(first.buf), moovOffset: 0 };
    const exact = await fetchRange(safeFetch, url, partialMoov.start, partialMoov.start + partialMoov.size - 1, cacheKey);
    return { parsed: parseMoov(exact.buf), moovOffset: exact.start };
  }

  const total = first.total;
  if (total && total > first.buf.length) {
    const tailStart = Math.max(0, total - INITIAL_RANGE);
    const tail = await fetchRange(safeFetch, url, tailStart, total - 1, cacheKey);
    top = children(tail.buf, 0, tail.buf.length);
    moov = top.find(x => x.type === 'moov');
    if (moov) {
      const exact = moov.start === 0 && moov.end <= tail.buf.length
        ? { buf: tail.buf, start: tailStart }
        : await fetchRange(safeFetch, url, tailStart + moov.start, tailStart + moov.start + moov.size - 1, cacheKey);
      return { parsed: parseMoov(exact.buf), moovOffset: exact.start };
    }
  }
  throw new Error('MP4 moov box not found in initial or tail Range');
}

function groupRanges(samples) {
  if (!samples?.length) return [];
  const sorted = samples.slice().sort((a, b) => a.offset - b.offset);
  const groups = [];
  let cur = null;
  for (const s of sorted) {
    const sEnd = s.offset + s.size - 1;
    if (!cur || s.offset > cur.end + 1 || sEnd - cur.start + 1 > MAX_GROUP_BYTES) {
      cur = { start: s.offset, end: sEnd, samples: [s] };
      groups.push(cur);
    } else {
      cur.end = Math.max(cur.end, sEnd);
      cur.samples.push(s);
    }
  }
  return groups;
}

async function extractMp4Tracks(safeFetch, url, cacheKey) {
  const info = await loadMoov(safeFetch, url, cacheKey);
  const tracks = info.parsed.tracks;
  const out = [];
  for (let ti = 0; ti < tracks.length; ti++) {
    const t = tracks[ti];
    const groups = groupRanges(t.samples);
    const cues = [];
    for (const g of groups) {
      const r = await fetchRange(safeFetch, url, g.start, g.end, cacheKey);
      for (const sample of g.samples) {
        const rel = sample.offset - r.start;
        const raw = r.buf.slice(rel, rel + sample.size);
        const text = extractTextFromSample(raw, t.format);
        if (text) {
          const tm = t.times[sample.index] || { startMs: 0, durationMs: 2000 };
          cues.push({ time: tm.startMs, duration: tm.durationMs, text });
        }
      }
    }
    if (cues.length) out.push({ index: ti, type: t.format, language: t.language, name: t.name, cues });
  }
  return out;
}

async function extractMp4Arabic(safeFetch, url, cacheKey) {
  const tracks = await extractMp4Tracks(safeFetch, url, cacheKey);
  const candidates = tracks.filter(t => t.cues?.length);
  candidates.sort((a, b) => {
    const aLang = /^(ara|ar)$/i.test(a.language || '') ? 1000 : 0;
    const bLang = /^(ara|ar)$/i.test(b.language || '') ? 1000 : 0;
    const aName = /arabic|عرب/i.test(a.name || '') ? 200 : 0;
    const bName = /arabic|عرب/i.test(b.name || '') ? 200 : 0;
    return (bLang + bName) - (aLang + aName);
  });
  return candidates[0]?.cues || [];
}

module.exports = { extractMp4Tracks, extractMp4Arabic, parseMoov, loadMoov };

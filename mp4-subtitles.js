const MAX_HEADER_BYTES = 16 * 1024 * 1024;
const INITIAL_RANGE = 1024 * 1024;
const MAX_GROUP_BYTES = 4 * 1024 * 1024;
const MAX_SAMPLES = 50000;
const FRAGMENT_SCAN_CHUNK = 1024 * 1024;
const MAX_FRAGMENT_SCAN_BYTES = 512 * 1024 * 1024;

function u32(b, o) { return b.readUInt32BE(o); }
function i32(b, o) { return b.readInt32BE(o); }
function u64(b, o) { return Number(b.readBigUInt64BE(o)); }

function boxHeader(buf, off, allowPartial = false) {
  if (off + 8 > buf.length) return null;
  let size = u32(buf, off);
  const type = buf.toString('ascii', off + 4, off + 8);
  let header = 8;
  if (size === 1) {
    if (off + 16 > buf.length) return allowPartial ? { partial: true } : null;
    size = u64(buf, off + 8);
    header = 16;
  } else if (size === 0) {
    size = buf.length - off;
  }
  if (size < header) return null;
  if (off + size > buf.length) {
    if (allowPartial) return { partial: true, size, type, header, start: off, dataStart: off + header, end: off + size };
    return null;
  }
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

function parseTkhdId(buf, box) {
  if (!box) return undefined;
  const version = buf[box.dataStart];
  const p = box.dataStart + 4 + (version === 1 ? 16 : 8);
  return p + 4 <= box.end ? u32(buf, p) : undefined;
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
      if (data && data.end > data.dataStart + 8) {
        return buf.toString('utf8', data.dataStart + 8, data.end).replace(/\0/g, '').trim();
      }
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

const SUPPORTED_HANDLERS = new Set(['text', 'sbtl', 'subt']);
const SUPPORTED_SAMPLE_ENTRIES = new Set(['tx3g', 'text', 'wvtt', 'stpp', 'sbtt', 'stxt']);

function parseMoov(buffer) {
  const top = children(buffer, 0, buffer.length);
  const moov = top.find(x => x.type === 'moov');
  if (!moov) return { tracks: [], diagnostics: ['moov not found'] };

  const tracks = [];
  const diagnostics = [];
  let trakNo = 0;

  for (const trak of findChildren(buffer, moov, 'trak')) {
    trakNo++;
    const mdia = findChild(buffer, trak, ['mdia']);
    if (!mdia) { diagnostics.push(`trak#${trakNo}: missing mdia`); continue; }
    const hdlrBox = findChild(buffer, mdia, ['hdlr']);
    const handler = hdlrBox ? parseHandler(buffer, hdlrBox) : undefined;
    const tkhdId = parseTkhdId(buffer, findChild(buffer, trak, ['tkhd']));
    const mdhd = findChild(buffer, mdia, ['mdhd']);
    const stbl = findChild(buffer, mdia, ['minf', 'stbl']);
    const stsd = stbl ? findChild(buffer, stbl, ['stsd']) : null;
    const entries = stsd ? parseStsd(buffer, stsd) : [];
    const sampleTypes = entries.map(e => e.type);
    diagnostics.push(`trak#${trakNo} id=${tkhdId ?? '?'} handler=${handler || '?'} sampleEntries=${sampleTypes.join(',') || '(none)'}`);

    if (!SUPPORTED_HANDLERS.has(handler)) continue;
    if (!mdhd) { diagnostics.push(`trak#${trakNo}: subtitle handler but missing mdhd`); continue; }
    const meta = parseMdhd(buffer, mdhd);
    const udta = findChild(buffer, trak, ['udta']);
    const name = udta ? findTextInBox(buffer, udta) : '';
    const entry = entries.find(e => SUPPORTED_SAMPLE_ENTRIES.has(e.type));

    // Fragmented MP4 subtitle tracks commonly have a stsd entry but no classic
    // stts/stsc/stsz/stco tables. Keep the track so the fragment extractor can
    // populate samples from moof/traf/trun later.
    if (!entry) {
      diagnostics.push(`trak#${trakNo}: no supported text sample entry`);
      continue;
    }

    const stts = stbl ? findChild(buffer, stbl, ['stts']) : null;
    const stsc = stbl ? findChild(buffer, stbl, ['stsc']) : null;
    const stsz = stbl ? findChild(buffer, stbl, ['stsz']) : null;
    const stco = stbl ? findChild(buffer, stbl, ['stco']) : null;
    const co64 = stbl ? findChild(buffer, stbl, ['co64']) : null;

    let samples = [];
    let times = [];
    if (stts && stsc && stsz && (stco || co64)) {
      const sizes = parseStsz(buffer, stsz).sizes;
      const offsets = parseOffsets(buffer, stco || co64, !!co64);
      const chunkMap = parseStsc(buffer, stsc);
      samples = buildSampleLocations(chunkMap, offsets, sizes);
      times = buildSampleTimes(parseStts(buffer, stts), samples.length, meta.timescale);
    } else {
      diagnostics.push(`trak#${trakNo}: ${entry.type} appears fragmented (classic sample tables incomplete)`);
    }

    tracks.push({
      index: tracks.length,
      trackNumber: tkhdId ?? tracks.length + 1,
      trackId: tkhdId,
      format: entry.type,
      language: meta.language,
      name,
      timescale: meta.timescale,
      samples,
      times,
      fragmented: !samples.length
    });
  }

  return { tracks, diagnostics };
}

function decodeTextUtf8OrUtf16(buf) {
  if (!buf || !buf.length) return '';
  const b = Buffer.from(buf);
  let text;
  if (b.length >= 2 && b[0] === 0xfe && b[1] === 0xff) text = b.slice(2).toString('utf16le');
  else if (b.length >= 2 && b[0] === 0xff && b[1] === 0xfe) text = b.slice(2).toString('utf16le');
  else if (b.length >= 4 && b[1] === 0 && b[3] === 0) {
    // Heuristic for UTF-16BE payloads without a BOM: 00 xx 00 xx.
    const swapped = Buffer.allocUnsafe(b.length - (b.length % 2));
    for (let i = 0; i < swapped.length; i += 2) { swapped[i] = b[i + 1]; swapped[i + 1] = b[i]; }
    text = swapped.toString('utf16le');
  } else text = b.toString('utf8');
  return text.replace(/\u0000/g, '').trim();
}

function decodeXmlEntities(s) {
  return String(s || '').replace(/&(#x[0-9a-f]+|#[0-9]+|amp|lt|gt|quot|apos);/gi, (_, ent) => {
    const e = ent.toLowerCase();
    if (e === 'amp') return '&'; if (e === 'lt') return '<'; if (e === 'gt') return '>';
    if (e === 'quot') return '"'; if (e === 'apos') return "'";
    const n = e.startsWith('#x') ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
    return Number.isFinite(n) ? String.fromCodePoint(Math.min(n, 0x10ffff)) : _;
  });
}

function extractXmlText(s) {
  return decodeXmlEntities(String(s || '')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<p\b[^>]*>/gi, '')
    .replace(/<\/p>/gi, '\n')
    .replace(/<[^>]+>/g, ''))
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n[ \t]+/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function extractWebVttPayload(buf) {
  if (!buf || !buf.length) return '';
  let p = 0;
  const texts = [];
  let parsedAnyBox = false;
  while (p + 8 <= buf.length) {
    const size = buf.readUInt32BE(p);
    const type = buf.toString('ascii', p + 4, p + 8);
    if (size < 8 || p + size > buf.length) break;
    parsedAnyBox = true;
    if (type === 'vttc') {
      const inner = extractWebVttPayload(buf.slice(p + 8, p + size));
      if (inner) texts.push(inner);
    } else if (type === 'payl') {
      const text = decodeTextUtf8OrUtf16(buf.slice(p + 8, p + size));
      if (text) texts.push(text);
    }
    p += size;
  }
  if (parsedAnyBox) return texts.join('\n').trim();
  return decodeTextUtf8OrUtf16(buf);
}

function extractTextFromSample(buf, format) {
  if (!buf || !buf.length) return '';
  if (format === 'wvtt') return extractWebVttPayload(buf);
  if (format === 'stpp' || format === 'sbtt') return extractXmlText(decodeTextUtf8OrUtf16(buf));
  if (format === 'stxt') return decodeTextUtf8OrUtf16(buf);
  if (format === 'tx3g' || format === 'text') {
    if (buf.length >= 2) {
      const n = buf.readUInt16BE(0);
      if (n > 0 && n <= buf.length - 2) return decodeTextUtf8OrUtf16(buf.slice(2, 2 + n));
    }
    return decodeTextUtf8OrUtf16(buf);
  }
  return decodeTextUtf8OrUtf16(buf);
}

function innerText(buf) {
  return decodeTextUtf8OrUtf16(buf);
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
  if (requested > MAX_GROUP_BYTES) throw new Error(`MP4 range too large (${requested} bytes)`);
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
    const h = boxHeader(buf, p, true);
    if (!h) return null;
    if (h.partial) return h.type === 'moov' ? h : null;
    if (h.type === 'moov') return { start: p, size: h.size, header: h.header, complete: p + h.size <= buf.length };
    p += h.size;
  }
  return null;
}

async function loadMoov(safeFetch, url, cacheKey) {
  const first = await fetchRange(safeFetch, url, 0, INITIAL_RANGE - 1, cacheKey);
  const partialMoov = findPartialTopLevelMoov(first.buf);
  if (partialMoov) {
    if (partialMoov.complete) return { parsed: parseMoov(first.buf), moovOffset: 0, total: first.total };
    const exact = await fetchRange(safeFetch, url, partialMoov.start, partialMoov.start + partialMoov.size - 1, cacheKey);
    return { parsed: parseMoov(exact.buf), moovOffset: exact.start, total: exact.total || first.total };
  }

  const total = first.total;
  if (total && total > first.buf.length) {
    const tailStart = Math.max(0, total - INITIAL_RANGE);
    const tail = await fetchRange(safeFetch, url, tailStart, total - 1, cacheKey);
    const top = children(tail.buf, 0, tail.buf.length);
    const moov = top.find(x => x.type === 'moov');
    if (moov) {
      const exact = moov.start === 0 && moov.end <= tail.buf.length
        ? { buf: tail.buf, start: tailStart }
        : await fetchRange(safeFetch, url, tailStart + moov.start, tailStart + moov.start + moov.size - 1, cacheKey);
      return { parsed: parseMoov(exact.buf), moovOffset: exact.start, total: total };
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
    if (!Number.isFinite(s.offset) || !Number.isFinite(s.size) || s.size <= 0) continue;
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

function parseTfhd(buf, box) {
  const flags = buf.readUIntBE(box.dataStart + 1, 3);
  let p = box.dataStart + 4;
  const trackId = u32(buf, p); p += 4;
  let baseDataOffset;
  let defaultSampleDuration;
  let defaultSampleSize;
  if (flags & 0x000001) { baseDataOffset = u64(buf, p); p += 8; }
  if (flags & 0x000002) p += 4; // sample_description_index
  if (flags & 0x000008) { defaultSampleDuration = u32(buf, p); p += 4; }
  if (flags & 0x000010) { defaultSampleSize = u32(buf, p); p += 4; }
  if (flags & 0x000020) p += 4; // default sample flags
  return { flags, trackId, baseDataOffset, defaultSampleDuration, defaultSampleSize, defaultBaseIsMoof: !!(flags & 0x020000) };
}

function parseTfdt(buf, box) {
  const version = buf[box.dataStart];
  const p = box.dataStart + 4;
  if (version === 1) return p + 8 <= box.end ? u64(buf, p) : 0;
  return p + 4 <= box.end ? u32(buf, p) : 0;
}

function parseTrun(buf, box) {
  const flags = buf.readUIntBE(box.dataStart + 1, 3);
  let p = box.dataStart + 4;
  if (p + 4 > box.end) return null;
  const count = Math.min(u32(buf, p), MAX_SAMPLES); p += 4;
  let dataOffset;
  let firstSampleFlags;
  if (flags & 0x000001) { if (p + 4 > box.end) return null; dataOffset = i32(buf, p); p += 4; }
  if (flags & 0x000004) { if (p + 4 > box.end) return null; firstSampleFlags = u32(buf, p); p += 4; }
  const samples = [];
  for (let i = 0; i < count; i++) {
    let duration, size;
    if (flags & 0x000100) { if (p + 4 > box.end) return null; duration = u32(buf, p); p += 4; }
    if (flags & 0x000200) { if (p + 4 > box.end) return null; size = u32(buf, p); p += 4; }
    if (flags & 0x000400) { if (p + 4 > box.end) return null; p += 4; }
    if (flags & 0x000800) { if (p + 4 > box.end) p = box.end; else p += 4; }
    samples.push({ duration, size });
    if (p > box.end) return null;
  }
  return { flags, count, dataOffset, firstSampleFlags, samples };
}

function parseFragmentSamples(moofBuf, moofStart, track) {
  const moof = children(moofBuf, 0, moofBuf.length).find(x => x.type === 'moof');
  if (!moof) return [];
  const out = [];
  for (const traf of findChildren(moofBuf, moof, 'traf')) {
    const tfhdBox = findChild(moofBuf, traf, ['tfhd']);
    if (!tfhdBox) continue;
    let tfhd;
    try { tfhd = parseTfhd(moofBuf, tfhdBox); } catch (_) { continue; }
    if (tfhd.trackId !== track.trackId) continue;
    const tfdtBox = findChild(moofBuf, traf, ['tfdt']);
    let decode = tfdtBox ? parseTfdt(moofBuf, tfdtBox) : 0;
    let runningOffset;
    for (const trunBox of findChildren(moofBuf, traf, 'trun')) {
      const trun = parseTrun(moofBuf, trunBox);
      if (!trun) continue;
      if (trun.dataOffset != null) {
        const base = tfhd.baseDataOffset != null ? tfhd.baseDataOffset : moofStart;
        runningOffset = base + trun.dataOffset;
      } else if (runningOffset == null) {
        if (tfhd.baseDataOffset != null) runningOffset = tfhd.baseDataOffset;
        else runningOffset = moofStart + moof.size;
      }
      for (let i = 0; i < trun.samples.length && out.length < MAX_SAMPLES; i++) {
        const s = trun.samples[i];
        const size = s.size ?? tfhd.defaultSampleSize;
        const duration = s.duration ?? tfhd.defaultSampleDuration ?? 1;
        if (!Number.isFinite(size) || size <= 0 || !Number.isFinite(runningOffset)) {
          decode += duration;
          continue;
        }
        out.push({ index: out.length, offset: runningOffset, size, timeUnits: decode, durationUnits: duration });
        runningOffset += size;
        decode += duration;
      }
    }
  }
  return out;
}

async function readTopLevelHeader(safeFetch, url, offset, total, cacheKey) {
  const end = Math.min(total - 1, offset + 31);
  const r = await fetchRange(safeFetch, url, offset, end, cacheKey);
  const h = boxHeader(r.buf, 0, true);
  if (!h) return null;
  return { ...h, absoluteStart: offset };
}

async function extractFragmentedMp4Tracks(safeFetch, url, cacheKey, total, tracks) {
  if (!total || !tracks.some(t => t.fragmented && t.trackId != null)) return tracks;
  const byId = new Map(tracks.filter(t => t.trackId != null).map(t => [t.trackId, t]));
  let offset = 0;
  let scanned = 0;
  let sawMoof = false;

  while (offset + 8 <= total && scanned < MAX_FRAGMENT_SCAN_BYTES) {
    const h = await readTopLevelHeader(safeFetch, url, offset, total, cacheKey);
    if (!h) break;
    if (h.type === 'moof') {
      sawMoof = true;
      const moofRange = await fetchRange(safeFetch, url, offset, offset + h.size - 1, cacheKey);
      const fragTracks = tracks.filter(t => t.trackId != null && t.fragmented);
      for (const t of fragTracks) {
        const fragSamples = parseFragmentSamples(moofRange.buf, offset, t);
        for (const s of fragSamples) {
          s.index = t.samples.length;
          t.samples.push(s);
          t.times.push({ startMs: Math.round(s.timeUnits * 1000 / t.timescale), durationMs: Math.max(1, Math.round(s.durationUnits * 1000 / t.timescale)) });
        }
      }
    }
    offset += h.size;
    scanned = offset;
    if (offset > total) break;
    // Avoid pathological zero/invalid boxes.
    if (h.size < h.header) break;
  }

  if (!sawMoof && tracks.some(t => t.fragmented)) {
    console.log(`[${cacheKey}] MP4 diagnostic: subtitle track metadata exists but no moof fragments were found during scan.`);
  }
  if (scanned >= MAX_FRAGMENT_SCAN_BYTES && total > MAX_FRAGMENT_SCAN_BYTES) {
    console.log(`[${cacheKey}] MP4 diagnostic: fragment scan capped at ${MAX_FRAGMENT_SCAN_BYTES} bytes.`);
  }
  return tracks;
}

async function extractMp4Tracks(safeFetch, url, cacheKey) {
  const info = await loadMoov(safeFetch, url, cacheKey);
  const diagnostics = info.parsed.diagnostics || [];
  if (diagnostics.length) console.log(`[${cacheKey}] MP4 track probe: ${diagnostics.join(' || ')}`);

  let tracks = info.parsed.tracks;
  tracks = await extractFragmentedMp4Tracks(safeFetch, url, cacheKey, info.total, tracks);

  const out = [];
  for (let ti = 0; ti < tracks.length; ti++) {
    const t = tracks[ti];
    const groups = groupRanges(t.samples);
    const cues = [];
    for (const g of groups) {
      const r = await fetchRange(safeFetch, url, g.start, g.end, cacheKey);
      for (const sample of g.samples) {
        const rel = sample.offset - r.start;
        if (rel < 0 || rel + sample.size > r.buf.length) continue;
        const raw = r.buf.slice(rel, rel + sample.size);
        const text = extractTextFromSample(raw, t.format);
        if (text) {
          const tm = t.times[sample.index] || { startMs: 0, durationMs: 2000 };
          cues.push({ time: tm.startMs, duration: tm.durationMs, text });
        }
      }
    }
    if (cues.length) {
      out.push({ index: ti, trackNumber: t.trackNumber, trackId: t.trackId, type: t.format, language: t.language, name: t.name, cues });
    }
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

module.exports = { extractMp4Tracks, extractMp4Arabic, parseMoov, loadMoov, extractTextFromSample };

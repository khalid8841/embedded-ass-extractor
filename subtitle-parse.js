// Converts raw subtitle-track bytes (as extracted from an MKV) into the
// { time, duration, text } cue objects the rest of the pipeline uses.
//
// WHY THIS FILE EXISTS (this was a real bug in v20):
// mkv-range.js returned tracks shaped { ..., bytes: <Buffer> }, but
// server.js's chooseTrack() filters on `t.cues && t.cues.length`. Nothing
// ever converted bytes -> cues, so the MKV path could NEVER select a track,
// even when detection and extraction both worked perfectly. The MP4 path
// (mp4-subtitles.js) already produced `cues`, which is why only that path
// could ever succeed. This module closes that gap.

// ASS/SSA timestamps look like H:MM:SS.cc (centiseconds).
function assTimeToMs(str) {
  const m = /^\s*(\d+):(\d{2}):(\d{2})[.,](\d{1,3})\s*$/.exec(str || '');
  if (!m) return null;
  const [, h, min, s, frac] = m;
  const centis = frac.length === 2 ? Number(frac) * 10 : frac.length === 1 ? Number(frac) * 100 : Number(frac);
  return Number(h) * 3600000 + Number(min) * 60000 + Number(s) * 1000 + centis;
}

// SRT timestamps look like HH:MM:SS,mmm (milliseconds).
function srtTimeToMs(str) {
  const m = /^\s*(\d+):(\d{2}):(\d{2})[.,](\d{1,3})\s*$/.exec(str || '');
  if (!m) return null;
  const [, h, min, s, frac] = m;
  const ms = frac.padEnd(3, '0');
  return Number(h) * 3600000 + Number(min) * 60000 + Number(s) * 1000 + Number(ms);
}

// Parses a full ASS/SSA script body. Handles the [Events] section's Format:
// line so we read the Start/End/Text columns by NAME rather than by fixed
// position — different muxers order these columns differently, and Text is
// always last (it may itself contain commas, so we only split up to the
// column count and keep the remainder as the text).
function parseAss(text) {
  const lines = text.split(/\r?\n/);
  const cues = [];
  let format = null;

  for (const line of lines) {
    const fmtMatch = /^\s*Format\s*:\s*(.+)$/i.exec(line);
    if (fmtMatch) {
      format = fmtMatch[1].split(',').map(s => s.trim().toLowerCase());
      continue;
    }
    const evMatch = /^\s*Dialogue\s*:\s*(.+)$/i.exec(line);
    if (!evMatch) continue;

    // Default ASS column order, used when no Format: line was seen.
    const cols = format || ['layer', 'start', 'end', 'style', 'name', 'marginl', 'marginr', 'marginv', 'effect', 'text'];
    const textIdx = cols.indexOf('text');
    const startIdx = cols.indexOf('start');
    const endIdx = cols.indexOf('end');
    if (startIdx === -1 || endIdx === -1 || textIdx === -1) continue;

    // Split only up to the number of fields before Text; everything after
    // that belongs to Text (which legitimately contains commas).
    const parts = evMatch[1].split(',');
    const head = parts.slice(0, textIdx);
    const body = parts.slice(textIdx).join(',');
    if (head.length < textIdx) continue;

    const start = assTimeToMs(head[startIdx]);
    const end = assTimeToMs(head[endIdx]);
    if (start === null || end === null) continue;

    cues.push({ time: start, duration: Math.max(0, end - start), text: body });
  }
  return cues;
}

// Parses SubRip (SRT) text.
function parseSrt(text) {
  const cues = [];
  const blocks = text.replace(/\r\n/g, '\n').split(/\n\s*\n/);
  for (const block of blocks) {
    const lines = block.split('\n').filter(l => l.trim() !== '');
    if (!lines.length) continue;
    const timeLineIdx = lines.findIndex(l => /-->/.test(l));
    if (timeLineIdx === -1) continue;
    const [rawStart, rawEnd] = lines[timeLineIdx].split('-->');
    const start = srtTimeToMs(rawStart);
    const end = srtTimeToMs(rawEnd);
    if (start === null || end === null) continue;
    const text_ = lines.slice(timeLineIdx + 1).join('\n');
    if (!text_.trim()) continue;
    cues.push({ time: start, duration: Math.max(0, end - start), text: text_ });
  }
  return cues;
}

// Main entry point: takes raw bytes plus the codec/type string reported by
// the MKV extractor, and returns cues. Falls back to sniffing the content
// itself when the declared type is missing or unrecognized, because muxers
// label these inconsistently (S_TEXT/ASS, ass, ssa, S_TEXT/UTF8, subrip...).
function parseSubtitleBytes(bytes, declaredType) {
  if (!bytes || !bytes.length) return [];
  const text = Buffer.from(bytes).toString('utf8');
  const type = String(declaredType || '').toLowerCase();

  const looksAss = /ass|ssa/.test(type) || /^\s*\[/m.test(text) || /^\s*Dialogue\s*:/mi.test(text);
  const looksSrt = /srt|subrip|utf8|utf-8/.test(type) || /-->/.test(text);

  // Prefer whichever actually yields cues — a mislabeled track is common.
  if (looksAss) {
    const cues = parseAss(text);
    if (cues.length) return cues;
  }
  if (looksSrt) {
    const cues = parseSrt(text);
    if (cues.length) return cues;
  }
  // Last resort: try both regardless of what the labels claimed.
  const assCues = parseAss(text);
  if (assCues.length) return assCues;
  return parseSrt(text);
}

module.exports = { parseSubtitleBytes, parseAss, parseSrt, assTimeToMs, srtTimeToMs };

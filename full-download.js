// Fallback path for servers that genuinely do not honour HTTP Range.
//
// This streams the remote file to a temporary file ON DISK — never into a
// Buffer — so memory use stays flat regardless of file size, then hands the
// local path to the extractor and deletes the temp file afterwards.
//
// This is deliberately the LAST resort: it is slow and burns bandwidth, so
// resolve-url.js is always tried first, and this only runs when Range has
// been proven not to work against the FINAL (post-redirect) URL.

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { pipeline } = require('stream/promises');

// Refuse to pull down anything larger than this. Render's free tier has
// limited disk and a request timeout; a multi-GB pull would fail anyway, and
// failing fast with a clear log line is more useful than hanging.
const DEFAULT_MAX_DOWNLOAD_BYTES = 2 * 1024 * 1024 * 1024; // 2 GB

function tempPathFor(suffix = '.bin') {
  return path.join(os.tmpdir(), `eas-${crypto.randomBytes(8).toString('hex')}${suffix}`);
}

// Downloads `url` to a temp file, invokes `work(localPath)`, then always
// deletes the temp file. Returns whatever `work` returned.
async function withDownloadedFile(url, safeFetch, cacheKey, log, options, work) {
  const maxBytes = (options && options.maxBytes) || DEFAULT_MAX_DOWNLOAD_BYTES;
  const knownSize = options && options.knownSize;
  const suffix = (options && options.suffix) || '.bin';

  if (knownSize && knownSize > maxBytes) {
    throw new Error(
      `Refusing full download: file is ${(knownSize / 1024 / 1024).toFixed(0)}MB which exceeds the ${(maxBytes / 1024 / 1024).toFixed(0)}MB safety limit`
    );
  }

  const tmp = tempPathFor(suffix);
  log(cacheKey, `FULL-DOWNLOAD fallback starting (Range unsupported on final URL). Streaming to disk, cap ${(maxBytes / 1024 / 1024).toFixed(0)}MB.`);

  const controller = new AbortController();
  let downloaded = 0;

  try {
    const res = await safeFetch(url, { signal: controller.signal }, cacheKey);
    if (!res.ok || !res.body) {
      throw new Error(`Full download failed: HTTP ${res.status}`);
    }

    // Enforce the cap as bytes arrive, so an unknown-length response can't
    // quietly fill the disk.
    res.body.on('data', chunk => {
      downloaded += chunk.length;
      if (downloaded > maxBytes) {
        controller.abort();
      }
    });

    await pipeline(res.body, fs.createWriteStream(tmp));

    if (downloaded > maxBytes) {
      throw new Error(`Aborted full download after exceeding the ${(maxBytes / 1024 / 1024).toFixed(0)}MB safety limit`);
    }

    log(cacheKey, `FULL-DOWNLOAD complete: ${(downloaded / 1024 / 1024).toFixed(1)}MB written to a temp file.`);
    return await work(tmp);
  } finally {
    // Awaited, not fire-and-forget: the caller must be able to rely on the
    // temp file being gone once this function returns (a test caught this —
    // an un-awaited unlink left the file on disk past return).
    try {
      await fs.promises.unlink(tmp);
    } catch (_) {
      /* already gone, or never created */
    }
    log(cacheKey, 'FULL-DOWNLOAD temp file removed.');
  }
}

module.exports = { withDownloadedFile, DEFAULT_MAX_DOWNLOAD_BYTES };

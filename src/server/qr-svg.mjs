/**
 * Wiretok — Pure Zero-Dependency ISO/IEC 18004 QR Code Generator (Byte Mode, ECC Level L, Versions 1–6)
 * Emits crisp inline SVG (<svg viewBox="...">) for PIN-protected LAN pairing QR codes.
 */

const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) {
    GF_EXP[i] = GF_EXP[i - 255];
  }
}

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

function rsGeneratorPoly(deg) {
  let gen = [1];
  for (let i = 0; i < deg; i++) {
    const next = new Array(gen.length + 1).fill(0);
    for (let j = 0; j < gen.length; j++) {
      next[j] ^= gen[j];
      next[j + 1] ^= gfMul(gen[j], GF_EXP[i]);
    }
    gen = next;
  }
  return gen;
}

function rsRemainder(data, eccLen) {
  const gen = rsGeneratorPoly(eccLen);
  const rem = new Array(eccLen).fill(0);
  for (let i = 0; i < data.length; i++) {
    const factor = data[i] ^ rem[0];
    rem.shift();
    rem.push(0);
    if (factor !== 0) {
      for (let j = 0; j < eccLen; j++) {
        rem[j] ^= gfMul(gen[j + 1], factor);
      }
    }
  }
  return rem;
}

// ISO/IEC 18004 ECC Level L parameters for Versions 1–6 (8-bit byte count indicator)
const VERSIONS_L = [
  { version: 1, size: 21, maxBytes: 17, blocks: [[1, 19, 7]], align: [] },
  { version: 2, size: 25, maxBytes: 32, blocks: [[1, 34, 10]], align: [6, 18] },
  { version: 3, size: 29, maxBytes: 53, blocks: [[1, 55, 15]], align: [6, 22] },
  { version: 4, size: 33, maxBytes: 78, blocks: [[1, 80, 20]], align: [6, 26] },
  { version: 5, size: 37, maxBytes: 106, blocks: [[1, 108, 26]], align: [6, 30] },
  { version: 6, size: 41, maxBytes: 134, blocks: [[2, 68, 18]], align: [6, 34] },
];

function encodeCodewords(bytes, spec) {
  const totalDataCw = spec.blocks.reduce((sum, [cnt, dc]) => sum + cnt * dc, 0);
  const totalBits = totalDataCw * 8;
  const bits = [];

  const pushBits = (val, len) => {
    for (let i = len - 1; i >= 0; i--) {
      bits.push((val >> i) & 1);
    }
  };

  // Byte mode indicator (0100) + 8-bit character count
  pushBits(0b0100, 4);
  pushBits(bytes.length, 8);
  for (let i = 0; i < bytes.length; i++) {
    pushBits(bytes[i], 8);
  }

  // Terminator (up to 4 zero bits)
  const termLen = Math.min(4, totalBits - bits.length);
  for (let i = 0; i < termLen; i++) bits.push(0);

  // Pad to byte boundary
  while (bits.length % 8 !== 0) bits.push(0);

  const dataCw = [];
  for (let i = 0; i < bits.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
    dataCw.push(b);
  }

  const PAD = [0xec, 0x11];
  let padIdx = 0;
  while (dataCw.length < totalDataCw) {
    dataCw.push(PAD[padIdx % 2]);
    padIdx += 1;
  }

  // Split into RS blocks & interleave data + ECC codewords
  const dataBlocks = [];
  const eccBlocks = [];
  let offset = 0;
  for (const [count, dc, ec] of spec.blocks) {
    for (let b = 0; b < count; b++) {
      const slice = dataCw.slice(offset, offset + dc);
      offset += dc;
      dataBlocks.push(slice);
      eccBlocks.push(rsRemainder(slice, ec));
    }
  }

  const out = [];
  const maxDataLen = Math.max(...dataBlocks.map((b) => b.length));
  for (let i = 0; i < maxDataLen; i++) {
    for (const blk of dataBlocks) {
      if (i < blk.length) out.push(blk[i]);
    }
  }
  const maxEccLen = Math.max(...eccBlocks.map((b) => b.length));
  for (let i = 0; i < maxEccLen; i++) {
    for (const blk of eccBlocks) {
      if (i < blk.length) out.push(blk[i]);
    }
  }
  return out;
}

function createMatrix(size) {
  const mod = Array.from({ length: size }, () => new Uint8Array(size));
  const fn = Array.from({ length: size }, () => new Uint8Array(size));
  return { size, mod, fn };
}

function setFunc(m, r, c, dark) {
  if (r < 0 || c < 0 || r >= m.size || c >= m.size) return;
  m.mod[r][c] = dark ? 1 : 0;
  m.fn[r][c] = 1;
}

function drawFinder(m, top, left) {
  for (let dr = -1; dr <= 7; dr++) {
    for (let dc = -1; dc <= 7; dc++) {
      const r = top + dr;
      const c = left + dc;
      if (r < 0 || c < 0 || r >= m.size || c >= m.size) continue;
      const inOuter = dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6;
      const onBorder = dr === 0 || dr === 6 || dc === 0 || dc === 6;
      const inCenter = dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4;
      setFunc(m, r, c, inOuter && (onBorder || inCenter));
    }
  }
}

function drawAlignment(m, centerR, centerC) {
  for (let dr = -2; dr <= 2; dr++) {
    for (let dc = -2; dc <= 2; dc++) {
      const dist = Math.max(Math.abs(dr), Math.abs(dc));
      setFunc(m, centerR + dr, centerC + dc, dist === 2 || dist === 0);
    }
  }
}

function populateFunctionPatterns(m, spec) {
  const s = m.size;
  drawFinder(m, 0, 0);
  drawFinder(m, 0, s - 7);
  drawFinder(m, s - 7, 0);

  // Alignment patterns (skip corners overlapping finder patterns)
  for (const r of spec.align) {
    for (const c of spec.align) {
      if (m.fn[r][c]) continue;
      drawAlignment(m, r, c);
    }
  }

  // Timing patterns
  for (let i = 8; i < s - 8; i++) {
    const dark = i % 2 === 0;
    if (!m.fn[6][i]) setFunc(m, 6, i, dark);
    if (!m.fn[i][6]) setFunc(m, i, 6, dark);
  }

  // Dark module
  setFunc(m, s - 8, 8, true);

  // Reserve format info cells (values filled per mask)
  for (let i = 0; i < 9; i++) {
    if (!m.fn[8][i]) setFunc(m, 8, i, false);
    if (!m.fn[i][8]) setFunc(m, i, 8, false);
  }
  for (let i = 0; i < 8; i++) {
    if (!m.fn[8][s - 1 - i]) setFunc(m, 8, s - 1 - i, false);
    if (i < 7 && !m.fn[s - 1 - i][8]) setFunc(m, s - 1 - i, 8, false);
  }
}

function placeDataBits(m, codewords) {
  const s = m.size;
  const totalBits = codewords.length * 8;
  let bitIdx = 0;
  let dir = -1; // start moving upward

  for (let col = s - 1; col >= 1; col -= 2) {
    if (col === 6) col -= 1; // skip vertical timing column
    for (let step = 0; step < s; step++) {
      const r = dir === -1 ? s - 1 - step : step;
      for (let dx = 0; dx < 2; dx++) {
        const c = col - dx;
        if (m.fn[r][c]) continue;
        let bit = 0;
        if (bitIdx < totalBits) {
          const byte = codewords[bitIdx >> 3];
          bit = (byte >> (7 - (bitIdx & 7))) & 1;
          bitIdx += 1;
        }
        m.mod[r][c] = bit;
      }
    }
    dir = -dir;
  }
}

function maskBit(maskId, r, c) {
  switch (maskId) {
    case 0: return (r + c) % 2 === 0;
    case 1: return r % 2 === 0;
    case 2: return c % 3 === 0;
    case 3: return (r + c) % 3 === 0;
    case 4: return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
    case 5: return ((r * c) % 2) + ((r * c) % 3) === 0;
    case 6: return (((r * c) % 2) + ((r * c) % 3)) % 2 === 0;
    case 7: return (((r + c) % 2) + ((r * c) % 3)) % 2 === 0;
    default: return false;
  }
}

function computeFormatBits(maskId) {
  // ECC Level L = 01
  const data = (0b01 << 3) | (maskId & 0x7);
  let rem = data << 10;
  for (let i = 14; i >= 10; i--) {
    if ((rem >> i) & 1) rem ^= 0x537 << (i - 10);
  }
  return ((data << 10) | rem) ^ 0x5412;
}

function writeFormatInfo(mod, size, maskId) {
  const fmt = computeFormatBits(maskId);
  const bit = (k) => (fmt >> k) & 1;

  // First copy
  for (let c = 0; c <= 5; c++) mod[8][c] = bit(14 - c);
  mod[8][7] = bit(8);
  mod[8][8] = bit(7);
  mod[7][8] = bit(6);
  for (let r = 5; r >= 0; r--) mod[r][8] = bit(r);

  // Second copy
  for (let i = 0; i < 7; i++) mod[size - 1 - i][8] = bit(14 - i);
  for (let i = 0; i < 8; i++) mod[8][size - 8 + i] = bit(7 - i);
}

function penaltyScore(mod, size) {
  let score = 0;

  // N1: 5+ consecutive same-color modules in rows and columns
  for (let r = 0; r < size; r++) {
    let runColor = mod[r][0];
    let runLen = 1;
    for (let c = 1; c < size; c++) {
      if (mod[r][c] === runColor) {
        runLen += 1;
      } else {
        if (runLen >= 5) score += 3 + (runLen - 5);
        runColor = mod[r][c];
        runLen = 1;
      }
    }
    if (runLen >= 5) score += 3 + (runLen - 5);
  }

  for (let c = 0; c < size; c++) {
    let runColor = mod[0][c];
    let runLen = 1;
    for (let r = 1; r < size; r++) {
      if (mod[r][c] === runColor) {
        runLen += 1;
      } else {
        if (runLen >= 5) score += 3 + (runLen - 5);
        runColor = mod[r][c];
        runLen = 1;
      }
    }
    if (runLen >= 5) score += 3 + (runLen - 5);
  }

  // N2: 2x2 same-color blocks
  for (let r = 0; r < size - 1; r++) {
    for (let c = 0; c < size - 1; c++) {
      const v = mod[r][c];
      if (mod[r][c + 1] === v && mod[r + 1][c] === v && mod[r + 1][c + 1] === v) {
        score += 3;
      }
    }
  }

  // N3: finder-like 1:1:3:1:1 patterns with 4 light modules on either side
  const hasPattern = (arr) => {
    let cnt = 0;
    for (let i = 0; i <= arr.length - 11; i++) {
      const a =
        arr[i] === 1 &&
        arr[i + 1] === 0 &&
        arr[i + 2] === 1 &&
        arr[i + 3] === 1 &&
        arr[i + 4] === 1 &&
        arr[i + 5] === 0 &&
        arr[i + 6] === 1 &&
        arr[i + 7] === 0 &&
        arr[i + 8] === 0 &&
        arr[i + 9] === 0 &&
        arr[i + 10] === 0;
      const b =
        arr[i] === 0 &&
        arr[i + 1] === 0 &&
        arr[i + 2] === 0 &&
        arr[i + 3] === 0 &&
        arr[i + 4] === 1 &&
        arr[i + 5] === 0 &&
        arr[i + 6] === 1 &&
        arr[i + 7] === 1 &&
        arr[i + 8] === 1 &&
        arr[i + 9] === 0 &&
        arr[i + 10] === 1;
      if (a || b) cnt += 40;
    }
    return cnt;
  };

  const colBuf = new Uint8Array(size);
  for (let r = 0; r < size; r++) score += hasPattern(mod[r]);
  for (let c = 0; c < size; c++) {
    for (let r = 0; r < size; r++) colBuf[r] = mod[r][c];
    score += hasPattern(colBuf);
  }

  // N4: dark ratio balance around 50%
  let dark = 0;
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) dark += mod[r][c];
  }
  const pct = (dark * 100) / (size * size);
  const k = Math.floor(Math.abs(pct - 50) / 5);
  score += k * 10;

  return score;
}

/**
 * Encode UTF-8 string into an ECC-L QR matrix (Versions 1–6).
 * @param {string} text
 * @returns {{ version: number, size: number, mask: number, matrix: Uint8Array[] }}
 */
export function encodeQrMatrix(text) {
  const bytes = Buffer.from(String(text || ''), 'utf8');
  const spec = VERSIONS_L.find((v) => bytes.length <= v.maxBytes);
  if (!spec) {
    throw new Error(`QR payload too long (${bytes.length} bytes; max ${VERSIONS_L[VERSIONS_L.length - 1].maxBytes})`);
  }

  const codewords = encodeCodewords(bytes, spec);
  const base = createMatrix(spec.size);
  populateFunctionPatterns(base, spec);
  placeDataBits(base, codewords);

  let bestMask = 0;
  let bestScore = Infinity;
  let bestMod = null;

  for (let mask = 0; mask < 8; mask++) {
    const candidate = base.mod.map((row) => new Uint8Array(row));
    for (let r = 0; r < spec.size; r++) {
      for (let c = 0; c < spec.size; c++) {
        if (!base.fn[r][c] && maskBit(mask, r, c)) {
          candidate[r][c] ^= 1;
        }
      }
    }
    writeFormatInfo(candidate, spec.size, mask);
    const score = penaltyScore(candidate, spec.size);
    if (score < bestScore) {
      bestScore = score;
      bestMask = mask;
      bestMod = candidate;
    }
  }

  return {
    version: spec.version,
    size: spec.size,
    mask: bestMask,
    matrix: bestMod,
  };
}

/**
 * Render an inline SVG QR code (#ffffff modules on #111618 background by default).
 * @param {string} text
 * @param {{ quietZone?: number, fg?: string, bg?: string, pixelSize?: number }} [opts]
 * @returns {string}
 */
export function encodeQrSvg(text, opts = {}) {
  const quiet = Number.isInteger(opts.quietZone) && opts.quietZone >= 0 ? opts.quietZone : 4;
  const fg = opts.fg || '#ffffff';
  const bg = opts.bg || '#111618';
  const pixelSize = Number(opts.pixelSize) > 0 ? Number(opts.pixelSize) : 220;

  const { size, matrix } = encodeQrMatrix(text);
  const viewSize = size + quiet * 2;

  const pathParts = [];
  for (let r = 0; r < size; r++) {
    let runStart = -1;
    for (let c = 0; c <= size; c++) {
      const dark = c < size && matrix[r][c] === 1;
      if (dark && runStart === -1) {
        runStart = c;
      } else if (!dark && runStart !== -1) {
        const len = c - runStart;
        pathParts.push(`M${runStart + quiet},${r + quiet}h${len}v1h-${len}z`);
        runStart = -1;
      }
    }
  }

  return (
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${viewSize} ${viewSize}" ` +
    `width="${pixelSize}" height="${pixelSize}" shape-rendering="crispEdges" ` +
    `role="img" aria-label="Wiretok LAN Pairing QR">` +
    `<rect width="${viewSize}" height="${viewSize}" fill="${bg}"/>` +
    `<path d="${pathParts.join('')}" fill="${fg}"/>` +
    `</svg>`
  );
}

export default encodeQrSvg;

/*
  File: build/ip-replacement/index.js
  Purpose: Stand-in for the "ip" npm package, installed through the "overrides" field in
  package.json. The only code that imports "ip" is bittorrent-tracker's UDP server
  (lib/server/parse-udp.js), which formats the optional IPv4 address in an announce with
  ipLib.toString(). Nym Share never runs that server and esbuild never bundles it, but the real
  package carries unfixed advisories (GHSA-2p57-rm9w-gvfp), so it is replaced by this module,
  which implements toString correctly and nothing else.
  Created: 2026-11-15
*/

/**
 * Formats an IP address as text.
 * Accepts an unsigned 32-bit number (as parse-udp.js passes it) or a 4- or 16-byte buffer,
 * with an optional offset and length into the buffer.
 */
function toString (value, offset = 0, length) {
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new RangeError('not an IPv4 address: ' + value)
    return [value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join('.')
  }
  const bytes = Uint8Array.from(value.subarray ? value.subarray(offset, length === undefined ? undefined : offset + length) : value)
  if (bytes.length === 4) return Array.from(bytes).join('.')
  if (bytes.length === 16) {
    const groups = []
    for (let index = 0; index < 16; index += 2) groups.push(((bytes[index] << 8) | bytes[index + 1]).toString(16))
    // Shorten the longest run of two or more zero groups to "::" (RFC 5952).
    let bestStart = -1
    let bestLength = 0
    for (let start = 0; start < 8; start += 1) {
      let runLength = 0
      while (start + runLength < 8 && groups[start + runLength] === '0') runLength += 1
      if (runLength > bestLength && runLength >= 2) { bestStart = start; bestLength = runLength }
    }
    if (bestStart === -1) return groups.join(':')
    return groups.slice(0, bestStart).join(':') + '::' + groups.slice(bestStart + bestLength).join(':')
  }
  throw new RangeError('expected 4 or 16 bytes, got ' + bytes.length)
}

export { toString }
export default { toString }

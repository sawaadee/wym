/*
  build/webtorrent-latency-patch.mjs
  Purpose: raises two timeouts in the prebuilt webtorrent 3.0.21 browser file that are too short
  for a mixnet path. WebTorrent destroys a peer whose BitTorrent handshake has not arrived after
  25 s, and a wire with piece requests outstanding that receives nothing for 30 s. In testing
  between two browsers, Nym messages took 8 to 19 s one way, so a handshake round trip came within
  6 s of the first limit. The page detects real stalls itself (src/app.js, checkReceiverHealth),
  with thresholds that scale with the measured round trip, so WebTorrent's limits only need to
  stop being the first thing to fire.
  Each anchor must match exactly once, and the version is checked, so an upgrade stops the build
  instead of silently leaving the old limits in place.
  Created: 2026-11-14
*/

export const PATCHED_WEBTORRENT_VERSION = '3.0.21'
export const HANDSHAKE_TIMEOUT_MS = 120000
export const PIECE_TIMEOUT_MS = 120000

const EDITS = [
  [
    'this.handshakeTimeout=setTimeout(()=>{this.destroy(new Error("handshake timeout"))},25e3)',
    'this.handshakeTimeout=setTimeout(()=>{this.destroy(new Error("handshake timeout"))},' + HANDSHAKE_TIMEOUT_MS + ')'
  ],
  [
    '"webSeed"!==e.type&&e.setTimeout(3e4,!0)',
    '"webSeed"!==e.type&&e.setTimeout(' + PIECE_TIMEOUT_MS + ',!0)'
  ]
]

/** Returns the WebTorrent browser build with the longer timeouts. */
export function patchWebTorrentSource (source) {
  let patched = source
  for (const [anchor, replacement] of EDITS) {
    const occurrences = patched.split(anchor).length - 1
    if (occurrences !== 1) throw new Error('WebTorrent patch: expected the anchor exactly once, found ' + occurrences + ': ' + anchor)
    patched = patched.replace(anchor, () => replacement)
  }
  return patched
}

/** esbuild plugin that applies the patch when webtorrent's prebuilt browser file is loaded. */
export function webTorrentLatencyPatchPlugin () {
  return {
    name: 'webtorrent-latency-patch',
    setup (build) {
      build.onLoad({ filter: /webtorrent[\\/]dist[\\/]webtorrent\.min\.js$/ }, async args => {
        const { readFile } = await import('node:fs/promises')
        const manifest = JSON.parse(await readFile(new URL('../node_modules/webtorrent/package.json', import.meta.url), 'utf8'))
        if (manifest.version !== PATCHED_WEBTORRENT_VERSION) {
          throw new Error('WebTorrent patch targets ' + PATCHED_WEBTORRENT_VERSION + ' but ' + manifest.version + ' is installed. Review the patch before upgrading.')
        }
        return { contents: patchWebTorrentSource(await readFile(args.path, 'utf8')), loader: 'js' }
      })
    }
  }
}

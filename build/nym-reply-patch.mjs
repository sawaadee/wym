/*
  build/nym-reply-patch.mjs
  Purpose: patches the web worker embedded in @nymproject/sdk-full-fat 1.4.1 so the page can
  answer a message through the reply blocks (SURBs) the sender attached to it, without ever
  learning the sender's Nym address.

  Why a patch is needed: the SDK already sends every message as "anonymous" with reply blocks,
  and its WebAssembly client passes each received message's sender tag to the worker. But the
  SDK drops that tag, and the tag arrives as an opaque wasm-bindgen object with no methods,
  while the client's send_reply(message, tag) only accepts the tag as a base58 string. The
  patch reads the tag's 16 bytes out of WebAssembly memory, base58-encodes them, forwards the
  tag with each RawMessageReceived event, and exposes rawReply({ payload, senderTag }).

  The worker source is decoded and re-encoded as Latin-1 so every byte outside the patched
  anchors stays identical. Each anchor must match exactly once; any mismatch (for example after
  a version change) stops the build instead of producing a half-patched worker.
  Created: 2026-11-14
*/

export const PATCHED_SDK_VERSION = '1.4.1'

// Reads an AnonymousSenderTag handed to JavaScript by wasm-bindgen. The object's __wbg_ptr points
// at a wasm-bindgen cell: a 4-byte borrow flag plus the 16 tag bytes. Rust does not guarantee the
// order of those two fields, so the flag is located instead of assumed: it is zero while the tag
// is not borrowed, and a random 16-byte tag has a 1 in 2^32 chance of ending in four zero bytes.
// When both ends are zero the tag is refused rather than guessed.
const SENDER_TAG_HELPERS = `
  // ---- wym patch: reply-tag helpers -------------------------------------------------------
  const WYM_BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  function wymEncodeBase58(bytes) {
      let leadingZeros = 0;
      while (leadingZeros < bytes.length && bytes[leadingZeros] === 0) leadingZeros++;
      const digits = [];
      for (let index = leadingZeros; index < bytes.length; index++) {
          let carry = bytes[index];
          for (let digitIndex = 0; digitIndex < digits.length; digitIndex++) {
              carry += digits[digitIndex] << 8;
              digits[digitIndex] = carry % 58;
              carry = (carry / 58) | 0;
          }
          while (carry > 0) {
              digits.push(carry % 58);
              carry = (carry / 58) | 0;
          }
      }
      let encoded = '1'.repeat(leadingZeros);
      for (let digitIndex = digits.length - 1; digitIndex >= 0; digitIndex--) encoded += WYM_BASE58_ALPHABET[digits[digitIndex]];
      return encoded;
  }
  function wymReadSenderTag(senderTag) {
      if (!senderTag || !senderTag.__wbg_ptr) return null;
      const cell = new Uint8Array(wasm.memory.buffer, senderTag.__wbg_ptr, 20);
      const flagAtStart = cell[0] === 0 && cell[1] === 0 && cell[2] === 0 && cell[3] === 0;
      const flagAtEnd = cell[16] === 0 && cell[17] === 0 && cell[18] === 0 && cell[19] === 0;
      if (flagAtStart === flagAtEnd) return null;
      return wymEncodeBase58(cell.slice(flagAtStart ? 4 : 0, flagAtStart ? 20 : 16));
  }
  // ---- end wym patch ------------------------------------------------------------------------
`

// [anchor, replacement] pairs applied to the decoded worker source, in order.
const WORKER_EDITS = [
  [
    '  const ClientConfigFinalization = ',
    SENDER_TAG_HELPERS + '\n  const ClientConfigFinalization = '
  ],
  [
    'onMessageHandler = function (message) {',
    'onMessageHandler = function (message, senderTag) {'
  ],
  [
    'onRawPayloadHandler(message);',
    'onRawPayloadHandler(message, wymReadSenderTag(senderTag));'
  ],
  [
    'wrapper.start(opts, function (message) {',
    'wrapper.start(opts, function (message, senderTag) {'
  ],
  [
    'args: { payload: message },',
    'args: { payload: message, senderTag: senderTag },'
  ],
  [
    '          rawSend: function (args) {',
    '          rawReply: function (args) {\n' +
    '              return wrapper.client.send_reply(args.payload, args.senderTag);\n' +
    '          },\n' +
    '          rawSend: function (args) {'
  ]
]

function replaceExactlyOnce (source, anchor, replacement, label) {
  const occurrences = source.split(anchor).length - 1
  if (occurrences !== 1) {
    throw new Error(label + ': expected the anchor exactly once, found ' + occurrences + ': ' + JSON.stringify(anchor.slice(0, 60)))
  }
  return source.replace(anchor, () => replacement)
}

/** Returns the worker source with the reply-tag patch applied. */
export function patchWorkerSource (workerSource) {
  let patched = workerSource
  for (const [anchor, replacement] of WORKER_EDITS) patched = replaceExactlyOnce(patched, anchor, replacement, 'Nym worker patch')
  return patched
}

// The SDK embeds its worker as the single-quoted base64 argument of this call. A plain string
// scan is used because a regular expression over the 6.7 MB literal overflows V8's stack.
const WORKER_FACTORY_CALL = "createBase64WorkerFactory('"

/** Returns { start, end } of the embedded base64 worker inside the SDK source. */
export function locateEmbeddedWorker (sdkSource) {
  const callIndex = sdkSource.indexOf(WORKER_FACTORY_CALL)
  if (callIndex === -1 || sdkSource.indexOf(WORKER_FACTORY_CALL, callIndex + 1) !== -1) {
    throw new Error('Nym SDK patch: expected exactly one ' + WORKER_FACTORY_CALL + ' call.')
  }
  const start = callIndex + WORKER_FACTORY_CALL.length
  const end = sdkSource.indexOf("'", start)
  if (end === -1 || !/^[A-Za-z0-9+/=]+$/.test(sdkSource.slice(start, Math.min(end, start + 4096)))) {
    throw new Error('Nym SDK patch: the embedded worker is not a base64 string.')
  }
  return { start, end }
}

/** Returns the SDK module source with its embedded base64 worker replaced by the patched worker. */
export function patchNymSdkSource (sdkSource) {
  const { start, end } = locateEmbeddedWorker(sdkSource)
  const workerSource = Buffer.from(sdkSource.slice(start, end), 'base64').toString('latin1')
  const patchedWorker = patchWorkerSource(workerSource)
  return sdkSource.slice(0, start) + Buffer.from(patchedWorker, 'latin1').toString('base64') + sdkSource.slice(end)
}

/** esbuild plugin that applies the patch when the SDK module is loaded. */
export function nymReplyPatchPlugin () {
  return {
    name: 'nym-reply-patch',
    setup (build) {
      build.onLoad({ filter: /@nymproject[\\/]sdk-full-fat[\\/]index\.js$/ }, async args => {
        const { readFile } = await import('node:fs/promises')
        const manifest = JSON.parse(await readFile(new URL('../node_modules/@nymproject/sdk-full-fat/package.json', import.meta.url), 'utf8'))
        if (manifest.version !== PATCHED_SDK_VERSION) {
          throw new Error('Nym SDK patch targets ' + PATCHED_SDK_VERSION + ' but ' + manifest.version + ' is installed. Review the patch before upgrading.')
        }
        return { contents: patchNymSdkSource(await readFile(args.path, 'utf8')), loader: 'js' }
      })
    }
  }
}

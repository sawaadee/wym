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

  It also skips the worker's attempt to decode every message in the SDK's mime-typed format
  (this page only sends raw frames, so every attempt failed with a console error), reports the
  worker's gateway WebSocket open, close and error events to the page (the
  SDK has no disconnect event), counts the messages and bytes the worker exchanges with its
  gateway (wymGatewayTraffic()), exposes wymCloseGatewaySockets() for fault-injection tests, and
  returns terminate() from createNymMixnetClient so a replaced client's worker can be ended.

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

// Reports the worker's gateway WebSocket lifecycle to the page. The SDK has no disconnect event,
// so without this the page cannot tell a lost gateway connection from a quiet one. The WASM
// client resolves the global WebSocket each time it connects, so wrapping the global before the
// client starts covers its first connection and every reconnection. Gateway URLs are not
// reported, because they identify the gateway this client uses.
const GATEWAY_SOCKET_TRACKING = `
  // ---- wym patch: gateway socket tracking -------------------------------------------------
  const wymTrackedSockets = new Set();
  const WymNativeWebSocket = self.WebSocket;
  function wymReportSocketState(state, details) {
      self.postMessage({ kind: 'WymSocketState', args: Object.assign({ state: state, openSockets: wymTrackedSockets.size }, details) });
  }
  // Cumulative gateway traffic of this worker, across every socket it has opened. The Nym gateway
  // client sends each Sphinx packet as one binary WebSocket message and every request or
  // response as a text message, so binary messages out count mix packets (real and cover).
  // Ping frames are handled by the browser and never reach these counters.
  const wymGatewayTraffic = {
      binaryMessagesOut: 0, binaryBytesOut: 0, textMessagesOut: 0, textBytesOut: 0,
      binaryMessagesIn: 0, binaryBytesIn: 0, textMessagesIn: 0, textBytesIn: 0
  };
  function wymMessageByteLength(data) {
      if (typeof data === 'string') return data.length;
      if (data instanceof ArrayBuffer || ArrayBuffer.isView(data)) return data.byteLength;
      if (typeof Blob !== 'undefined' && data instanceof Blob) return data.size;
      return 0;
  }
  function WymTrackedWebSocket(url, protocols) {
      const socket = protocols === undefined ? new WymNativeWebSocket(url) : new WymNativeWebSocket(url, protocols);
      // The WASM glue calls socket.send(...) as a property lookup, so an own property on the
      // instance sees every outgoing message without changing the shared prototype.
      const wymNativeSend = socket.send;
      socket.send = function (data) {
          if (typeof data === 'string') {
              wymGatewayTraffic.textMessagesOut += 1;
              wymGatewayTraffic.textBytesOut += data.length;
          } else {
              wymGatewayTraffic.binaryMessagesOut += 1;
              wymGatewayTraffic.binaryBytesOut += wymMessageByteLength(data);
          }
          return wymNativeSend.call(socket, data);
      };
      socket.addEventListener('message', function (event) {
          if (typeof event.data === 'string') {
              wymGatewayTraffic.textMessagesIn += 1;
              wymGatewayTraffic.textBytesIn += event.data.length;
          } else {
              wymGatewayTraffic.binaryMessagesIn += 1;
              wymGatewayTraffic.binaryBytesIn += wymMessageByteLength(event.data);
          }
      });
      socket.addEventListener('open', function () {
          wymTrackedSockets.add(socket);
          wymReportSocketState('open', {});
      });
      socket.addEventListener('close', function (event) {
          wymTrackedSockets.delete(socket);
          wymReportSocketState('closed', { code: event.code, wasClean: event.wasClean });
      });
      socket.addEventListener('error', function () {
          wymReportSocketState('error', {});
      });
      return socket;
  }
  WymTrackedWebSocket.prototype = WymNativeWebSocket.prototype;
  WymTrackedWebSocket.CONNECTING = 0;
  WymTrackedWebSocket.OPEN = 1;
  WymTrackedWebSocket.CLOSING = 2;
  WymTrackedWebSocket.CLOSED = 3;
  self.WebSocket = WymTrackedWebSocket;
  // ---- end wym patch ------------------------------------------------------------------------
`

// [anchor, replacement] pairs applied to the decoded worker source, in order.
const WORKER_EDITS = [
  [
    "(function () {\n  'use strict';\n",
    "(function () {\n  'use strict';\n" + GATEWAY_SOCKET_TRACKING
  ],
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
  // After posting the raw message, the worker tries to decode every message as the SDK's own
  // mime-typed format. This page only sends raw frames, so each attempt fails, logs an error to the
  // console and costs a WebAssembly call per frame. Returning here skips it; the page only
  // subscribes to raw messages.
  [
    'args: { payload: message, senderTag: senderTag },\n                              });\n',
    'args: { payload: message, senderTag: senderTag },\n                              });\n                              return [2 /*return*/];\n'
  ],
  [
    '          rawSend: function (args) {',
    '          rawReply: function (args) {\n' +
    '              return wrapper.client.send_reply(args.payload, args.senderTag);\n' +
    '          },\n' +
    // Closes this client's gateway connections, for fault-injection tests only: the page calls
    // it solely when opened with ?faults=1. The Nym client then sees a closed connection.
    '          wymCloseGatewaySockets: function () {\n' +
    '              const count = wymTrackedSockets.size;\n' +
    "              wymTrackedSockets.forEach(function (socket) { socket.close(4000, 'fault injection'); });\n" +
    '              return count;\n' +
    '          },\n' +
    // Returns the cumulative gateway traffic counters with the worker's own clock, so the page
    // can compute rates between two samples without mixing the page's and the worker's clocks.
    '          wymGatewayTraffic: function () {\n' +
    '              return Object.assign({ sampledAtMs: performance.now(), openSockets: wymTrackedSockets.size }, wymGatewayTraffic);\n' +
    '          },\n' +
    '          rawSend: function (args) {'
  ]
]

// [anchor, replacement] pairs applied to the SDK's main-thread code. They expose the socket
// events above and let the page terminate a client's worker; stop() alone frees the WASM client
// but leaves its worker running, so replacing a client would otherwise leak one worker each time.
const MAIN_THREAD_EDITS = [
  [
    '        subscribeToRawMessageReceivedEvent: (handler) => addSubscription(EventKinds.RawMessageReceived, handler),\n    };',
    "        subscribeToRawMessageReceivedEvent: (handler) => addSubscription(EventKinds.RawMessageReceived, handler),\n        subscribeToWymSocketState: (handler) => addSubscription('WymSocketState', handler),\n    };"
  ],
  [
    '    return {\n        client,\n        events,\n    };',
    '    return {\n        client,\n        events,\n        terminate: () => worker.terminate(),\n    };'
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
  let patchedSdk = sdkSource.slice(0, start) + Buffer.from(patchedWorker, 'latin1').toString('base64') + sdkSource.slice(end)
  for (const [anchor, replacement] of MAIN_THREAD_EDITS) patchedSdk = replaceExactlyOnce(patchedSdk, anchor, replacement, 'Nym SDK main-thread patch')
  return patchedSdk
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

/*
  src/app.js
  Purpose: application logic for Nym Share. Files are encrypted in the sender's browser with
  wormhole-crypto (RFC 8188, AES-128-GCM), moved as a private WebTorrent swarm, and every byte
  travels through the Nym mixnet as client-to-client messages, so neither side learns the
  other's IP address. The share link's #fragment carries the network mode, the sender's Nym
  address, the infohash, the key, the salt and an encrypted file list. No server stores anything.
  build.mjs bundles this module and its libraries into docs/index.html.
  Created: 2026-11-14
*/
import { createNymMixnetClient } from '@nymproject/sdk-full-fat'
import WebTorrent from 'webtorrent/dist/webtorrent.min.js'
import { Keychain } from 'wormhole-crypto'
import { Duplex } from 'streamx'
import QRCode from 'qrcode'
import {
  createIcons,
  ArrowRight as ArrowRightIcon,
  Check as CheckIcon,
  CircleX as CircleXIcon,
  ClipboardCopy as ClipboardCopyIcon,
  Copy as CopyIcon,
  Download as DownloadIcon,
  Eraser as EraserIcon,
  EyeOff as EyeOffIcon,
  File as FileIcon,
  FileDown as FileDownIcon,
  Gauge as GaugeIcon,
  Info as InfoIcon,
  Lock as LockIcon,
  QrCode as QrCodeIcon,
  ShieldCheck as ShieldCheckIcon,
  TriangleAlert as TriangleAlertIcon,
  Upload as UploadIcon
} from 'lucide'

// PAGE_VERSION is replaced at build time with the version in package.json.
/* global PAGE_VERSION */

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const NYM_API_URL = 'https://validator.nymtech.net/api'

// Nym pacing per network mode. "balanced" sends a real packet every 2 ms instead of 20 ms
// (raw client throughput in the standalone harness: ~55 -> ~120 KB/s). End to end in this
// page, 1 MB moved at ~43 KB/s Balanced versus ~35 KB/s Maximum once transfers were running,
// so the transfer is not limited by this setting alone. Per-hop mixing delays stay at Nym's defaults.
const NYM_CLIENT_OVERRIDES = {
  balanced: { traffic: { messageSendingAverageDelayMs: 2 } },
  maximum: undefined
}

// WebTorrent keeps ~1 s of requests in flight (PIPELINE_MAX_DURATION = 1). A mixnet round
// trip takes 2-6 s, so the speed WebTorrent reads is scaled to widen the window to ~8 s.
const REQUEST_WINDOW_MULTIPLIER = 8

const MESSAGE_KIND_CONTROL = 1
const MESSAGE_KIND_DATA = 2
const LINK_ID_BYTES = 16
const DATA_HEADER_BYTES = 1 + LINK_ID_BYTES + 4
const MAX_NYM_MESSAGE_BYTES = 32768
// Reply blocks (SURBs) the recipient attaches to each message it sends. The sender answers only
// through these, so it never learns the recipient's Nym address. Each one carries one reply
// packet; when the sender runs short, its Nym client asks the recipient's client for more.
const RECIPIENT_REPLY_SURBS_PER_MESSAGE = 10
// Receiver stall recovery. "Data" means bytes delivered in order to WebTorrent; frames waiting
// behind a gap do not count. With no data for STALL_RELINK_AFTER_MS the receiver opens a fresh
// link to the sender. If that link brings nothing within STALL_SENDER_CHECK_AFTER_RELINK_MS, or
// any link closes before the transfer finishes, it asks whether the sender is online, again every
// STALL_SENDER_CHECK_INTERVAL_MS, and opens a new link whenever the sender answers. In testing a
// fresh link's first frame arrived within 0.3 to 3.5 s, so 15 s without one means it failed.
const STALL_RELINK_AFTER_MS = 20000
const STALL_SENDER_CHECK_AFTER_RELINK_MS = 15000
const STALL_SENDER_CHECK_INTERVAL_MS = 20000
const STALL_CHECK_INTERVAL_MS = 2000
const RECIPIENT_ID_PATTERN = /^[0-9a-f]{32}$/

// Fault injection for testing recovery, enabled only when the page is opened with ?faults=1.
// It adds window.nymShareFaults; nothing else changes.
const FAULT_INJECTION_ENABLED = new URLSearchParams(location.search).get('faults') === '1'
const faultInjection = { dropIncomingDataUntil: 0 }
const PIECE_LENGTH_BYTES = 65536
const MAX_TOTAL_BYTES = 500 * 1000 * 1000 // everything is held in memory on both sides
const SENDER_REPLY_TIMEOUT_MS = 60000
const LINK_VERSION = 'v2'
const LINK_MODE_CODES = { balanced: 'b', maximum: 'm' }
const MODE_LABELS = { balanced: 'Balanced', maximum: 'Maximum privacy' }
const LINK_SEPARATOR = '~' // Nym addresses contain "." and "@", never "~"

// ---------------------------------------------------------------------------
// Diagnostics log
// Everything the page does is recorded here with a timestamp relative to page load, so
// logs from a sender and a receiver can be lined up. Secrets never enter the log: no key,
// salt, link, file name or full Nym address. Addresses are reduced to a short prefix plus
// the gateway prefix, which is enough to tell peers apart.
// ---------------------------------------------------------------------------
const MAX_LOG_ENTRIES = 5000
const SESSION_ID = Array.from(crypto.getRandomValues(new Uint8Array(4)), byte => byte.toString(16).padStart(2, '0')).join('')

const diagnostics = {
  entries: [],
  renderScheduled: false,

  log (level, category, message, details) {
    const entry = {
      seconds: performance.now() / 1000,
      wallClock: new Date().toISOString().slice(11, 23),
      level,
      category,
      message,
      details: details === undefined ? undefined : diagnostics.safeStringify(details)
    }
    diagnostics.entries.push(entry)
    if (diagnostics.entries.length > MAX_LOG_ENTRIES) diagnostics.entries.splice(0, diagnostics.entries.length - MAX_LOG_ENTRIES)
    const consoleMethod = level === 'error' ? 'error' : level === 'warn' ? 'warn' : 'log'
    console[consoleMethod]('[nym-share ' + category + '] ' + message, details ?? '')
    diagnostics.scheduleRender()
  },
  info (category, message, details) { diagnostics.log('info', category, message, details) },
  warn (category, message, details) { diagnostics.log('warn', category, message, details) },
  error (category, message, details) { diagnostics.log('error', category, message, details) },

  safeStringify (value) {
    try {
      if (value instanceof Error) return value.name + ': ' + value.message + (value.stack ? ' | ' + value.stack.split('\n').slice(1, 4).join(' | ').replace(/\s+/g, ' ') : '')
      return JSON.stringify(value, (key, inner) => inner instanceof Error ? inner.name + ': ' + inner.message : inner)
    } catch (error) {
      return String(value)
    }
  },

  formatEntry (entry) {
    return '+' + entry.seconds.toFixed(3).padStart(9) + 's ' + entry.wallClock + ' ' + entry.level.toUpperCase().padEnd(5) + ' ' + entry.category.padEnd(9) + ' ' + entry.message + (entry.details ? ' ' + entry.details : '')
  },

  scheduleRender () {
    if (diagnostics.renderScheduled) return
    diagnostics.renderScheduled = true
    // A timer rather than requestAnimationFrame: animation frames never fire in a background
    // tab, which left the panel frozen while a second tab was in front during two-tab tests.
    setTimeout(() => {
      diagnostics.renderScheduled = false
      const output = document.getElementById('log-output')
      const count = document.getElementById('log-count')
      if (!output || !count) return
      count.textContent = diagnostics.entries.length + (diagnostics.entries.length === 1 ? ' entry' : ' entries')
      if (!document.getElementById('diagnostics').open) return
      const nearBottom = output.scrollHeight - output.scrollTop - output.clientHeight < 40
      const fragment = document.createDocumentFragment()
      for (const entry of diagnostics.entries.slice(-800)) {
        const line = document.createElement('div')
        if (entry.level !== 'info') line.className = 'log-level-' + entry.level
        line.textContent = diagnostics.formatEntry(entry)
        fragment.append(line)
      }
      output.replaceChildren(fragment)
      if (nearBottom) output.scrollTop = output.scrollHeight
    }, 150)
  },

  exportText () {
    const header = [
      'Nym Share diagnostics',
      'session ' + SESSION_ID + ', exported ' + new Date().toISOString(),
      'entries ' + diagnostics.entries.length + (diagnostics.entries.length >= MAX_LOG_ENTRIES ? ' (oldest dropped)' : ''),
      ''
    ]
    return header.concat(diagnostics.entries.map(diagnostics.formatEntry)).join('\n') + '\n'
  }
}

/** Shortens a Nym address ("identity.encryption@gateway") to identity and gateway prefixes. */
function redactNymAddress (address) {
  if (typeof address !== 'string') return String(address)
  const [client, gateway = ''] = address.split('@')
  return client.slice(0, 6) + '...@' + gateway.slice(0, 6) + '...'
}

function logEnvironment () {
  const navigatorDetails = {
    userAgent: navigator.userAgent,
    brands: navigator.userAgentData?.brands?.map(brand => brand.brand + ' ' + brand.version).join(', ') ?? null,
    platform: navigator.userAgentData?.platform ?? navigator.platform ?? null,
    mobile: navigator.userAgentData?.mobile ?? null,
    language: navigator.language,
    hardwareConcurrency: navigator.hardwareConcurrency ?? null,
    deviceMemoryGb: navigator.deviceMemory ?? null
  }
  const pageDetails = {
    session: SESSION_ID,
    protocol: location.protocol,
    origin: location.origin,
    secureContext: window.isSecureContext,
    crossOriginIsolated: window.crossOriginIsolated,
    webCrypto: Boolean(crypto?.subtle),
    workers: typeof Worker === 'function',
    webAssembly: typeof WebAssembly === 'object',
    readableStream: typeof ReadableStream === 'function',
    hasLinkInAddressBar: location.hash.length > 1,
    visibility: document.visibilityState
  }
  diagnostics.info('env', 'browser', navigatorDetails)
  diagnostics.info('env', 'page', pageDetails)
  if (!window.isSecureContext) diagnostics.warn('env', 'page is not a secure context; Web Crypto may be unavailable')
}

window.addEventListener('error', event => {
  diagnostics.error('runtime', 'uncaught error', { message: event.message, source: (event.filename ?? '').split('/').pop(), line: event.lineno, column: event.colno })
})
window.addEventListener('unhandledrejection', event => {
  diagnostics.error('runtime', 'unhandled promise rejection', event.reason instanceof Error ? event.reason : String(event.reason))
})
document.addEventListener('visibilitychange', () => diagnostics.info('env', 'visibility ' + document.visibilityState))
window.addEventListener('online', () => diagnostics.info('env', 'network online'))
window.addEventListener('offline', () => diagnostics.warn('env', 'network offline'))

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()
const elementById = id => document.getElementById(id)

function bytesToHex (bytes) {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
}
function hexToBytes (hex) {
  return Uint8Array.from(hex.match(/../g), pair => parseInt(pair, 16))
}
function bytesToBase64Url (bytes) {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function base64UrlToBytes (text) {
  const padded = text.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((text.length + 3) % 4)
  return Uint8Array.from(atob(padded), character => character.charCodeAt(0))
}
async function sha256Hex (bytes) {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)))
}
async function readStreamToBytes (readableStream) {
  return new Uint8Array(await new Response(readableStream).arrayBuffer())
}
function formatBytes (bytes) {
  const units = ['B', 'KB', 'MB', 'GB']
  let value = bytes
  let unitIndex = 0
  while (value >= 1000 && unitIndex < units.length - 1) { value /= 1000; unitIndex += 1 }
  return (unitIndex === 0 ? String(Math.round(value)) : value.toFixed(value < 10 ? 1 : 0)) + ' ' + units[unitIndex]
}
function formatDuration (seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return 'Estimating'
  if (seconds < 60) return Math.ceil(seconds) + ' s'
  const minutes = Math.floor(seconds / 60)
  return minutes + ' min ' + Math.round(seconds % 60) + ' s'
}

/** Builds an element; text content is always set as text, never parsed as HTML. */
function createElement (tagName, attributes = {}, children = []) {
  const element = document.createElement(tagName)
  for (const [name, value] of Object.entries(attributes)) {
    if (name === 'text') element.textContent = value
    else if (name === 'className') element.className = value
    else element.setAttribute(name, value)
  }
  for (const child of children) element.append(child)
  return element
}

/**
 * Measures a rate over a sliding window of samples. Mixnet delivery arrives in bursts
 * (tested: 4 to 147 KB/s within seconds), so a 15 s window keeps speed and time-left steady.
 */
class RateMeter {
  constructor (windowMs = 15000) { this.windowMs = windowMs; this.samples = [] }
  update (totalBytes) {
    const now = performance.now()
    this.samples.push({ time: now, totalBytes })
    while (this.samples.length > 2 && now - this.samples[0].time > this.windowMs) this.samples.shift()
    const first = this.samples[0]
    const elapsedSeconds = (now - first.time) / 1000
    return elapsedSeconds > 0 ? (totalBytes - first.totalBytes) / elapsedSeconds : 0
  }
}

// ---------------------------------------------------------------------------
// Libraries
// ---------------------------------------------------------------------------
// Every library is bundled into the page at build time (build.mjs), so nothing is fetched from
// a CDN when the page runs. loadLibraries keeps its async shape so the callers stay unchanged.
const libraries = { createNymMixnetClient, WebTorrent, Keychain, Duplex, QRCode, loaded: true }
let librariesReported = false
function loadLibraries () {
  if (!librariesReported) {
    librariesReported = true
    diagnostics.info('library', 'bundled libraries ready', { webtorrent: WebTorrent.VERSION, webrtcSupport: WebTorrent.WEBRTC_SUPPORT })
  }
  return Promise.resolve(libraries)
}

// Only the icons the page uses are bundled. Keys are the PascalCase names createIcons looks up
// for each data-lucide attribute; the imports are aliased so names such as File do not shadow
// the browser's own File constructor.
const PAGE_ICONS = {
  ArrowRight: ArrowRightIcon,
  Check: CheckIcon,
  CircleX: CircleXIcon,
  ClipboardCopy: ClipboardCopyIcon,
  Copy: CopyIcon,
  Download: DownloadIcon,
  Eraser: EraserIcon,
  EyeOff: EyeOffIcon,
  File: FileIcon,
  FileDown: FileDownIcon,
  Gauge: GaugeIcon,
  Info: InfoIcon,
  Lock: LockIcon,
  QrCode: QrCodeIcon,
  ShieldCheck: ShieldCheckIcon,
  TriangleAlert: TriangleAlertIcon,
  Upload: UploadIcon
}
function renderIcons () {
  try {
    createIcons({ icons: PAGE_ICONS })
  } catch (error) {
    diagnostics.warn('library', 'icons could not be rendered', error)
  }
}

// ---------------------------------------------------------------------------
// Network status
// ---------------------------------------------------------------------------
function setNetworkStatus (state, text) {
  const pill = elementById('network-status')
  pill.dataset.state = state
  elementById('network-status-text').textContent = text
}

// ---------------------------------------------------------------------------
// Nym node: one mixnet client, routing control messages and data frames
// ---------------------------------------------------------------------------
function encodeControlMessage (message) {
  const json = textEncoder.encode(JSON.stringify(message))
  const frame = new Uint8Array(1 + json.length)
  frame[0] = MESSAGE_KIND_CONTROL
  frame.set(json, 1)
  return frame
}

/** Describes a control message for the log: its kind and non-secret fields only. */
function describeControlMessage (message) {
  const description = { kind: message?.kind }
  if (typeof message?.infoHash === 'string') description.infoHash = message.infoHash.slice(0, 8)
  if (typeof message?.linkId === 'string') description.linkId = message.linkId.slice(0, 8)
  if (message?.reason !== undefined) description.reason = message.reason
  if (message?.verified !== undefined) description.verified = message.verified
  if (typeof message?.recipientId === 'string') description.recipient = message.recipientId.slice(0, 6)
  return description
}

/** Shortens a reply tag for the log. A tag identifies a conversation, not a person or address. */
function describeReplyTag (senderTag) {
  return typeof senderTag === 'string' ? senderTag.slice(0, 6) + '...' : null
}

// ---------------------------------------------------------------------------
// Nym client storage housekeeping
// ---------------------------------------------------------------------------
// The Nym SDK keeps each client's keys in an IndexedDB database named
// "wasm-client-storage-<clientId>". Every page load uses a fresh random client id, so without
// cleanup each visit would leave one more database of key material behind for good.
// Open tabs record a heartbeat in localStorage; on startup, a database is deleted only when
// no tab has refreshed its heartbeat for a minute, so another live tab's storage is never
// pulled out from under it.
const NYM_CONNECT_ATTEMPT_TIMEOUT_MS = 20000
const NYM_CONNECT_ATTEMPTS = 3
// How long the Nym client gets to restore a lost gateway connection on its own before the node
// replaces it, how long a send waits for a reconnecting client, and the longest pause between
// reconnect attempts.
const NYM_INTERNAL_RECONNECT_GRACE_MS = 15000
const NYM_SEND_WAIT_MS = 90000
const NYM_RECONNECT_MAX_DELAY_MS = 30000
// The Nym WASM client registers with a new gateway on every start unless it is given a preferred
// one, and a new gateway means a new address, which breaks links already shared. Reconnects
// therefore ask for the current gateway first, and only fall back to a new one after this many
// failed attempts (the gateway itself may be down).
const NYM_RECONNECT_SAME_GATEWAY_ATTEMPTS = 3
const NYM_STORAGE_PREFIX = 'wasm-client-storage-'
const NYM_CLIENT_ID_PREFIX = 'nym-share-'
const CLIENT_HEARTBEAT_KEY = 'nym-share-live-clients'
const CLIENT_HEARTBEAT_INTERVAL_MS = 10000
const CLIENT_HEARTBEAT_STALE_MS = 60000

function readClientHeartbeats () {
  try {
    return JSON.parse(localStorage.getItem(CLIENT_HEARTBEAT_KEY) ?? '{}') ?? {}
  } catch (error) {
    return {}
  }
}

function writeClientHeartbeats (heartbeats) {
  try {
    localStorage.setItem(CLIENT_HEARTBEAT_KEY, JSON.stringify(heartbeats))
  } catch (error) {
    // Storage can be disabled (private modes, some file:// setups); cleanup then becomes a no-op.
  }
}

/** Marks a client id as in use until the returned function is called. */
function startClientHeartbeat (clientId) {
  const beat = () => {
    const heartbeats = readClientHeartbeats()
    heartbeats[clientId] = Date.now()
    writeClientHeartbeats(heartbeats)
  }
  beat()
  const timer = setInterval(beat, CLIENT_HEARTBEAT_INTERVAL_MS)
  return () => {
    clearInterval(timer)
    const heartbeats = readClientHeartbeats()
    delete heartbeats[clientId]
    writeClientHeartbeats(heartbeats)
  }
}

/** Deletes Nym key databases left by earlier visits whose tabs are no longer open. */
async function removeStaleNymStorage (currentClientId) {
  if (typeof indexedDB?.databases !== 'function') {
    diagnostics.info('storage', 'indexedDB.databases() unsupported; skipping cleanup of earlier Nym clients')
    return
  }
  const now = Date.now()
  const heartbeats = readClientHeartbeats()
  for (const [clientId, lastSeen] of Object.entries(heartbeats)) {
    if (now - lastSeen > CLIENT_HEARTBEAT_STALE_MS) delete heartbeats[clientId]
  }
  writeClientHeartbeats(heartbeats)

  const names = (await indexedDB.databases()).map(database => database.name ?? '')
  const staleNames = names.filter(name => {
    if (!name.startsWith(NYM_STORAGE_PREFIX + NYM_CLIENT_ID_PREFIX)) return false
    const clientId = name.slice(NYM_STORAGE_PREFIX.length)
    return clientId !== currentClientId && heartbeats[clientId] === undefined
  })
  for (const name of staleNames) indexedDB.deleteDatabase(name)
  const otherLiveClients = Object.keys(heartbeats).filter(clientId => clientId !== currentClientId).length
  diagnostics.info('storage', 'earlier Nym client storage removed', { removed: staleNames.length, otherLiveClients })
}

// A Nym node is one Nym identity (clientId) for the life of the page. The Nym client behind it
// can be replaced: if the gateway connection is lost and the Nym client does not restore it
// within NYM_INTERNAL_RECONNECT_GRACE_MS, the node starts a new client with the same clientId.
// The keys and gateway registration stored under that id are reused, so the address in an
// existing share link stays valid and messages the gateway held meanwhile are delivered.
// Sends made while the client is being replaced wait for it (up to NYM_SEND_WAIT_MS).
async function createNymNode (mode) {
  const startedAt = performance.now()
  const clientId = NYM_CLIENT_ID_PREFIX + crypto.randomUUID()
  const stopHeartbeat = startClientHeartbeat(clientId)
  try {
    await removeStaleNymStorage(clientId)
  } catch (error) {
    diagnostics.warn('storage', 'cleanup of earlier Nym client storage failed', error)
  }
  diagnostics.info('nym', 'starting client', { mode, override: NYM_CLIENT_OVERRIDES[mode] ?? 'Nym defaults' })

  const node = {
    address: null,
    mode,
    state: 'connecting', // connecting, connected, reconnecting, stopped
    onControl: null,
    onData: null,
    onReconnected: null,
    counters: { dataFramesIn: 0, dataBytesIn: 0, dataFramesOut: 0, dataBytesOut: 0, controlIn: 0, controlOut: 0, sendFailures: 0, unknownMessages: 0, gatewayDisconnects: 0, reconnects: 0, faultDroppedFrames: 0 }
  }
  let mixnetClient = null
  let clientGeneration = 0
  let usableWaiters = []
  let socketGraceTimer = null
  let socketLostAt = 0
  let reconnectPromise = null

  const setState = state => {
    node.state = state
    if (state !== 'connected') return
    const waiters = usableWaiters
    usableWaiters = []
    for (const waiter of waiters) waiter.resolve()
  }

  // Resolves once the node can send. Rejects after NYM_SEND_WAIT_MS so a sender is never stuck
  // behind a client that cannot come back.
  const waitUntilUsable = () => {
    if (node.state === 'connected') return Promise.resolve()
    if (node.state === 'stopped') return Promise.reject(new Error('The Nym client was stopped.'))
    return new Promise((resolve, reject) => {
      const waiter = { resolve: () => { clearTimeout(waiter.timer); resolve() } }
      waiter.timer = setTimeout(() => {
        usableWaiters = usableWaiters.filter(entry => entry !== waiter)
        reject(new Error('The Nym client did not reconnect within ' + NYM_SEND_WAIT_MS / 1000 + ' seconds.'))
      }, NYM_SEND_WAIT_MS)
      usableWaiters.push(waiter)
    })
  }

  // senderTag is set when the message carried reply blocks (see build/nym-reply-patch.mjs),
  // and null for replies, which carry none.
  const handleRawMessage = event => {
    const payload = event.args.payload
    const senderTag = typeof event.args.senderTag === 'string' ? event.args.senderTag : null
    if (payload[0] === MESSAGE_KIND_DATA) {
      if (faultInjection.dropIncomingDataUntil > Date.now()) {
        node.counters.faultDroppedFrames += 1
        return
      }
      node.counters.dataFramesIn += 1
      node.counters.dataBytesIn += payload.length
      node.onData?.(payload, senderTag)
      return
    }
    if (payload[0] !== MESSAGE_KIND_CONTROL) {
      node.counters.unknownMessages += 1
      diagnostics.warn('nym', 'message with unknown type byte', { typeByte: payload[0], bytes: payload.length })
      return
    }
    let message
    try {
      message = JSON.parse(textDecoder.decode(payload.subarray(1)))
    } catch (error) {
      diagnostics.warn('control', 'dropped malformed control message', { bytes: payload.length, error })
      return
    }
    node.counters.controlIn += 1
    diagnostics.info('control', 'received ' + message?.kind, Object.assign(describeControlMessage(message), { replyTag: describeReplyTag(senderTag) }))
    try {
      node.onControl?.(message, senderTag)
    } catch (error) {
      diagnostics.error('control', 'handler failed for ' + message?.kind, error)
    }
  }

  // The Nym client retries a lost gateway connection by itself (10 attempts, 5 s apart). The
  // node gives it NYM_INTERNAL_RECONNECT_GRACE_MS before replacing the client.
  const handleSocketState = ({ state, code, wasClean, openSockets }) => {
    if (state === 'open') {
      if (socketGraceTimer) {
        clearTimeout(socketGraceTimer)
        socketGraceTimer = null
        diagnostics.info('nym', 'gateway connection restored by the Nym client', { afterMs: Math.round(performance.now() - socketLostAt) })
        setNetworkStatus('connected', 'Connected to Nym')
      }
      return
    }
    if (state === 'error') {
      diagnostics.warn('nym', 'gateway connection error', { openSockets, nodeState: node.state })
      return
    }
    if (node.state !== 'connected' || openSockets > 0 || socketGraceTimer) {
      diagnostics.info('nym', 'a gateway connection closed', { code, wasClean, openSockets, nodeState: node.state })
      return
    }
    node.counters.gatewayDisconnects += 1
    socketLostAt = performance.now()
    diagnostics.warn('nym', 'gateway connection lost', { code, wasClean, waitingMs: NYM_INTERNAL_RECONNECT_GRACE_MS })
    setNetworkStatus('connecting', 'Reconnecting to Nym')
    socketGraceTimer = setTimeout(() => {
      socketGraceTimer = null
      node.reconnect('the gateway connection did not come back within ' + NYM_INTERNAL_RECONNECT_GRACE_MS / 1000 + ' s')
    }, NYM_INTERNAL_RECONNECT_GRACE_MS)
  }

  const shutDownClient = async (client, purpose) => {
    try { await client.client.stop?.() } catch (error) { diagnostics.warn('nym', 'client stop failed', { purpose, error }) }
    try { client.terminate?.() } catch (error) { diagnostics.warn('nym', 'worker terminate failed', { purpose, error }) }
  }

  // Starts a Nym client under this node's clientId and waits for its gateway connection.
  // Events from a client that has since been replaced are ignored.
  const startClient = async (purpose, preferredGateway) => {
    const generation = ++clientGeneration
    const attemptStartedAt = performance.now()
    const { createNymMixnetClient } = await loadLibraries()
    const candidate = await createNymMixnetClient()
    let connectedAddress = null
    candidate.events.subscribeToConnected(event => { if (generation === clientGeneration) connectedAddress = event.args.address })
    candidate.events.subscribeToRawMessageReceivedEvent(event => { if (generation === clientGeneration) handleRawMessage(event) })
    candidate.events.subscribeToWymSocketState(event => { if (generation === clientGeneration) handleSocketState(event.args) })
    const startOptions = { clientId, nymApiUrl: NYM_API_URL, forceTls: true }
    if (NYM_CLIENT_OVERRIDES[mode]) startOptions.clientOverride = NYM_CLIENT_OVERRIDES[mode]
    if (preferredGateway) startOptions.preferredGateway = preferredGateway
    try {
      await candidate.client.start(startOptions)
    } catch (error) {
      await shutDownClient(candidate, purpose)
      throw error
    }
    diagnostics.info('nym', 'client started, waiting for gateway', { purpose, sameGatewayRequested: Boolean(preferredGateway), ms: Math.round(performance.now() - attemptStartedAt) })
    const deadline = Date.now() + NYM_CONNECT_ATTEMPT_TIMEOUT_MS
    while (!connectedAddress && Date.now() < deadline && generation === clientGeneration) await new Promise(resolve => setTimeout(resolve, 200))
    if (generation !== clientGeneration || node.state === 'stopped') {
      // The node was stopped while this client was connecting; do not leave it running.
      await shutDownClient(candidate, purpose)
      throw new Error('The Nym client was stopped while connecting.')
    }
    if (!connectedAddress) {
      diagnostics.warn('nym', 'no gateway connection within ' + NYM_CONNECT_ATTEMPT_TIMEOUT_MS / 1000 + ' s; discarding this client', { purpose, mode })
      await shutDownClient(candidate, purpose)
      throw new Error('Could not connect to the Nym network within ' + NYM_CONNECT_ATTEMPT_TIMEOUT_MS / 1000 + ' seconds.')
    }
    mixnetClient = candidate
    return { address: connectedAddress, ms: Math.round(performance.now() - attemptStartedAt) }
  }

  try {
    const { address } = await startClient('initial')
    node.address = address
  } catch (error) {
    // A first attempt that never connected leaves nothing worth keeping.
    stopHeartbeat()
    indexedDB.deleteDatabase(NYM_STORAGE_PREFIX + clientId)
    throw error
  }
  setState('connected')
  diagnostics.info('nym', 'connected', { address: redactNymAddress(node.address), ms: Math.round(performance.now() - startedAt) })

  // Replaces the Nym client, keeping this node's identity. Concurrent calls share one attempt.
  node.reconnect = reason => {
    if (node.state === 'stopped') return Promise.resolve(false)
    if (reconnectPromise) return reconnectPromise
    reconnectPromise = (async () => {
      const reconnectStartedAt = performance.now()
      setState('reconnecting')
      setNetworkStatus('connecting', 'Reconnecting to Nym')
      diagnostics.warn('nym', 'replacing the Nym client with the same identity', { reason })
      const previousClient = mixnetClient
      mixnetClient = null
      if (previousClient) await shutDownClient(previousClient, 'replaced')
      // The gateway is the part of the address after "@".
      const currentGateway = String(node.address).split('@')[1] || null
      for (let attempt = 1; node.state === 'reconnecting'; attempt += 1) {
        const keepGateway = Boolean(currentGateway) && attempt <= NYM_RECONNECT_SAME_GATEWAY_ATTEMPTS
        if (attempt === NYM_RECONNECT_SAME_GATEWAY_ATTEMPTS + 1) diagnostics.warn('nym', 'the current gateway did not accept ' + NYM_RECONNECT_SAME_GATEWAY_ATTEMPTS + ' reconnects; trying a new gateway, which changes the address')
        try {
          const { address, ms } = await startClient('reconnect', keepGateway ? currentGateway : null)
          node.counters.reconnects += 1
          const sameAddress = address === node.address
          diagnostics.info('nym', 'reconnected', { attempt, ms, totalMs: Math.round(performance.now() - reconnectStartedAt), sameAddress })
          if (!sameAddress) {
            diagnostics.warn('nym', 'the Nym address changed while reconnecting', { previous: redactNymAddress(node.address), current: redactNymAddress(address) })
            node.address = address
          }
          setState('connected')
          setNetworkStatus('connected', 'Connected to Nym')
          try { node.onReconnected?.({ sameAddress }) } catch (error) { diagnostics.error('nym', 'reconnect handler failed', error) }
          return true
        } catch (error) {
          const delayMs = Math.min(NYM_RECONNECT_MAX_DELAY_MS, 2000 * 2 ** (attempt - 1))
          diagnostics.warn('nym', 'reconnect attempt ' + attempt + ' failed; next try in ' + delayMs / 1000 + ' s', error)
          setNetworkStatus('failed', 'Nym unavailable, retrying')
          await new Promise(resolve => setTimeout(resolve, delayMs))
        }
      }
      return false
    })().finally(() => { reconnectPromise = null })
    return reconnectPromise
  }

  const countOutgoing = payload => {
    if (payload[0] !== MESSAGE_KIND_DATA) return
    node.counters.dataFramesOut += 1
    node.counters.dataBytesOut += payload.length
  }
  // Sends to a Nym address, attaching reply blocks so the other side can answer without
  // learning this client's address.
  node.send = async (payload, recipient) => {
    try {
      await waitUntilUsable()
      countOutgoing(payload)
      await mixnetClient.client.rawSend({ payload, recipient, replySurbs: RECIPIENT_REPLY_SURBS_PER_MESSAGE })
    } catch (error) {
      node.counters.sendFailures += 1
      diagnostics.error('nym', 'send failed', { to: redactNymAddress(recipient), bytes: payload.length, nodeState: node.state, error })
      throw error
    }
  }
  // Answers a message through the reply blocks that came with it. Only the tag is needed.
  node.reply = async (payload, senderTag) => {
    try {
      await waitUntilUsable()
      countOutgoing(payload)
      await mixnetClient.client.rawReply({ payload, senderTag })
    } catch (error) {
      node.counters.sendFailures += 1
      diagnostics.error('nym', 'reply failed', { replyTag: describeReplyTag(senderTag), bytes: payload.length, nodeState: node.state, error })
      throw error
    }
  }
  node.sendControl = (message, recipient) => {
    node.counters.controlOut += 1
    diagnostics.info('control', 'sending ' + message.kind, Object.assign(describeControlMessage(message), { to: redactNymAddress(recipient) }))
    return node.send(encodeControlMessage(message), recipient)
  }
  node.replyControl = (message, senderTag) => {
    node.counters.controlOut += 1
    diagnostics.info('control', 'replying ' + message.kind, Object.assign(describeControlMessage(message), { replyTag: describeReplyTag(senderTag) }))
    return node.reply(encodeControlMessage(message), senderTag)
  }
  // Test hook, reachable only through the ?faults=1 controls.
  node.closeGatewaySocketsForTest = async () => (mixnetClient ? mixnetClient.client.wymCloseGatewaySockets() : 0)
  node.stop = async () => {
    diagnostics.info('nym', 'stopping client', node.counters)
    setState('stopped')
    clearTimeout(socketGraceTimer)
    socketGraceTimer = null
    clientGeneration += 1
    for (const waiter of usableWaiters) clearTimeout(waiter.timer)
    usableWaiters = []
    if (mixnetClient) await shutDownClient(mixnetClient, 'stopped')
    mixnetClient = null
    // A stopped client's keys are never reused, so release its heartbeat and delete them now.
    stopHeartbeat()
    indexedDB.deleteDatabase(NYM_STORAGE_PREFIX + clientId)
  }
  return node
}

// One Nym client per page, started early so connecting overlaps with choosing files.
// getNymNode(mode) always resolves to a client running in that mode. Asking for a different
// mode chains a switch onto the current client: the switch waits for it to finish connecting,
// stops it, then starts the new one. Because each switch is chained to the previous promise,
// switching again while one is in progress can never stop the same client twice or leave
// two clients running.
let nymNodePromise = null
let nymNodeMode = null
function getNymNode (mode) {
  if (nymNodePromise && nymNodeMode === mode) return nymNodePromise
  const previousPromise = nymNodePromise
  nymNodeMode = mode
  setNetworkStatus('connecting', 'Connecting to Nym')
  const promise = (async () => {
    if (previousPromise) {
      const previous = await previousPromise.catch(() => null)
      if (previous) {
        diagnostics.info('nym', 'switching client', { from: previous.mode, to: mode })
        await previous.stop()
      }
    }
    // A fresh client usually reaches a gateway in 3 to 6 s. In testing, one client after a
    // mode switch never connected at all, while the next fresh client connected in 5 s, so
    // a stalled attempt is abandoned and retried with a new client instead of waiting.
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await createNymNode(mode)
      } catch (error) {
        if (attempt >= NYM_CONNECT_ATTEMPTS) throw error
        diagnostics.warn('nym', 'connection attempt ' + attempt + ' of ' + NYM_CONNECT_ATTEMPTS + ' failed; retrying', error)
      }
    }
  })().then(node => {
    if (nymNodePromise === promise) setNetworkStatus('connected', 'Connected to Nym')
    return node
  }, error => {
    if (nymNodePromise === promise) {
      setNetworkStatus('failed', 'Nym unavailable')
      nymNodePromise = null
      nymNodeMode = null
    }
    throw error
  })
  nymNodePromise = promise
  return promise
}

// ---------------------------------------------------------------------------
// Transport: an ordered byte stream over unordered Nym messages
// ---------------------------------------------------------------------------
function createLinkStreamClass () {
  const { Duplex } = libraries
  return class NymLinkStream extends Duplex {
    // route: { label, send(frame) } decides how frames reach the other side. The recipient
    // sends to the sender's address; the sender replies through the recipient's reply tag.
    constructor (route, linkIdBytes) {
      super()
      this.id = 'nym-link-' + bytesToHex(linkIdBytes) // WebTorrent's peer id for this connection
      this.connected = true // WebTorrent's WebRTC path treats the stream as already open
      this.route = route
      this.linkIdBytes = linkIdBytes
      this.nextOutgoingSequence = 0
      this.nextExpectedSequence = 0
      this.pendingFrames = new Map()
      this.openedAt = performance.now()
      // Transport counters, reported in the periodic snapshots.
      this.stats = { framesOut: 0, bytesOut: 0, framesIn: 0, bytesIn: 0, outOfOrder: 0, duplicates: 0, maxPending: 0, highestSequenceSeen: -1, firstFrameInAtMs: null }
      diagnostics.info('link', 'opened', { link: this.id.slice(9, 17), via: route.label })
      this.once('close', () => diagnostics.info('link', 'closed', Object.assign({ link: this.id.slice(9, 17) }, this.stats)))
    }

    _write (chunk, callback) {
      const bytes = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk)
      const maxBodyBytes = MAX_NYM_MESSAGE_BYTES - DATA_HEADER_BYTES
      const sends = []
      for (let offset = 0; offset < bytes.length; offset += maxBodyBytes) {
        const body = bytes.subarray(offset, offset + maxBodyBytes)
        const frame = new Uint8Array(DATA_HEADER_BYTES + body.length)
        frame[0] = MESSAGE_KIND_DATA
        frame.set(this.linkIdBytes, 1)
        new DataView(frame.buffer).setUint32(1 + LINK_ID_BYTES, this.nextOutgoingSequence++)
        frame.set(body, DATA_HEADER_BYTES)
        this.stats.framesOut += 1
        this.stats.bytesOut += body.length
        sends.push(this.route.send(frame))
      }
      Promise.all(sends).then(() => callback(null), error => {
        diagnostics.error('link', 'write failed', { link: this.id.slice(9, 17), error })
        callback(error)
      })
    }

    // Mixnet delivery is unordered: frames wait here until every earlier one has arrived.
    receiveFrame (frame) {
      if (this.destroyed) return
      const sequence = new DataView(frame.buffer, frame.byteOffset).getUint32(1 + LINK_ID_BYTES)
      this.stats.framesIn += 1
      this.stats.bytesIn += frame.length - DATA_HEADER_BYTES
      if (this.stats.firstFrameInAtMs === null) {
        this.stats.firstFrameInAtMs = Math.round(performance.now() - this.openedAt)
        diagnostics.info('link', 'first frame received', { link: this.id.slice(9, 17), afterMs: this.stats.firstFrameInAtMs })
      }
      if (sequence < this.stats.highestSequenceSeen) this.stats.outOfOrder += 1
      this.stats.highestSequenceSeen = Math.max(this.stats.highestSequenceSeen, sequence)
      if (sequence < this.nextExpectedSequence || this.pendingFrames.has(sequence)) {
        this.stats.duplicates += 1
        return
      }
      this.pendingFrames.set(sequence, frame.slice(DATA_HEADER_BYTES))
      this.stats.maxPending = Math.max(this.stats.maxPending, this.pendingFrames.size)
      while (this.pendingFrames.has(this.nextExpectedSequence)) {
        const body = this.pendingFrames.get(this.nextExpectedSequence)
        this.pendingFrames.delete(this.nextExpectedSequence)
        this.nextExpectedSequence += 1
        this.push(body)
      }
    }
  }
}

function createMemoryChunkStoreClass () {
  // Pieces stay in memory: nothing about the transfer is written to disk.
  return class MemoryChunkStore {
    constructor (chunkLength) { this.chunkLength = Number(chunkLength); this.chunks = new Map() }
    put (index, buffer, callback = () => {}) { this.chunks.set(index, new Uint8Array(buffer)); queueMicrotask(() => callback(null)) }
    get (index, options, callback) {
      if (typeof options === 'function') { callback = options; options = null }
      const chunk = this.chunks.get(index)
      if (!chunk) { queueMicrotask(() => callback(Object.assign(new Error('missing chunk'), { notFound: true }))); return }
      const offset = options?.offset ?? 0
      const length = options?.length ?? chunk.length - offset
      queueMicrotask(() => callback(null, chunk.subarray(offset, offset + length)))
    }
    close (callback = () => {}) { queueMicrotask(() => callback(null)) }
    destroy (callback = () => {}) { this.chunks.clear(); queueMicrotask(() => callback(null)) }
  }
}

/** Logs a torrent's lifecycle and each peer connection's BitTorrent-level events. */
function instrumentTorrent (torrent, role) {
  let lastProgressDecile = -1
  const tag = () => (torrent.infoHash ?? '').slice(0, 8)
  torrent.on('infoHash', () => diagnostics.info('torrent', role + ' infohash known', { infoHash: tag() }))
  torrent.on('metadata', () => diagnostics.info('torrent', role + ' metadata received', { pieces: torrent.pieces.length, pieceLength: torrent.pieceLength, encryptedBytes: torrent.length, files: torrent.files.length }))
  torrent.on('ready', () => diagnostics.info('torrent', role + ' ready', { infoHash: tag(), pieces: torrent.pieces.length, encryptedBytes: torrent.length }))
  torrent.on('done', () => diagnostics.info('torrent', role + ' all pieces verified', { downloaded: torrent.downloaded }))
  torrent.on('warning', warning => diagnostics.warn('torrent', role + ' warning', String(warning?.message ?? warning)))
  torrent.on('error', error => diagnostics.error('torrent', role + ' error', error))
  // Progress only means something for the downloading side; a seeder starts at 100%.
  if (role === 'receiver') {
    torrent.on('download', () => {
      const decile = Math.floor(torrent.progress * 10)
      if (decile > lastProgressDecile) {
        lastProgressDecile = decile
        diagnostics.info('torrent', role + ' progress ' + decile * 10 + '%', { downloaded: torrent.downloaded })
      }
    })
  }
  // WebTorrent emits 'wire' after the BitTorrent handshake has completed, so the peer id is
  // already known here and a 'handshake' listener would never fire.
  torrent.on('wire', wire => {
    const wireTag = String(wire.peerId ?? 'unknown').slice(0, 8)
    diagnostics.info('wire', role + ' wire attached after handshake', { peer: wireTag })
    wire.on('extended', extension => { if (extension === 'handshake') diagnostics.info('wire', role + ' extended handshake', { extensions: Object.keys(wire.peerExtendedHandshake?.m ?? {}) }) })
    wire.on('unchoke', () => diagnostics.info('wire', role + ' peer unchoked us'))
    wire.on('choke', () => diagnostics.info('wire', role + ' peer choked us'))
    wire.on('interested', () => diagnostics.info('wire', role + ' peer is interested'))
    wire.on('close', () => diagnostics.info('wire', role + ' wire closed', { peer: wireTag, downloaded: wire.downloaded, uploaded: wire.uploaded }))
  })
}

/**
 * Records transfer state every 5 s; returns a function that stops it. A snapshot identical
 * to the previous one is skipped (and counted), so an idle sender tab left open for hours
 * does not push the useful entries out of the 5000-entry log.
 */
function startSnapshots (role, getState) {
  let previousSerialized = null
  let unchangedSkipped = 0
  const timer = setInterval(() => {
    try {
      const state = getState()
      const serialized = diagnostics.safeStringify(state)
      if (serialized === previousSerialized) {
        unchangedSkipped += 1
        return
      }
      previousSerialized = serialized
      if (unchangedSkipped > 0) state.unchangedSnapshotsSkipped = unchangedSkipped
      unchangedSkipped = 0
      diagnostics.info('snapshot', role, state)
    } catch (error) {
      diagnostics.warn('snapshot', role + ' snapshot failed', error)
    }
  }, 5000)
  return () => clearInterval(timer)
}

function describeLinks (links) {
  return Array.from(links, link => Object.assign({ link: link.id.slice(9, 17), pending: link.pendingFrames.size, nextExpected: link.nextExpectedSequence }, link.stats))
}

function widenRequestWindow (torrent) {
  torrent.on('wire', wire => {
    const throughputMeter = wire.downloadSpeed
    // Recording calls pass a byte count; reading calls pass nothing. Only reads are scaled.
    wire.downloadSpeed = bytes => bytes === undefined ? throughputMeter() * REQUEST_WINDOW_MULTIPLIER : throughputMeter(bytes)
  })
}

// ---------------------------------------------------------------------------
// Share links
// ---------------------------------------------------------------------------
// v2 links carry the sender's network mode so the recipient's client runs with the same
// traffic settings: v2~<mode code>~<sender>~<infohash>~<key>~<salt>~<encrypted list>.
// v1 links (no mode field) are still accepted and treated as Balanced, which is what every
// v1 recipient used.
function buildShareLink (fields) {
  const fragment = [LINK_VERSION, LINK_MODE_CODES[fields.mode], fields.senderAddress, fields.infoHash, fields.keyB64Url, fields.saltB64Url, fields.encryptedListB64Url].join(LINK_SEPARATOR)
  const base = location.href.split('#')[0]
  return base + '#' + fragment
}

function parseShareLink (link) {
  const hashIndex = link.indexOf('#')
  if (hashIndex === -1) return null
  const parts = decodeURIComponent(link.slice(hashIndex + 1)).split(LINK_SEPARATOR)
  let mode
  if (parts[0] === 'v1' && parts.length === 6) {
    mode = 'balanced'
    parts.splice(1, 0, LINK_MODE_CODES.balanced)
  } else if (parts[0] === LINK_VERSION && parts.length === 7) {
    mode = Object.keys(LINK_MODE_CODES).find(name => LINK_MODE_CODES[name] === parts[1])
  }
  if (!mode || !/^[0-9a-f]{40}$/.test(parts[3])) return null
  return { linkVersion: parts[0], mode, senderAddress: parts[2], infoHash: parts[3], keyB64Url: parts[4], saltB64Url: parts[5], encryptedListB64Url: parts[6] }
}

// ---------------------------------------------------------------------------
// Screen wake lock
// ---------------------------------------------------------------------------
// While this tab is sending or receiving, a sleeping screen can suspend it and drop its Nym
// connection. Browsers release the lock whenever the tab is hidden, so it is requested again
// each time the tab becomes visible while it is still wanted.
const wakeLock = { wantedBy: new Set(), sentinel: null, refusalLogged: false }
async function acquireWakeLock (reason) {
  wakeLock.wantedBy.add(reason)
  if (!('wakeLock' in navigator)) {
    diagnostics.info('env', 'screen wake lock not supported by this browser')
    return
  }
  if (wakeLock.sentinel || document.visibilityState !== 'visible') return
  try {
    wakeLock.sentinel = await navigator.wakeLock.request('screen')
    diagnostics.info('env', 'screen wake lock acquired', { for: [...wakeLock.wantedBy] })
    wakeLock.sentinel.addEventListener('release', () => {
      wakeLock.sentinel = null
      diagnostics.info('env', 'screen wake lock released', { stillWanted: wakeLock.wantedBy.size > 0 })
    })
  } catch (error) {
    // Refusals repeat on every visibility change in a browser that does not allow the lock.
    if (!wakeLock.refusalLogged) diagnostics.warn('env', 'screen wake lock refused; the device may sleep during the transfer', error)
    wakeLock.refusalLogged = true
  }
}
function releaseWakeLock (reason) {
  wakeLock.wantedBy.delete(reason)
  if (wakeLock.wantedBy.size === 0 && wakeLock.sentinel) wakeLock.sentinel.release().catch(() => {})
}
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && wakeLock.wantedBy.size > 0 && !wakeLock.sentinel) acquireWakeLock([...wakeLock.wantedBy][0])
})

// ---------------------------------------------------------------------------
// Sender
// ---------------------------------------------------------------------------
// framesAwaitingLink: the mixnet reorders messages, so a receiver's first data frames can
// arrive before its "open" control message. They are held here until the link opens.
// closedLinkIds: links that were closed (finished, replaced or closed by the recipient). The same
// reordering can deliver their last frames afterwards; those are counted and dropped, not held.
// recipients: recipient id -> { linkIds }. The id is a random value each recipient chooses for its
// session and only shares with this sender, so a recipient that reconnects keeps its slot under
// the recipient limit. Like the link itself, it identifies a session, not a person.
const sendSession = { torrent: null, client: null, node: null, links: new Map(), framesAwaitingLink: new Map(), closedLinkIds: new Set(), lateFramesDropped: 0, recipients: new Map(), finished: new Set(), recipientLimit: 5, statsTimer: null, stopSnapshots: null, qrDataUrl: null, linkFields: null }
const FRAMES_AWAITING_LINK_TTL_MS = 60000

function routeSenderFrame (frame, senderTag) {
  const linkIdHex = bytesToHex(frame.subarray(1, 1 + LINK_ID_BYTES))
  const link = sendSession.links.get(linkIdHex)
  if (link) {
    // Keep answering through the newest tag the recipient used, and record any change: the
    // tag is expected to stay the same for one recipient's whole session.
    if (senderTag && senderTag !== link.route.senderTag) {
      diagnostics.warn('link', 'recipient reply tag changed', { link: linkIdHex.slice(0, 8), from: describeReplyTag(link.route.senderTag), to: describeReplyTag(senderTag) })
      link.route.senderTag = senderTag
    }
    link.receiveFrame(frame)
    return
  }
  if (sendSession.closedLinkIds.has(linkIdHex)) {
    sendSession.lateFramesDropped += 1
    return
  }
  const now = Date.now()
  for (const [staleId, entry] of sendSession.framesAwaitingLink) {
    if (now - entry.firstSeenAt > FRAMES_AWAITING_LINK_TTL_MS) {
      sendSession.framesAwaitingLink.delete(staleId)
      diagnostics.warn('link', 'discarded frames for a link that never opened', { link: staleId.slice(0, 8), frames: entry.frames.length })
    }
  }
  const entry = sendSession.framesAwaitingLink.get(linkIdHex) ?? { frames: [], firstSeenAt: now }
  if (entry.frames.length === 0) diagnostics.info('link', 'frame arrived before its open message; holding it', { link: linkIdHex.slice(0, 8) })
  entry.frames.push(frame.slice())
  sendSession.framesAwaitingLink.set(linkIdHex, entry)
}

function showView (viewId) {
  for (const id of ['view-choose', 'view-share', 'view-receive']) elementById(id).classList.toggle('hidden', id !== viewId)
}

function renderFileRows (listElement, files, options = {}) {
  listElement.replaceChildren(...files.map((file, index) => {
    const children = [
      createElement('i', { 'data-lucide': 'file' }),
      createElement('span', { className: 'file-name', text: file.name, title: file.name }),
      createElement('span', { className: 'file-size', text: formatBytes(file.size) })
    ]
    if (options.verified?.[index]) {
      children.push(createElement('span', { className: 'verified' }, [createElement('i', { 'data-lucide': 'check' }), 'Verified']))
    }
    if (options.onSave) {
      const saveButton = createElement('button', { className: 'button button-secondary', type: 'button', 'aria-label': 'Save ' + file.name }, [createElement('i', { 'data-lucide': 'download' }), 'Save'])
      saveButton.addEventListener('click', () => options.onSave(index))
      children.push(saveButton)
    }
    return createElement('li', { className: 'file-row' }, children)
  }))
  renderIcons()
}

async function startSharing (fileList) {
  const files = Array.from(fileList).filter(file => file.size > 0)
  if (files.length === 0) return
  const totalBytes = files.reduce((sum, file) => sum + file.size, 0)
  if (totalBytes > MAX_TOTAL_BYTES) {
    showChooseError('These files total ' + formatBytes(totalBytes) + '. The limit is ' + formatBytes(MAX_TOTAL_BYTES) + ', because everything is held in memory.')
    return
  }

  sendSession.recipientLimit = Number(elementById('recipient-limit').value)
  const mode = elementById('privacy-mode').value
  const shareStartedAt = performance.now()
  diagnostics.info('send', 'sharing started', { files: files.length, plaintextBytes: totalBytes, fileSizes: files.map(file => file.size), recipientLimit: sendSession.recipientLimit || 'none', mode })
  showView('view-share')
  renderFileRows(elementById('share-file-list'), files)
  setShareHeading('Encrypting', 'Encrypting ' + files.length + (files.length === 1 ? ' file' : ' files') + ' in your browser.')

  try {
    const nodePromise = getNymNode(mode)
    const { Keychain, WebTorrent } = await loadLibraries()
    const keychain = new Keychain()

    // Each file is encrypted separately; the list of real names, sizes and hashes is
    // encrypted with the metadata key and travels only inside the link.
    const encryptedFiles = []
    const fileDescriptions = []
    let processedBytes = 0
    for (const [index, file] of files.entries()) {
      const plaintext = new Uint8Array(await file.arrayBuffer())
      const plaintextHash = await sha256Hex(plaintext)
      const ciphertext = await readStreamToBytes(await keychain.encryptStream(new Response(plaintext).body))
      // Generic, zero-padded names keep the torrent's file order equal to the list order.
      encryptedFiles.push(new File([ciphertext], 'item-' + String(index).padStart(4, '0')))
      fileDescriptions.push({ name: file.name, type: file.type, size: file.size, sha256: plaintextHash })
      processedBytes += file.size
      elementById('encrypt-progress').style.width = Math.round((processedBytes / totalBytes) * 100) + '%'
    }
    const encryptedList = await keychain.encryptMeta(textEncoder.encode(JSON.stringify(fileDescriptions)))
    diagnostics.info('send', 'encrypted', { ms: Math.round(performance.now() - shareStartedAt), encryptedBytes: encryptedFiles.reduce((sum, file) => sum + file.size, 0), encryptedListBytes: encryptedList.length, plaintextHashPrefixes: fileDescriptions.map(description => description.sha256.slice(0, 8)) })

    setShareHeading('Connecting', 'Joining the Nym network.')
    sendSession.node = await nodePromise
    sendSession.mode = mode

    sendSession.client = new WebTorrent({ tracker: false, dht: false, lsd: false, webSeeds: false })
    sendSession.client.on('error', error => showShareError(error))
    const MemoryChunkStore = createMemoryChunkStoreClass()
    sendSession.torrent = await new Promise(resolve => {
      const torrent = sendSession.client.seed(encryptedFiles, {
        name: 'payload',
        private: true,
        pieceLength: PIECE_LENGTH_BYTES,
        store: MemoryChunkStore,
        // A random nonce makes the infohash unique even when the same files are shared twice.
        info: { nonce: bytesToHex(crypto.getRandomValues(new Uint8Array(16))) }
      }, resolve)
      instrumentTorrent(torrent, 'sender')
    })
    diagnostics.info('send', 'seeding', { infoHash: sendSession.torrent.infoHash.slice(0, 8), pieces: sendSession.torrent.pieces.length, pieceLength: sendSession.torrent.pieceLength })

    const saltBytes = Uint8Array.from(atob(keychain.saltB64), character => character.charCodeAt(0))
    sendSession.linkFields = {
      mode: sendSession.mode,
      senderAddress: sendSession.node.address,
      infoHash: sendSession.torrent.infoHash,
      keyB64Url: keychain.keyB64,
      saltB64Url: bytesToBase64Url(saltBytes),
      encryptedListB64Url: bytesToBase64Url(encryptedList)
    }
    const shareLink = buildShareLink(sendSession.linkFields)

    sendSession.node.onControl = (message, senderTag) => handleSenderControl(message, senderTag)
    sendSession.node.onData = (frame, senderTag) => routeSenderFrame(frame, senderTag)
    sendSession.node.onReconnected = ({ sameAddress }) => handleSenderReconnected(sameAddress)
    acquireWakeLock('sharing')

    elementById('share-link').value = shareLink
    sendSession.qrDataUrl = null
    elementById('encrypt-progress-track').classList.add('hidden')
    elementById('share-ready').classList.remove('hidden')
    setShareHeading('Ready to share', 'Send this link to the people you want to have the files.')
    diagnostics.info('send', 'link ready', { linkVersion: LINK_VERSION, mode: sendSession.mode, linkCharacters: shareLink.length, senderAddress: redactNymAddress(sendSession.node.address), totalMs: Math.round(performance.now() - shareStartedAt) })
    startSenderStats()
    sendSession.stopSnapshots = startSnapshots('sender', () => ({
      peers: sendSession.torrent?.numPeers,
      uploaded: sendSession.torrent?.uploaded,
      recipients: sendSession.recipients.size,
      finished: sendSession.finished.size,
      nymState: sendSession.node?.state,
      framesAwaitingLink: sendSession.framesAwaitingLink.size,
      lateFramesDropped: sendSession.lateFramesDropped,
      nym: sendSession.node?.counters,
      links: describeLinks(sendSession.links.values())
    }))
    window.addEventListener('beforeunload', warnBeforeLeaving)
    renderIcons()
  } catch (error) {
    showShareError(error)
  }
}

// Recipients announce themselves with "hello", then open a link for the transfer. Every answer
// goes back through the reply blocks attached to the recipient's message, identified by its
// reply tag, so the sender never learns where the recipient is. A message without a tag cannot
// be answered, and one without a recipient id cannot be counted; both are ignored.
function handleSenderControl (message, senderTag) {
  const torrent = sendSession.torrent
  if (!torrent) {
    diagnostics.warn('send', 'control message while not sharing', describeControlMessage(message))
    return
  }
  if (message.infoHash !== torrent.infoHash) {
    diagnostics.warn('send', 'control message for another share ignored', describeControlMessage(message))
    return
  }
  if (!senderTag) {
    diagnostics.warn('send', 'control message without reply blocks ignored', describeControlMessage(message))
    return
  }
  const recipientId = typeof message.recipientId === 'string' && RECIPIENT_ID_PATTERN.test(message.recipientId) ? message.recipientId : null
  if (!recipientId) {
    diagnostics.warn('send', 'control message without a recipient id ignored', describeControlMessage(message))
    return
  }
  const knownRecipient = sendSession.recipients.has(recipientId)
  const limitReached = sendSession.recipientLimit > 0 && sendSession.recipients.size >= sendSession.recipientLimit && !knownRecipient
  const linkId = typeof message.linkId === 'string' && /^[0-9a-f]{32}$/.test(message.linkId) ? message.linkId : null

  if (message.kind === 'hello') {
    sendSession.node.replyControl({ kind: limitReached ? 'refused' : 'available', infoHash: torrent.infoHash, reason: limitReached ? 'limit' : undefined }, senderTag).catch(() => {})
  } else if (message.kind === 'open' && linkId) {
    if (limitReached) {
      sendSession.node.replyControl({ kind: 'refused', infoHash: torrent.infoHash, reason: 'limit' }, senderTag).catch(() => {})
      return
    }
    if (sendSession.links.has(linkId) || sendSession.closedLinkIds.has(linkId)) {
      diagnostics.info('send', 'duplicate open ignored', { link: linkId.slice(0, 8) })
      return
    }
    const recipient = sendSession.recipients.get(recipientId) ?? { linkIds: new Set() }
    sendSession.recipients.set(recipientId, recipient)
    // A recipient reopening after a stall gets a fresh link; its old one is dead, so retire it
    // now in case the recipient's "close" message is still in flight or was lost.
    for (const previousLinkId of [...recipient.linkIds]) retireSenderLink(previousLinkId, 'replaced by a new link from the same recipient')
    const LinkStream = sendSession.LinkStream ?? (sendSession.LinkStream = createLinkStreamClass())
    const node = sendSession.node
    const route = {
      label: 'reply tag ' + describeReplyTag(senderTag),
      senderTag,
      send (frame) { return node.reply(frame, route.senderTag) }
    }
    const link = new LinkStream(route, hexToBytes(linkId))
    link.recipientId = recipientId
    sendSession.links.set(linkId, link)
    recipient.linkIds.add(linkId)
    const added = torrent.addPeer(link)
    diagnostics.info('send', 'recipient link added to torrent', { link: linkId.slice(0, 8), added, recipients: sendSession.recipients.size, returningRecipient: knownRecipient })
    const waiting = sendSession.framesAwaitingLink.get(linkId)
    if (waiting) {
      sendSession.framesAwaitingLink.delete(linkId)
      diagnostics.info('link', 'replaying held frames', { link: linkId.slice(0, 8), frames: waiting.frames.length })
      for (const frame of waiting.frames) link.receiveFrame(frame)
    }
  } else if (message.kind === 'close' && linkId) {
    if (sendSession.links.get(linkId)?.recipientId === recipientId) retireSenderLink(linkId, 'closed by the recipient')
  } else if (message.kind === 'complete') {
    sendSession.finished.add(recipientId)
    diagnostics.info('send', 'recipient finished', { finished: sendSession.finished.size, verified: message.verified })
    // The recipient has destroyed its side, but nothing travels back over the mixnet to tell
    // this link stream. Close it here so the wire, the Connected count and the logs settle.
    if (linkId && sendSession.links.get(linkId)?.recipientId === recipientId) retireSenderLink(linkId, 'recipient finished')
  } else {
    diagnostics.warn('send', 'unexpected control message', describeControlMessage(message))
  }
}

function retireSenderLink (linkId, reason) {
  const link = sendSession.links.get(linkId)
  if (!link) return
  sendSession.links.delete(linkId)
  sendSession.closedLinkIds.add(linkId)
  sendSession.recipients.get(link.recipientId)?.linkIds.delete(linkId)
  diagnostics.info('send', 'link retired', { link: linkId.slice(0, 8), reason })
  link.destroy()
}

// The node reconnects under the same identity, so the address normally stays the same and the
// link already shared keeps working. If it ever changes, the old link is dead: show a new one.
function handleSenderReconnected (sameAddress) {
  if (!sendSession.torrent || !sendSession.linkFields) return
  if (sameAddress) {
    diagnostics.info('send', 'reachable again at the same address; the shared link still works')
    hideShareNotice()
    return
  }
  sendSession.linkFields.senderAddress = sendSession.node.address
  const shareLink = buildShareLink(sendSession.linkFields)
  elementById('share-link').value = shareLink
  sendSession.qrDataUrl = null
  elementById('qr-image').classList.add('hidden')
  diagnostics.warn('send', 'share link replaced after the Nym address changed', { linkCharacters: shareLink.length })
  showShareNotice('Your Nym connection was replaced and the old link no longer works. Send this new link instead.')
}

function showShareNotice (text) {
  elementById('share-notice-text').textContent = text
  elementById('share-notice').classList.remove('hidden')
}
function hideShareNotice () {
  elementById('share-notice').classList.add('hidden')
}

function startSenderStats () {
  const meter = new RateMeter()
  clearInterval(sendSession.statsTimer)
  sendSession.statsTimer = setInterval(() => {
    const torrent = sendSession.torrent
    if (!torrent) return
    elementById('stat-connected').textContent = String(torrent.numPeers)
    elementById('stat-finished').textContent = String(sendSession.finished.size)
    elementById('stat-sent').textContent = formatBytes(torrent.uploaded)
    elementById('stat-upload').textContent = formatBytes(meter.update(torrent.uploaded)) + '/s'
  }, 1000)
}

function setShareHeading (title, subtitle) {
  elementById('share-title').textContent = title
  elementById('share-subtitle').textContent = subtitle
}

function showShareError (error) {
  diagnostics.error('send', 'sharing failed', error)
  setShareHeading('Something went wrong', error?.message ?? String(error))
  elementById('encrypt-progress-track').classList.add('hidden')
}

function showChooseError (text) {
  const dropZone = elementById('drop-zone')
  dropZone.querySelector('.muted').textContent = text
}

function warnBeforeLeaving (event) {
  event.preventDefault()
  event.returnValue = ''
}

async function stopSharing () {
  diagnostics.info('send', 'stopping', { uploaded: sendSession.torrent?.uploaded, recipients: sendSession.recipients.size, finished: sendSession.finished.size, links: describeLinks(sendSession.links.values()) })
  window.removeEventListener('beforeunload', warnBeforeLeaving)
  releaseWakeLock('sharing')
  hideShareNotice()
  clearInterval(sendSession.statsTimer)
  sendSession.stopSnapshots?.()
  if (sendSession.client) await new Promise(resolve => sendSession.client.destroy(resolve))
  if (sendSession.node) {
    sendSession.node.onControl = null
    sendSession.node.onData = null
    sendSession.node.onReconnected = null
  }
  Object.assign(sendSession, { torrent: null, client: null, links: new Map(), framesAwaitingLink: new Map(), closedLinkIds: new Set(), lateFramesDropped: 0, recipients: new Map(), finished: new Set(), qrDataUrl: null, stopSnapshots: null, linkFields: null })
  diagnostics.info('send', 'stopped')
  elementById('share-ready').classList.add('hidden')
  elementById('qr-image').classList.add('hidden')
  elementById('encrypt-progress-track').classList.remove('hidden')
  elementById('encrypt-progress').style.width = '0%'
  elementById('file-input').value = ''
  showView('view-choose')
}

// ---------------------------------------------------------------------------
// Receiver
// ---------------------------------------------------------------------------
// recipientId: random per receiving session; the sender counts it against the recipient limit
// and lets it reopen links after a stall. retiredLinkIds: links replaced after a stall, whose
// late frames are dropped. stall: the recovery state (see checkReceiverHealth).
const receiveSession = { link: null, keychain: null, files: null, client: null, torrent: null, node: null, linkStream: null, LinkStream: null, results: null, replyTimer: null, statsTimer: null, monitorTimer: null, recipientId: null, downloading: false, retiredLinkIds: new Set(), lateFramesDropped: 0, linkGeneration: 0, lastDataAt: 0, stall: null }

function newStallState () {
  return { stage: 'healthy', relinks: 0, senderChecks: 0, lastSenderCheckAt: 0, stalledAt: 0, relinkedAt: 0 }
}

async function openShareLink (linkText) {
  const link = parseShareLink(linkText)
  if (!link) {
    diagnostics.warn('receive', 'not a valid share link', { characters: linkText.length, hasHash: linkText.includes('#') })
    elementById('paste-input').setCustomValidity('This is not a Nym Share link.')
    elementById('paste-input').reportValidity()
    return
  }
  diagnostics.info('receive', 'opening link', { linkVersion: link.linkVersion, mode: link.mode, infoHash: link.infoHash.slice(0, 8), sender: redactNymAddress(link.senderAddress), linkCharacters: linkText.length })
  if (location.hash.slice(1) !== linkText.slice(linkText.indexOf('#') + 1)) history.replaceState(null, '', '#' + linkText.slice(linkText.indexOf('#') + 1))
  receiveSession.link = link
  showView('view-receive')

  try {
    const { Keychain } = await loadLibraries()
    receiveSession.keychain = new Keychain(link.keyB64Url, base64UrlToBytes(link.saltB64Url))
    // The file list is decrypted locally from the link; no network request is needed.
    receiveSession.files = JSON.parse(textDecoder.decode(await receiveSession.keychain.decryptMeta(base64UrlToBytes(link.encryptedListB64Url))))
    diagnostics.info('receive', 'file list decrypted from link', { files: receiveSession.files.length, fileSizes: receiveSession.files.map(file => file.size), plaintextHashPrefixes: receiveSession.files.map(file => String(file.sha256).slice(0, 8)) })
  } catch (error) {
    diagnostics.error('receive', 'file list could not be decrypted', error)
    setReceiveHeading('This link does not work', 'The key in the link could not decrypt the file list. Check that the whole link was copied.')
    showReceiveNotice('error', 'Decryption failed: ' + (error?.message ?? String(error)))
    return
  }

  const totalBytes = receiveSession.files.reduce((sum, file) => sum + file.size, 0)
  setReceiveHeading(receiveSession.files.length === 1 ? 'A file for you' : receiveSession.files.length + ' files for you', formatBytes(totalBytes) + ' in total. Checking whether the sender is online.')
  renderFileRows(elementById('receive-file-list'), receiveSession.files)

  // Run the client in the sender's mode. If this page already connected in another mode
  // (for example Balanced on load before a Maximum link was pasted), getNymNode switches it.
  elementById('receive-mode').textContent = 'Network mode: ' + MODE_LABELS[link.mode] + ', set by the sender.'
  try {
    receiveSession.node = await getNymNode(link.mode)
  } catch (error) {
    diagnostics.error('receive', 'could not join Nym', error)
    showReceiveNotice('error', error.message)
    return
  }
  receiveSession.recipientId = bytesToHex(crypto.getRandomValues(new Uint8Array(16)))
  receiveSession.node.onControl = (message, senderTag) => handleReceiverControl(message, senderTag)
  receiveSession.node.onData = frame => routeReceiverFrame(frame)
  receiveSession.helloSentAt = performance.now()
  // No return address: the sender answers through the reply blocks attached to this message.
  receiveSession.node.sendControl({ kind: 'hello', infoHash: link.infoHash, recipientId: receiveSession.recipientId }, link.senderAddress).catch(() => {})
  clearTimeout(receiveSession.replyTimer)
  receiveSession.replyTimer = setTimeout(() => {
    diagnostics.warn('receive', 'sender did not answer within ' + SENDER_REPLY_TIMEOUT_MS / 1000 + ' s')
    setReceiveHeading(elementById('receive-title').textContent, 'The sender did not answer.')
    showReceiveNotice('warning', 'The sender is not reachable. Their tab may be closed, or they stopped sharing.')
  }, SENDER_REPLY_TIMEOUT_MS)
}

function handleReceiverControl (message) {
  if (message.infoHash !== receiveSession.link?.infoHash) {
    diagnostics.warn('receive', 'control message for another share ignored', describeControlMessage(message))
    return
  }
  const replyMs = receiveSession.helloSentAt ? Math.round(performance.now() - receiveSession.helloSentAt) : null
  if (message.kind === 'available' && receiveSession.downloading) {
    // An answer to a sender check made during a stall: the sender is up, so open a fresh link.
    if (receiveSession.stall.stage === 'checking-sender') {
      diagnostics.info('receive', 'sender answered during a stall; opening a new link', { roundTripMs: replyMs, senderChecks: receiveSession.stall.senderChecks })
      receiveSession.stall.stage = 'relinked'
      receiveSession.stall.relinks += 1
      showReceiveNotice('warning', 'The sender is online again. Resuming the transfer.')
      openReceiverLink('sender answered after a stall')
    }
    return
  }
  if (message.kind === 'available') {
    clearTimeout(receiveSession.replyTimer)
    diagnostics.info('receive', 'sender is online', { roundTripMs: replyMs })
    hideReceiveNotice()
    elementById('receive-subtitle').textContent = 'The sender is online. Files arrive through the Nym mixnet.'
    elementById('start-download').disabled = false
  } else if (message.kind === 'refused') {
    clearTimeout(receiveSession.replyTimer)
    if (receiveSession.downloading) {
      receiveSession.downloading = false
      clearInterval(receiveSession.monitorTimer)
      releaseWakeLock('receiving')
    }
    diagnostics.warn('receive', 'sender refused', { reason: message.reason, roundTripMs: replyMs })
    elementById('start-download').disabled = true
    showReceiveNotice('error', message.reason === 'limit' ? 'The sender set a recipient limit, and it has been reached.' : 'The sender refused the connection.')
  } else {
    diagnostics.warn('receive', 'unexpected control message', describeControlMessage(message))
  }
}

async function startDownload () {
  const link = receiveSession.link
  const { WebTorrent } = await loadLibraries()
  elementById('start-download').disabled = true
  elementById('receive-progress-track').classList.remove('hidden')
  elementById('receive-stats').classList.remove('hidden')
  // The first ~10 s go to the BitTorrent handshake and metadata exchange over the mixnet.
  elementById('receive-subtitle').textContent = 'Connecting to the sender through the mixnet, then receiving the encrypted files.'

  receiveSession.downloadStartedAt = performance.now()
  diagnostics.info('receive', 'download started')
  receiveSession.client = new WebTorrent({ tracker: false, dht: false, lsd: false, webSeeds: false })
  receiveSession.client.on('error', error => {
    diagnostics.error('receive', 'webtorrent client error', error)
    showReceiveNotice('error', error.message)
  })
  const MemoryChunkStore = createMemoryChunkStoreClass()
  const torrent = receiveSession.client.add('magnet:?xt=urn:btih:' + link.infoHash, { store: MemoryChunkStore })
  receiveSession.torrent = torrent
  instrumentTorrent(torrent, 'receiver')
  widenRequestWindow(torrent)
  await new Promise(resolve => torrent.infoHash ? resolve() : torrent.once('infoHash', resolve))

  receiveSession.downloading = true
  receiveSession.stall = newStallState()
  openReceiverLink('download started')
  acquireWakeLock('receiving')
  clearInterval(receiveSession.monitorTimer)
  receiveSession.monitorTimer = setInterval(checkReceiverHealth, STALL_CHECK_INTERVAL_MS)
  receiveSession.stopSnapshots = startSnapshots('receiver', () => ({
    progress: Number(torrent.progress.toFixed(4)),
    downloaded: torrent.downloaded,
    hasMetadata: Boolean(torrent.metadata),
    peers: torrent.numPeers,
    requestsInFlight: torrent.wires.reduce((sum, wire) => sum + wire.requests.length, 0),
    peerChoking: torrent.wires.map(wire => wire.peerChoking),
    nymState: receiveSession.node.state,
    stall: Object.assign({ quietMs: Date.now() - receiveSession.lastDataAt, linkGeneration: receiveSession.linkGeneration, lateFramesDropped: receiveSession.lateFramesDropped }, receiveSession.stall),
    nym: receiveSession.node.counters,
    links: describeLinks([receiveSession.linkStream])
  }))

  const totalBytes = receiveSession.files.reduce((sum, file) => sum + file.size, 0)
  const meter = new RateMeter()
  receiveSession.statsTimer = setInterval(() => {
    const received = Math.min(totalBytes, Math.round(torrent.progress * totalBytes))
    const speed = meter.update(torrent.downloaded)
    elementById('receive-progress').style.width = (torrent.progress * 100).toFixed(1) + '%'
    elementById('stat-received').textContent = formatBytes(received)
    elementById('stat-download').textContent = formatBytes(speed) + '/s'
    elementById('stat-eta').textContent = torrent.length && speed > 0 ? formatDuration((torrent.length - torrent.downloaded) / speed) : 'Estimating'
  }, 1000)

  torrent.once('done', () => finishDownload(torrent))
}

// Opens a link to the sender and adds it to the torrent as a peer. A link that already exists
// (one that stalled) is retired first: the sender is told to close it, and any of its frames
// still in the mixnet are dropped on arrival. WebTorrent keeps every verified piece and
// re-requests whatever the old link had in flight.
function openReceiverLink (reason) {
  const node = receiveSession.node
  const link = receiveSession.link
  const previous = receiveSession.linkStream
  if (previous) {
    const previousLinkId = bytesToHex(previous.linkIdBytes)
    previous.retiredByReceiver = true
    receiveSession.retiredLinkIds.add(previousLinkId)
    node.sendControl({ kind: 'close', infoHash: link.infoHash, linkId: previousLinkId, recipientId: receiveSession.recipientId }, link.senderAddress).catch(() => {})
    previous.destroy()
  }
  receiveSession.LinkStream = receiveSession.LinkStream ?? createLinkStreamClass()
  const linkIdBytes = crypto.getRandomValues(new Uint8Array(LINK_ID_BYTES))
  receiveSession.linkGeneration += 1
  const linkStream = new receiveSession.LinkStream({ label: redactNymAddress(link.senderAddress), send: frame => node.send(frame, link.senderAddress) }, linkIdBytes)
  receiveSession.linkStream = linkStream
  receiveSession.lastDataAt = Date.now()
  receiveSession.stall.relinkedAt = Date.now()
  // WebTorrent closes a peer whose BitTorrent handshake never arrives (after about 25 s), and a
  // link can also fail on a write error. Either way, waiting longer on it cannot help.
  linkStream.once('close', () => {
    if (linkStream.retiredByReceiver || receiveSession.linkStream !== linkStream || !receiveSession.downloading) return
    diagnostics.warn('receive', 'the link closed before the transfer finished', { linkGeneration: receiveSession.linkGeneration, framesIn: linkStream.stats.framesIn })
    checkSenderDuringStall('the link closed')
  })
  node.sendControl({ kind: 'open', infoHash: link.infoHash, linkId: bytesToHex(linkIdBytes), recipientId: receiveSession.recipientId }, link.senderAddress).catch(() => {})
  const added = receiveSession.torrent.addPeer(receiveSession.linkStream)
  diagnostics.info('receive', 'link added to torrent', { added, reason, linkGeneration: receiveSession.linkGeneration })
}

function routeReceiverFrame (frame) {
  const linkIdHex = bytesToHex(frame.subarray(1, 1 + LINK_ID_BYTES))
  const current = receiveSession.linkStream
  if (current && linkIdHex === bytesToHex(current.linkIdBytes)) {
    const deliveredBefore = current.nextExpectedSequence
    current.receiveFrame(frame)
    if (current.nextExpectedSequence > deliveredBefore) noteReceiverData()
    return
  }
  if (receiveSession.retiredLinkIds.has(linkIdHex)) {
    receiveSession.lateFramesDropped += 1
    return
  }
  diagnostics.warn('link', 'data frame for an unknown link dropped', { link: linkIdHex.slice(0, 8), bytes: frame.length })
}

function noteReceiverData () {
  receiveSession.lastDataAt = Date.now()
  const stall = receiveSession.stall
  if (!stall || stall.stage === 'healthy') return
  diagnostics.info('receive', 'transfer resumed', { pausedMs: Date.now() - stall.stalledAt, relinks: stall.relinks, senderChecks: stall.senderChecks, linkGeneration: receiveSession.linkGeneration })
  stall.stage = 'healthy'
  hideReceiveNotice()
  elementById('receive-subtitle').textContent = 'Receiving the encrypted files through the Nym mixnet.'
}

// Runs every STALL_CHECK_INTERVAL_MS while downloading. While this page's own Nym client is
// reconnecting, the node handles recovery and the stall clock is not acted on.
function checkReceiverHealth () {
  if (!receiveSession.downloading || !receiveSession.stall) return
  const node = receiveSession.node
  if (node.state !== 'connected') return
  const stall = receiveSession.stall
  const now = Date.now()
  const quietMs = now - receiveSession.lastDataAt
  const torrent = receiveSession.torrent
  const transferState = () => ({
    quietSeconds: Math.round(quietMs / 1000),
    progress: Number(torrent.progress.toFixed(4)),
    hasMetadata: Boolean(torrent.metadata),
    requestsInFlight: torrent.wires.reduce((sum, wire) => sum + wire.requests.length, 0),
    linkGeneration: receiveSession.linkGeneration
  })

  if (stall.stage === 'healthy' && quietMs >= STALL_RELINK_AFTER_MS) {
    stall.stage = 'relinked'
    stall.stalledAt = receiveSession.lastDataAt
    stall.relinks += 1
    diagnostics.warn('receive', 'no data for ' + Math.round(quietMs / 1000) + ' s; opening a new link', transferState())
    showReceiveNotice('warning', 'The transfer paused. Reconnecting to the sender.')
    openReceiverLink('stalled')
    return
  }
  if (stall.stage !== 'healthy' && now - stall.relinkedAt >= STALL_SENDER_CHECK_AFTER_RELINK_MS && now - stall.lastSenderCheckAt >= STALL_SENDER_CHECK_INTERVAL_MS) {
    checkSenderDuringStall('no data on the new link', transferState())
  }
}

// Asks the sender whether it is online. Its "available" answer opens a fresh link (see
// handleReceiverControl). Repeated every STALL_SENDER_CHECK_INTERVAL_MS until data flows again.
function checkSenderDuringStall (reason, details = {}) {
  const stall = receiveSession.stall
  if (!stall) return
  if (stall.stage === 'healthy') stall.stalledAt = receiveSession.lastDataAt
  stall.stage = 'checking-sender'
  stall.lastSenderCheckAt = Date.now()
  stall.senderChecks += 1
  diagnostics.warn('receive', 'checking whether the sender is online', Object.assign({ reason, senderChecks: stall.senderChecks }, details))
  showReceiveNotice('warning', 'Waiting for the sender. Their tab may be closed, asleep or offline. This page keeps trying.')
  receiveSession.helloSentAt = performance.now()
  receiveSession.node.sendControl({ kind: 'hello', infoHash: receiveSession.link.infoHash, recipientId: receiveSession.recipientId }, receiveSession.link.senderAddress).catch(() => {})
}

async function finishDownload (torrent) {
  receiveSession.downloading = false
  clearInterval(receiveSession.monitorTimer)
  clearInterval(receiveSession.statsTimer)
  receiveSession.stopSnapshots?.()
  releaseWakeLock('receiving')
  hideReceiveNotice()
  const transferSeconds = (performance.now() - receiveSession.downloadStartedAt) / 1000
  diagnostics.info('receive', 'transfer complete', {
    seconds: Number(transferSeconds.toFixed(1)),
    encryptedBytes: torrent.length,
    averageKBps: Number((torrent.length / 1000 / transferSeconds).toFixed(1)),
    links: describeLinks([receiveSession.linkStream]),
    relinks: receiveSession.stall.relinks,
    senderChecks: receiveSession.stall.senderChecks,
    lateFramesDropped: receiveSession.lateFramesDropped,
    nym: receiveSession.node.counters
  })
  elementById('receive-progress').style.width = '100%'
  elementById('receive-subtitle').textContent = 'Decrypting and checking the files.'
  try {
    // Torrent files are named item-0000, item-0001 ...; sort to match the decrypted list.
    const torrentFiles = [...torrent.files].sort((left, right) => left.name.localeCompare(right.name))
    const results = []
    for (const [index, description] of receiveSession.files.entries()) {
      const decryptStartedAt = performance.now()
      const ciphertext = new Uint8Array(await (await torrentFiles[index].blob()).arrayBuffer())
      const plaintext = await readStreamToBytes(await receiveSession.keychain.decryptStream(new Response(ciphertext).body))
      const plaintextHash = await sha256Hex(plaintext)
      const verified = plaintext.length === description.size && plaintextHash === description.sha256
      diagnostics.log(verified ? 'info' : 'error', 'receive', 'file ' + (index + 1) + ' of ' + receiveSession.files.length + (verified ? ' verified' : ' FAILED verification'), {
        encryptedBytes: ciphertext.length,
        plaintextBytes: plaintext.length,
        expectedBytes: description.size,
        hashPrefix: plaintextHash.slice(0, 8),
        expectedHashPrefix: String(description.sha256).slice(0, 8),
        decryptMs: Math.round(performance.now() - decryptStartedAt)
      })
      results.push({ blob: new Blob([plaintext], { type: description.type || 'application/octet-stream' }), verified })
    }
    receiveSession.results = results
    const allVerified = results.every(result => result.verified)
    receiveSession.node.sendControl({ kind: 'complete', infoHash: receiveSession.link.infoHash, linkId: bytesToHex(receiveSession.linkStream.linkIdBytes), recipientId: receiveSession.recipientId, verified: allVerified }, receiveSession.link.senderAddress).catch(() => {})

    setReceiveHeading(allVerified ? 'Ready to save' : 'Integrity check failed', allVerified ? 'Every file was decrypted and matches what the sender shared.' : 'At least one file does not match what the sender shared. Do not trust it.')
    renderFileRows(elementById('receive-file-list'), receiveSession.files, { verified: results.map(result => result.verified), onSave: saveFile })
    elementById('save-all').classList.toggle('hidden', results.length < 2)
    elementById('start-download').classList.add('hidden')
    elementById('stat-eta').textContent = 'Done'
    // The 1 s stats timer stopped at 'done', so its last reading is stale; show the final total.
    elementById('stat-received').textContent = formatBytes(receiveSession.files.reduce((sum, file) => sum + file.size, 0))
    await new Promise(resolve => receiveSession.client.destroy(resolve))
    diagnostics.info('receive', 'done', { allVerified, totalSeconds: Number(((performance.now() - receiveSession.downloadStartedAt) / 1000).toFixed(1)) })
  } catch (error) {
    diagnostics.error('receive', 'decryption failed', error)
    showReceiveNotice('error', 'Decryption failed: ' + (error?.message ?? String(error)))
  }
}

function saveFile (index) {
  const result = receiveSession.results?.[index]
  if (!result) return
  diagnostics.info('receive', 'save requested', { file: index + 1, bytes: result.blob.size, verified: result.verified })
  const url = URL.createObjectURL(result.blob)
  const anchor = createElement('a', { href: url, download: receiveSession.files[index].name })
  document.body.append(anchor)
  anchor.click()
  anchor.remove()
  setTimeout(() => URL.revokeObjectURL(url), 60000)
}

async function saveAllFiles () {
  for (let index = 0; index < (receiveSession.results?.length ?? 0); index += 1) {
    saveFile(index)
    await new Promise(resolve => setTimeout(resolve, 400)) // browsers drop rapid back-to-back downloads
  }
}

function setReceiveHeading (title, subtitle) {
  elementById('receive-title').textContent = title
  elementById('receive-subtitle').textContent = subtitle
}
function showReceiveNotice (tone, text) {
  const notice = elementById('receive-notice')
  notice.dataset.tone = tone
  elementById('receive-notice-text').textContent = text
  notice.classList.remove('hidden')
}
function hideReceiveNotice () {
  elementById('receive-notice').classList.add('hidden')
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------
function wireUserInterface () {
  const dropZone = elementById('drop-zone')
  const fileInput = elementById('file-input')
  dropZone.addEventListener('click', () => fileInput.click())
  dropZone.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); fileInput.click() } })
  dropZone.addEventListener('dragover', event => { event.preventDefault(); dropZone.dataset.dragging = 'true' })
  dropZone.addEventListener('dragleave', () => { dropZone.dataset.dragging = 'false' })
  dropZone.addEventListener('drop', event => {
    event.preventDefault()
    dropZone.dataset.dragging = 'false'
    startSharing(event.dataTransfer.files)
  })
  fileInput.addEventListener('change', () => startSharing(fileInput.files))

  elementById('privacy-mode').addEventListener('change', event => {
    diagnostics.info('nym', 'network mode changed', { mode: event.target.value })
    getNymNode(event.target.value).catch(error => diagnostics.error('nym', 'mode switch failed', error))
  })

  elementById('copy-link').addEventListener('click', async () => {
    const label = elementById('copy-link').querySelector('span')
    try {
      await navigator.clipboard.writeText(elementById('share-link').value)
      label.textContent = 'Copied'
    } catch (error) {
      elementById('share-link').select()
      label.textContent = 'Press Cmd+C'
    }
    setTimeout(() => { label.textContent = 'Copy' }, 2000)
  })

  elementById('toggle-qr').addEventListener('click', async () => {
    const image = elementById('qr-image')
    if (!sendSession.qrDataUrl) {
      const { QRCode } = await loadLibraries()
      sendSession.qrDataUrl = await QRCode.toDataURL(elementById('share-link').value, { errorCorrectionLevel: 'L', margin: 1, width: 400 })
      image.src = sendSession.qrDataUrl
    }
    image.classList.toggle('hidden')
  })

  elementById('stop-sharing').addEventListener('click', () => stopSharing())
  elementById('paste-form').addEventListener('submit', event => {
    event.preventDefault()
    elementById('paste-input').setCustomValidity('')
    openShareLink(elementById('paste-input').value.trim())
  })
  elementById('start-download').addEventListener('click', () => startDownload().catch(error => {
    diagnostics.error('receive', 'download could not start', error)
    showReceiveNotice('error', error.message)
  }))
  elementById('save-all').addEventListener('click', () => saveAllFiles())

  // Diagnostics panel
  elementById('diagnostics').addEventListener('toggle', () => diagnostics.scheduleRender())
  elementById('copy-logs').addEventListener('click', async () => {
    const label = elementById('copy-logs').querySelector('span')
    const text = diagnostics.exportText()
    try {
      await navigator.clipboard.writeText(text)
      label.textContent = 'Copied'
    } catch (error) {
      // The async clipboard can be refused (for example on file:// pages). Copy the complete
      // log through a temporary text field instead of the on-screen panel, which only shows
      // the most recent lines.
      const field = createElement('textarea', { readonly: '', 'aria-hidden': 'true' })
      field.value = text
      field.style.position = 'fixed'
      field.style.opacity = '0'
      document.body.append(field)
      field.select()
      const copied = document.execCommand('copy')
      field.remove()
      label.textContent = copied ? 'Copied' : 'Copy failed, use Save log'
      if (!copied) diagnostics.warn('diag', 'clipboard unavailable', error)
    }
    setTimeout(() => { label.textContent = 'Copy log' }, 2500)
  })
  elementById('save-logs').addEventListener('click', () => {
    const url = URL.createObjectURL(new Blob([diagnostics.exportText()], { type: 'text/plain' }))
    const anchor = createElement('a', { href: url, download: 'nym-share-log-' + SESSION_ID + '.txt' })
    document.body.append(anchor)
    anchor.click()
    anchor.remove()
    setTimeout(() => URL.revokeObjectURL(url), 60000)
  })
  elementById('clear-logs').addEventListener('click', () => {
    diagnostics.entries.length = 0
    diagnostics.info('diag', 'log cleared')
  })
}

diagnostics.info('diag', 'page loaded', { session: SESSION_ID, pageVersion: PAGE_VERSION, faultInjection: FAULT_INJECTION_ENABLED })
if (FAULT_INJECTION_ENABLED) {
  // Test controls for recovery. Each action is logged so test logs show exactly what was injected.
  window.nymShareFaults = {
    dropIncomingData (seconds) {
      faultInjection.dropIncomingDataUntil = Date.now() + seconds * 1000
      diagnostics.warn('fault', 'dropping all incoming data frames', { seconds })
    },
    async closeGatewaySockets () {
      const node = await nymNodePromise
      const closed = await node.closeGatewaySocketsForTest()
      diagnostics.warn('fault', 'closed this client\'s gateway connections', { closed })
      return closed
    },
    async replaceNymClient () {
      const node = await nymNodePromise
      diagnostics.warn('fault', 'replacing the Nym client on request')
      return node.reconnect('fault injection')
    }
  }
  diagnostics.warn('fault', 'fault injection controls enabled through ?faults=1')
}
logEnvironment()
wireUserInterface()
renderIcons()
if (location.hash.length > 1) {
  diagnostics.info('diag', 'link found in address bar; opening receive view')
  openShareLink(location.href)
} else {
  // Connect while the sender is still choosing files.
  getNymNode(elementById('privacy-mode').value).catch(error => diagnostics.error('nym', 'initial connection failed', error))
}

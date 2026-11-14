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
  ChevronDown as ChevronDownIcon,
  ChevronLeft as ChevronLeftIcon,
  CircleAlert as CircleAlertIcon,
  CircleCheck as CircleCheckIcon,
  CircleSlash as CircleSlashIcon,
  CircleX as CircleXIcon,
  ClipboardCopy as ClipboardCopyIcon,
  Copy as CopyIcon,
  Download as DownloadIcon,
  Eraser as EraserIcon,
  EyeOff as EyeOffIcon,
  File as FileIcon,
  FileDown as FileDownIcon,
  Gauge as GaugeIcon,
  Hourglass as HourglassIcon,
  Info as InfoIcon,
  LoaderCircle as LoaderCircleIcon,
  Lock as LockIcon,
  QrCode as QrCodeIcon,
  RotateCw as RotateCwIcon,
  Share as ShareIcon,
  ShieldCheck as ShieldCheckIcon,
  TriangleAlert as TriangleAlertIcon,
  Upload as UploadIcon,
  UserRound as UserRoundIcon
} from 'lucide'

// PAGE_VERSION is replaced at build time with the version in package.json.
/* global PAGE_VERSION */

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const NYM_API_URL = 'https://validator.nymtech.net/api'

// Nym pacing per network mode. Each tick of the client's main stream sends one packet, real or
// cover, so this sets the steady packet rate whether or not anything is being sent. "maximum" keeps
// Nym's default of one packet every 20 ms (with loop cover, 55 a second, about 1.1 Mbps up).
// "balanced" asks for one every 11 ms: with loop cover about 96 a second, about 1.9 Mbps up, which
// sits inside the range NymVPN users can choose with its Mixnet Tuning (0.7 to 2 Mbps). It used to
// ask for 2 ms, which no browser delivered: desktop Brave and Chromium capped it at about 135 a
// second and Brave with DevTools open at about 66, so the rate on the wire depended on the browser
// and machine. At 11 ms desktop browsers deliver what is asked. Per-hop mixing delays stay at
// Nym's defaults in both modes.
const NYM_CLIENT_OVERRIDES = {
  balanced: { traffic: { messageSendingAverageDelayMs: 11 } },
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
// The three thresholds above are minimums. Between two Brave windows on one machine, messages took
// 8 to 19 s each way, so a fixed 20 s would relink in a loop. Each threshold is raised to a
// multiple of the slowest recent round trip to the sender, up to STALL_THRESHOLD_CAP_MS.
const STALL_RELINK_ROUND_TRIPS = 3
const STALL_SENDER_CHECK_ROUND_TRIPS = 2
const STALL_THRESHOLD_CAP_MS = 180000
const ROUND_TRIP_SAMPLES_KEPT = 5
const STALL_CHECK_INTERVAL_MS = 2000
const RECIPIENT_ID_PATTERN = /^[0-9a-f]{32}$/

// Fault injection for testing recovery, enabled only when the page is opened with ?faults=1.
// It adds window.nymShareFaults; nothing else changes.
const FAULT_INJECTION_ENABLED = new URLSearchParams(location.search).get('faults') === '1'
const faultInjection = { dropIncomingDataUntil: 0, incomingDelayMs: 0, hideAcknowledgementsUntil: 0, stallConnects: 0, rememberFaultFailures: false }
const PIECE_LENGTH_BYTES = 65536
const MAX_TOTAL_BYTES = 500 * 1000 * 1000 // everything is held in memory on both sides
const SENDER_REPLY_TIMEOUT_MS = 60000
// Control messages can be delayed or lost in the mixnet (one "hello" took almost two minutes in
// testing), so the recipient repeats "hello" until the sender answers: every
// HELLO_RETRY_INTERVAL_MS at first, then every HELLO_RETRY_SLOW_INTERVAL_MS after the first
// minute. Messages slower than SLOW_CONTROL_MESSAGE_MS are logged as warnings.
const HELLO_RETRY_INTERVAL_MS = 10000
const HELLO_RETRY_SLOW_INTERVAL_MS = 30000
const SLOW_CONTROL_MESSAGE_MS = 10000
const LINK_VERSION = 'v2'
const LINK_MODE_CODES = { balanced: 'b', maximum: 'm' }
const MODE_LABELS = { balanced: 'Balanced', maximum: 'Maximum privacy' }
// The network mode is a page-wide setting, remembered in this browser so the next visit starts
// in it and never connects in one mode only to restart in another.
const MODE_STORAGE_KEY = 'nym-share-network-mode'
const DEFAULT_MODE = 'balanced'
// Data used per hour while connected, upload plus download, from gateway traffic measured in
// Brave and Chromium on macOS: Maximum 1.1 up + 0.7 down Mbps. Balanced at 11 ms is estimated from
// its packet rate (96 a second, 1.9 up) with the same download share as measured in both modes
// (about 0.65 of upload), 1.25 down. The share view shows these until this tab has measured its own rate.
const ESTIMATED_GIGABYTES_PER_HOUR = { balanced: 1.4, maximum: 0.8 }
// With nothing to send or receive, the page disconnects from Nym after this long without user
// activity, and reconnects on the next click, key press or return to the tab.
const NYM_IDLE_DISCONNECT_MS = 5 * 60 * 1000
// A recipient stops asking an unresponsive sender after RECEIVER_GIVE_UP_MS before the download,
// or after RECEIVER_STALL_GIVE_UP_MS of a stalled download, and offers Try again instead.
const RECEIVER_GIVE_UP_MS = 3 * 60 * 1000
const RECEIVER_STALL_GIVE_UP_MS = 5 * 60 * 1000
// How long Stop sharing waits for its "stopped" messages to be handed to the Nym client.
const STOP_NOTICE_WAIT_MS = 3000
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
  ChevronDown: ChevronDownIcon,
  ChevronLeft: ChevronLeftIcon,
  CircleAlert: CircleAlertIcon,
  CircleCheck: CircleCheckIcon,
  CircleSlash: CircleSlashIcon,
  CircleX: CircleXIcon,
  ClipboardCopy: ClipboardCopyIcon,
  Copy: CopyIcon,
  Download: DownloadIcon,
  Eraser: EraserIcon,
  EyeOff: EyeOffIcon,
  File: FileIcon,
  FileDown: FileDownIcon,
  Gauge: GaugeIcon,
  Hourglass: HourglassIcon,
  Info: InfoIcon,
  LoaderCircle: LoaderCircleIcon,
  Lock: LockIcon,
  QrCode: QrCodeIcon,
  RotateCw: RotateCwIcon,
  Share: ShareIcon,
  ShieldCheck: ShieldCheckIcon,
  TriangleAlert: TriangleAlertIcon,
  Upload: UploadIcon,
  UserRound: UserRoundIcon
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
// The header pill shows one of these states. "paused" means the page disconnected on purpose
// after NYM_IDLE_DISCONNECT_MS without activity, to save data; it reconnects on the next action.
const NETWORK_STATUS_TEXT = {
  connecting: { text: 'Connecting', title: 'Joining the Nym mixnet.' },
  reconnecting: { text: 'Reconnecting', title: 'The connection to the Nym mixnet dropped. Reconnecting.' },
  switching: { text: 'Reconnecting', title: 'This gateway was not delivering incoming messages. Moving to another one.' },
  connected: { text: 'Connected', title: 'Connected to the Nym mixnet.' },
  paused: { text: 'Paused', title: 'Disconnected after 5 minutes without activity, to save data. It reconnects when you use the page.' },
  failed: { text: 'Offline', title: 'Could not reach the Nym mixnet.' }
}
function setNetworkStatus (state) {
  const description = NETWORK_STATUS_TEXT[state] ?? NETWORK_STATUS_TEXT.connecting
  const pill = elementById('network-status')
  pill.dataset.state = state === 'reconnecting' ? 'connecting' : state
  pill.title = description.title
  elementById('network-status-text').textContent = description.text
}

// ---------------------------------------------------------------------------
// Nym node: one mixnet client, routing control messages and data frames
// ---------------------------------------------------------------------------
// Every control message carries the sender's wall-clock time so the log can show how long it
// spent in the mixnet. Across two machines the figure includes their clock difference.
function encodeControlMessage (message) {
  const json = textEncoder.encode(JSON.stringify(Object.assign({ sentAt: Date.now() }, message)))
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
  if (typeof message?.attempt === 'number') description.attempt = message.attempt
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
// Most connects took 5 to 7 s in testing, one took 18.8 s, and attempts cut off at 20 s were
// followed by retries that connected in 6 to 7 s, so a slow attempt gets 30 s before it is replaced.
const NYM_CONNECT_ATTEMPT_TIMEOUT_MS = 30000
// A connect that is visibly progressing is not abandoned at 30 s: in one log the gateway
// registration took 22 s and its working connection opened 8 s before the cut-off. The deadline
// moves to NYM_CONNECT_ACTIVITY_GRACE_MS after the latest gateway socket event, up to
// NYM_CONNECT_ATTEMPT_MAX_MS in total.
const NYM_CONNECT_ACTIVITY_GRACE_MS = 15000
const NYM_CONNECT_ATTEMPT_MAX_MS = 60000
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
// Gateway traffic measurement (wymGatewayTraffic in build/nym-reply-patch.mjs). Nym's client
// defaults, from common/client-core/config-types: one packet (real or cover) every 20 ms on
// average in the main Poisson stream, plus one loop cover packet every 200 ms. The expected
// rate for a mode is the sum of both streams. Samples are taken every 10 s; busy windows are
// logged each sample, idle windows every 60 s (the first one after connecting after 10 s), so an
// idle sender tab adds about one entry a minute.
const NYM_DEFAULT_MESSAGE_STREAM_DELAY_MS = 20
const NYM_DEFAULT_LOOP_COVER_DELAY_MS = 200
const GATEWAY_TRAFFIC_SAMPLE_INTERVAL_MS = 10000
const GATEWAY_TRAFFIC_IDLE_LOG_INTERVAL_MS = 60000
// Incoming-path health, from the gateway test (README, "Gateway choice and health"). Of 23
// gateways that connected, 8 were broken or very slow at connect time, 4 of them scoring 0.96 to
// 0.99, and one more got worse during its run:
// - Acknowledgements: every packet sent, real or cover, earns one back through this client's
//   gateway. In the first 8 s after connecting, healthy gateways returned 0.83 to 1.00 per packet
//   sent and broken or slow ones 0.09 to 0.61; over the next 20 s healthy ones held 0.89 to 1.03,
//   broken ones 0.12 to 0.35, the one getting worse 0.58, and slow ones caught up (0.75 to 1.19).
// - Messages to its own address: healthy gateways returned them in 0.4 to 2.3 s; slow ones took
//   3.1 to 17 s or lost them, and broken ones lost every one.
// So the first check, HEALTH_FIRST_CHECK_MS after connecting, needs at least
// HEALTH_FIRST_CHECK_ACK_MINIMUM acknowledgements per packet sent and HEALTH_PROBES messages to
// itself with a median round trip of at most HEALTH_PROBE_MAX_MS (a lost one counts as infinite).
// Later, a connected client is reported degraded after HEALTH_CONFIRMING_WINDOWS 10 s samples in a
// row below HEALTH_STEADY_ACK_MINIMUM. That bound is lower than the first check's because, while
// a transfer runs, acknowledgements for real data come back through the other side's gateway.
// Samples with fewer than HEALTH_MIN_PACKETS_PER_WINDOW packets sent are too small to judge.
const HEALTH_FIRST_CHECK_MS = 8000
const HEALTH_FIRST_CHECK_ACK_MINIMUM = 0.75
const HEALTH_ACK_GRACE_MS = 1500
const HEALTH_PROBES = 3
const HEALTH_PROBE_SPACING_MS = 300
const HEALTH_PROBE_TIMEOUT_MS = 7000
const HEALTH_PROBE_MAX_MS = 3000
const HEALTH_STEADY_ACK_MINIMUM = 0.6
const HEALTH_CONFIRMING_WINDOWS = 2
const HEALTH_MIN_PACKETS_PER_WINDOW = 200
// Acknowledgements trail their packets by about a second, and right after a connect the first check
// already covers the incoming path, so ongoing checks ignore samples that began within this long
// of the latest connect.
const HEALTH_SETTLE_MS = 10000
// A healthy connect makes visible progress every 1 to 2 s: the registration connection opens 1.4
// to 3 s after the client starts and closes about a second later, the working connection opens
// about 1.5 s after that, and the client reports connected about 0.8 s later (gateway test). A
// connect with no gateway connection event for this long is abandoned for another gateway: in
// testing, one gateway took 21 s to open its first connection (making a move take 45 s), and
// another registered but never opened its working connection, holding a start for 30 s.
const GATEWAY_STALL_TIMEOUT_MS = 8000
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

// ---------------------------------------------------------------------------
// Gateway choice
// ---------------------------------------------------------------------------
// Nym's API publishes every entry gateway with a performance score from Nym's own probes. Left to
// itself, the Nym client picks uniformly at random among gateways scoring 50 % or more. In the
// gateway test, 6 of 8 gateways scoring below 0.95 failed to connect or failed the health check,
// against 4 of 16 scoring 0.95 or more, and 97 % of browser-usable gateways score at least
// GATEWAY_MINIMUM_PERFORMANCE. The score lowers the odds of a bad gateway; the health check
// (below) catches the rest. So the page fetches the list once per page load (from the same Nym
// API server the client contacts anyway), keeps gateways that browsers can reach over secure
// WebSockets and that score at least the minimum, and picks one uniformly at random. Choosing at
// random, rather than the fastest or a fixed list, keeps users of this page spread across the
// whole network, where they are indistinguishable from other Nym users. Gateways this page has
// already tried are skipped, so a switch never lands on the gateway it is leaving.
// The client's own minimum-score setting is not used for this: it also removes gateways from the
// client's view of the network, which would make anyone on a lower-scoring gateway unreachable.
const GATEWAY_DIRECTORY_URL = NYM_API_URL + '/v1/unstable/nym-nodes/skimmed/entry-gateways/all'
const GATEWAY_MINIMUM_PERFORMANCE = 0.95
const GATEWAY_DIRECTORY_TIMEOUT_MS = 8000
const GATEWAY_DIRECTORY_MAX_AGE_MS = 30 * 60 * 1000
const gatewayDirectory = { promise: null, fetchedAt: 0, triedThisPage: new Set() }

/** The gateway part of a Nym address (after the @), or null. */
function gatewayOfAddress (address) {
  return String(address ?? '').split('@')[1] || null
}

/** Resolves to [{ identity, performance }] for every gateway a browser can use, or [] on failure. */
function loadGatewayDirectory () {
  if (gatewayDirectory.promise && performance.now() - gatewayDirectory.fetchedAt < GATEWAY_DIRECTORY_MAX_AGE_MS) return gatewayDirectory.promise
  const startedAt = performance.now()
  gatewayDirectory.fetchedAt = startedAt
  gatewayDirectory.promise = (async () => {
    const abortController = new AbortController()
    const timer = setTimeout(() => abortController.abort(), GATEWAY_DIRECTORY_TIMEOUT_MS)
    try {
      const response = await fetch(GATEWAY_DIRECTORY_URL, { signal: abortController.signal, credentials: 'omit', referrerPolicy: 'no-referrer' })
      if (!response.ok) throw new Error('Nym API answered ' + response.status)
      const body = await response.json()
      const nodes = body?.nodes?.data ?? body?.data ?? body
      if (!Array.isArray(nodes)) throw new Error('unexpected gateway list format')
      // Pages are served over https, so only gateways with a secure WebSocket port are reachable.
      const gateways = nodes
        .filter(node => typeof node?.ed25519_identity_pubkey === 'string' && node.entry?.hostname && node.entry?.wss_port)
        .map(node => ({ identity: node.ed25519_identity_pubkey, performance: Number(node.performance) }))
        .filter(gateway => Number.isFinite(gateway.performance))
      const eligible = gateways.filter(gateway => gateway.performance >= GATEWAY_MINIMUM_PERFORMANCE).length
      diagnostics.info('nym', 'gateway list loaded', { ms: Math.round(performance.now() - startedAt), browserUsable: gateways.length, atOrAboveMinimum: eligible, minimumPerformance: GATEWAY_MINIMUM_PERFORMANCE })
      return gateways
    } catch (error) {
      diagnostics.warn('nym', 'gateway list unavailable; the Nym client will choose a gateway itself', { ms: Math.round(performance.now() - startedAt), error })
      gatewayDirectory.promise = null
      return []
    } finally {
      clearTimeout(timer)
    }
  })()
  return gatewayDirectory.promise
}

// Gateways that failed the health check or stalled while connecting in this browser are skipped for
// GATEWAY_FAILURE_MEMORY_MS. In testing, the same gateway failed every time it was drawn, across two
// days, while its published score moved from 0.94 to 0.95. Only failures are remembered: returning
// to a gateway that worked would tie visits together, while leaving a few gateways out of a random
// draw does not. Failures caused by the ?faults=1 controls are not remembered unless asked for.
const GATEWAY_FAILURE_MEMORY_KEY = 'nym-share-failed-gateways'
const GATEWAY_FAILURE_MEMORY_MS = 24 * 60 * 60 * 1000
const GATEWAY_FAILURE_MEMORY_LIMIT = 50

/** Identity -> time of failure, for failures within GATEWAY_FAILURE_MEMORY_MS. */
function readGatewayFailures () {
  try {
    const stored = JSON.parse(localStorage.getItem(GATEWAY_FAILURE_MEMORY_KEY) ?? '{}') ?? {}
    const now = Date.now()
    return Object.fromEntries(Object.entries(stored).filter(([identity, failedAt]) => typeof identity === 'string' && Number.isFinite(failedAt) && now - failedAt < GATEWAY_FAILURE_MEMORY_MS))
  } catch (error) {
    return {}
  }
}

function rememberGatewayFailure (gateway, reason) {
  if (!gateway?.identity) return
  const failures = readGatewayFailures()
  failures[gateway.identity] = Date.now()
  // Keep the most recent failures only, so the list cannot grow without bound.
  const kept = Object.entries(failures).sort((left, right) => right[1] - left[1]).slice(0, GATEWAY_FAILURE_MEMORY_LIMIT)
  try {
    localStorage.setItem(GATEWAY_FAILURE_MEMORY_KEY, JSON.stringify(Object.fromEntries(kept)))
  } catch (error) {
    // Storage can be unavailable (private modes); the gateway is still skipped for this page.
  }
  diagnostics.info('nym', 'gateway remembered as failed for ' + GATEWAY_FAILURE_MEMORY_MS / 3600000 + ' hours', Object.assign({ reason, rememberedFailures: kept.length }, describeGateway(gateway)))
}

/** Uniform random integer in [0, upperBound) from the browser's cryptographic generator. */
function randomIndex (upperBound) {
  const limit = Math.floor(0x100000000 / upperBound) * upperBound
  const value = new Uint32Array(1)
  do {
    crypto.getRandomValues(value)
  } while (value[0] >= limit) // rejection sampling keeps every index equally likely
  return value[0] % upperBound
}

/**
 * Picks a gateway at random among those scoring at least minimumPerformance that this page has
 * not tried yet, and marks it tried. Returns { identity, performance } or null, in which case the
 * Nym client chooses by itself. The bounds let the gateway test sample particular score bands.
 */
async function chooseGateway ({ minimumPerformance = GATEWAY_MINIMUM_PERFORMANCE, maximumPerformance = Infinity, skipRecentFailures = true } = {}) {
  const gateways = await loadGatewayDirectory()
  const recentFailures = skipRecentFailures ? readGatewayFailures() : {}
  const inBand = gateways.filter(gateway => gateway.performance >= minimumPerformance && gateway.performance < maximumPerformance && !gatewayDirectory.triedThisPage.has(gateway.identity))
  const candidates = inBand.filter(gateway => recentFailures[gateway.identity] === undefined)
  if (candidates.length < inBand.length) diagnostics.info('nym', 'skipping gateways that failed in this browser recently', { skipped: inBand.length - candidates.length })
  if (candidates.length === 0) return null
  const chosen = candidates[randomIndex(candidates.length)]
  gatewayDirectory.triedThisPage.add(chosen.identity)
  return chosen
}

/** A gateway for the log: the first characters of its identity and its published score. */
function describeGateway (gateway) {
  if (!gateway?.identity) return null
  return { gateway: gateway.identity.slice(0, 6) + '...', score: gateway.performance ?? 'not listed' }
}

/** One connect step as a short line for the log, for example "2210 ms gateway socket open (took 180 ms)". */
function describeConnectStep (step) {
  switch (step.event) {
    case 'fetched': return step.atMs + ' ms ' + step.target + ' ' + step.status + ' (took ' + (step.atMs - step.startedAtMs) + ' ms)'
    case 'fetch failed': return step.atMs + ' ms ' + step.target + ' failed (after ' + (step.atMs - step.startedAtMs) + ' ms)'
    case 'gateway socket open': return step.atMs + ' ms gateway socket open (took ' + (step.atMs - step.openingAtMs) + ' ms)'
    case 'gateway socket closed': return step.atMs + ' ms gateway socket closed, code ' + step.code + ' (lived ' + (step.atMs - step.openingAtMs) + ' ms)'
    default: return step.atMs + ' ms ' + step.event
  }
}

/** The published score of a gateway, or null when it is not in the list. */
async function gatewayPerformance (identity) {
  const gateways = await loadGatewayDirectory()
  return gateways.find(gateway => gateway.identity === identity)?.performance ?? null
}

// A Nym node is one Nym identity (clientId) for the life of the page. The Nym client behind it
// can be replaced: if the gateway connection is lost and the Nym client does not restore it
// within NYM_INTERNAL_RECONNECT_GRACE_MS, the node starts a new client with the same clientId.
// The keys and gateway registration stored under that id are reused, so the address in an
// existing share link stays valid and messages the gateway held meanwhile are delivered.
// Sends made while the client is being replaced wait for it (up to NYM_SEND_WAIT_MS).
async function createNymNode (mode, abortSignal, { gatewayBand = null, rememberFailures = true } = {}) {
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
    gateway: null, // { identity, performance } of the gateway in use, when known
    health: { state: 'checking', acknowledgementReturn: null, failedWindows: 0, checks: 0 },
    onHealthChange: null,
    healthSwitches: 0,
    counters: { dataFramesIn: 0, dataBytesIn: 0, dataFramesOut: 0, dataBytesOut: 0, controlIn: 0, controlOut: 0, sendFailures: 0, unknownMessages: 0, gatewayDisconnects: 0, reconnects: 0, faultDroppedFrames: 0 }
  }
  // Only the page's current node drives the header status; a node being replaced stays quiet.
  const reportNetworkStatus = state => { if (currentNymNode === node) setNetworkStatus(state) }
  let mixnetClient = null
  let clientGeneration = 0
  let usableWaiters = []
  let socketGraceTimer = null
  let socketLostAt = 0
  let lastSocketActivityAt = 0
  let reconnectPromise = null

  // ---- Gateway traffic measurement ------------------------------------------------------------
  // Every GATEWAY_TRAFFIC_SAMPLE_INTERVAL_MS the worker's cumulative counters are read and the
  // difference to the previous reading becomes one sample. A sample is "busy" when any data or
  // control message crossed the mixnet in it, otherwise "idle". Consecutive samples of the same
  // phase are merged into a window that is logged as one 'gateway traffic' entry, and running
  // per-phase totals are kept so every entry also carries the averages so far.
  const streamDelayMs = NYM_CLIENT_OVERRIDES[mode]?.traffic?.messageSendingAverageDelayMs ?? NYM_DEFAULT_MESSAGE_STREAM_DELAY_MS
  const expectedPacketsOutPerSecond = 1000 / streamDelayMs + 1000 / NYM_DEFAULT_LOOP_COVER_DELAY_MS
  const createTrafficTotals = () => ({ milliseconds: 0, packetsOut: 0, bytesOut: 0, packetsIn: 0, bytesIn: 0, acknowledgementsIn: 0, textMessagesOut: 0, textMessagesIn: 0, hiddenSamples: 0, samples: 0 })
  const gatewayTrafficTotals = { idle: createTrafficTotals(), busy: createTrafficTotals() }
  let gatewayTrafficBaseline = null
  let gatewayTrafficWindow = null
  let gatewayTrafficSampleInFlight = false
  let idleWindowsLoggedSinceConnect = 0

  const addTrafficTotals = (target, source) => {
    for (const key of Object.keys(target)) target[key] += source[key]
  }
  const describeTrafficRates = totals => {
    const seconds = totals.milliseconds / 1000
    if (seconds <= 0) return null
    return {
      seconds: Math.round(seconds),
      packetsOutPerSecond: Math.round(totals.packetsOut / seconds * 10) / 10,
      megabitsOutPerSecond: Math.round(totals.bytesOut * 8 / seconds / 1e4) / 100,
      averagePacketBytesOut: totals.packetsOut > 0 ? Math.round(totals.bytesOut / totals.packetsOut) : null,
      packetsInPerSecond: Math.round(totals.packetsIn / seconds * 10) / 10,
      megabitsInPerSecond: Math.round(totals.bytesIn * 8 / seconds / 1e4) / 100,
      acknowledgementsPerPacketOut: totals.packetsOut > 0 ? Math.round(totals.acknowledgementsIn / totals.packetsOut * 100) / 100 : null,
      percentOfExpectedOut: Math.round(totals.packetsOut / seconds / expectedPacketsOutPerSecond * 100),
      tabHiddenSamples: totals.hiddenSamples,
      samples: totals.samples
    }
  }
  // Combined upload and download rate measured so far, in megabits per second, or null before
  // the first 10 s sample. The share view turns it into data per hour.
  node.measuredMegabitsPerSecond = () => {
    const idle = gatewayTrafficTotals.idle
    const busy = gatewayTrafficTotals.busy
    const seconds = (idle.milliseconds + busy.milliseconds) / 1000
    if (seconds <= 0) return null
    return (idle.bytesOut + idle.bytesIn + busy.bytesOut + busy.bytesIn) * 8 / seconds / 1e6
  }
  node.describeGatewayTraffic = () => ({
    mode,
    expectedPacketsOutPerSecond: Math.round(expectedPacketsOutPerSecond * 10) / 10,
    idle: describeTrafficRates(gatewayTrafficTotals.idle),
    busy: describeTrafficRates(gatewayTrafficTotals.busy)
  })

  const flushGatewayTrafficWindow = () => {
    const finishedWindow = gatewayTrafficWindow
    gatewayTrafficWindow = null
    if (!finishedWindow || finishedWindow.totals.samples === 0) return
    addTrafficTotals(gatewayTrafficTotals[finishedWindow.phase], finishedWindow.totals)
    if (finishedWindow.phase === 'idle') idleWindowsLoggedSinceConnect += 1
    diagnostics.info('wire', 'gateway traffic', Object.assign(
      { phase: finishedWindow.phase },
      describeTrafficRates(finishedWindow.totals),
      { textMessagesOut: finishedWindow.totals.textMessagesOut, textMessagesIn: finishedWindow.totals.textMessagesIn, averagesSoFar: node.describeGatewayTraffic() }
    ))
  }

  // Readings from an earlier client (a replaced worker starts its counters at zero) or taken
  // while the node was not connected are never subtracted from each other.
  const sampleGatewayTraffic = async () => {
    if (gatewayTrafficSampleInFlight) return
    if (node.state !== 'connected' || !mixnetClient) {
      flushGatewayTrafficWindow()
      gatewayTrafficBaseline = null
      idleWindowsLoggedSinceConnect = 0
      return
    }
    gatewayTrafficSampleInFlight = true
    const generation = clientGeneration
    try {
      const reading = await mixnetClient.client.wymGatewayTraffic()
      if (generation !== clientGeneration || node.state !== 'connected') return
      const messageCounts = node.counters.dataFramesIn + node.counters.dataFramesOut + node.counters.controlIn + node.counters.controlOut
      const baseline = gatewayTrafficBaseline
      gatewayTrafficBaseline = { generation, reading, messageCounts, takenAt: performance.now() }
      if (!baseline || baseline.generation !== generation || reading.binaryMessagesOut < baseline.reading.binaryMessagesOut) return
      const phase = messageCounts !== baseline.messageCounts ? 'busy' : 'idle'
      const sample = {
        milliseconds: reading.sampledAtMs - baseline.reading.sampledAtMs,
        packetsOut: reading.binaryMessagesOut - baseline.reading.binaryMessagesOut,
        bytesOut: reading.binaryBytesOut - baseline.reading.binaryBytesOut,
        packetsIn: reading.binaryMessagesIn - baseline.reading.binaryMessagesIn,
        bytesIn: reading.binaryBytesIn - baseline.reading.binaryBytesIn,
        // Test only (?faults=1): pretend no acknowledgements came back, as on a broken gateway.
        acknowledgementsIn: faultInjection.hideAcknowledgementsUntil > Date.now() ? 0 : reading.acknowledgementsIn - baseline.reading.acknowledgementsIn,
        textMessagesOut: reading.textMessagesOut - baseline.reading.textMessagesOut,
        textMessagesIn: reading.textMessagesIn - baseline.reading.textMessagesIn,
        hiddenSamples: document.visibilityState === 'hidden' ? 1 : 0,
        samples: 1
      }
      evaluateHealth(sample, baseline.takenAt)
      if (gatewayTrafficWindow && gatewayTrafficWindow.phase !== phase) flushGatewayTrafficWindow()
      if (!gatewayTrafficWindow) gatewayTrafficWindow = { phase, totals: createTrafficTotals() }
      addTrafficTotals(gatewayTrafficWindow.totals, sample)
      const logAfterMs = phase === 'busy' || idleWindowsLoggedSinceConnect === 0 ? GATEWAY_TRAFFIC_SAMPLE_INTERVAL_MS : GATEWAY_TRAFFIC_IDLE_LOG_INTERVAL_MS
      if (gatewayTrafficWindow.totals.milliseconds >= logAfterMs) flushGatewayTrafficWindow()
    } catch (error) {
      diagnostics.warn('wire', 'gateway traffic sample failed', error)
    } finally {
      gatewayTrafficSampleInFlight = false
    }
  }
  const gatewayTrafficTimer = setInterval(sampleGatewayTraffic, GATEWAY_TRAFFIC_SAMPLE_INTERVAL_MS)

  // ---- Incoming-path health -------------------------------------------------------------------
  let healthWaiters = []
  let firstHealthCheckTimer = null
  const setHealth = (state, details) => {
    const previous = node.health.state
    Object.assign(node.health, { state }, details)
    if (state !== 'checking') {
      const waiters = healthWaiters
      healthWaiters = []
      for (const waiter of waiters) waiter()
    }
    if (state === 'degraded' && previous !== 'degraded' && rememberFailures && (faultInjection.hideAcknowledgementsUntil <= Date.now() || faultInjection.rememberFaultFailures)) {
      rememberGatewayFailure(node.gateway, 'failed the health check')
    }
    if (state !== previous) {
      diagnostics.log(state === 'degraded' ? 'warn' : 'info', 'nym', 'incoming path ' + state, { acknowledgementsPerPacketOut: node.health.acknowledgementReturn, roundTripsToSelfMs: node.health.probeMs, checks: node.health.checks, gateway: describeGateway(node.gateway) })
      try { node.onHealthChange?.(node.health) } catch (error) { diagnostics.error('nym', 'health handler failed', error) }
    }
  }
  // The first check after a connect collects two results, an acknowledgement sample and the
  // round trips of messages sent to itself, and decides once both are in.
  let firstCheck = null
  const concludeFirstCheck = () => {
    if (!firstCheck || firstCheck.acknowledgementReturn === null || firstCheck.probeMs === null) return
    const { acknowledgementReturn, probeMs } = firstCheck
    firstCheck = null
    const medianProbeMs = median(probeMs.map(value => value ?? Infinity))
    const passed = acknowledgementReturn >= HEALTH_FIRST_CHECK_ACK_MINIMUM && medianProbeMs <= HEALTH_PROBE_MAX_MS
    setHealth(passed ? 'healthy' : 'degraded', { acknowledgementReturn, probeMs, failedWindows: 0, checks: 1 })
  }
  let healthSettledAt = 0
  const evaluateHealth = (sample, sampleStartedAt) => {
    if (node.health.state === 'degraded' || sample.packetsOut < HEALTH_MIN_PACKETS_PER_WINDOW) return
    if (sampleStartedAt < healthSettledAt) return
    const acknowledgementReturn = Math.round(sample.acknowledgementsIn / sample.packetsOut * 100) / 100
    if (node.health.state === 'checking') return // the first check takes its own readings
    const passed = acknowledgementReturn >= HEALTH_STEADY_ACK_MINIMUM
    const checks = node.health.checks + 1
    const failedWindows = passed ? 0 : node.health.failedWindows + 1
    if (passed) {
      Object.assign(node.health, { acknowledgementReturn, failedWindows, checks })
    } else if (failedWindows >= HEALTH_CONFIRMING_WINDOWS) {
      setHealth('degraded', { acknowledgementReturn, failedWindows, checks })
    } else {
      Object.assign(node.health, { acknowledgementReturn, failedWindows, checks })
      diagnostics.warn('nym', 'few acknowledgements came back; checking again', { acknowledgementsPerPacketOut: acknowledgementReturn, failedWindows })
    }
  }
  // Starts a fresh check for the client now in use: a baseline traffic reading right away, three
  // messages to itself, and a first verdict HEALTH_FIRST_CHECK_MS later instead of waiting for
  // the next 10 s sample.
  const beginHealthCheck = () => {
    setHealth('checking', { acknowledgementReturn: null, probeMs: null, failedWindows: 0, checks: 0 })
    clearTimeout(firstHealthCheckTimer)
    const thisCheck = { acknowledgementReturn: null, probeMs: null }
    firstCheck = thisCheck
    healthSettledAt = performance.now() + HEALTH_SETTLE_MS
    // A new client means new counters and possibly a new gateway: close the logged traffic window
    // so no window mixes two gateways.
    flushGatewayTrafficWindow()
    gatewayTrafficBaseline = null
    sampleGatewayTraffic()
    // Its own readings, exactly HEALTH_FIRST_CHECK_MS apart, so the regular 10 s samples cannot
    // shorten the window (acknowledgements trail their packets by about a second).
    const generation = clientGeneration
    const startReading = mixnetClient.client.wymGatewayTraffic().catch(() => null)
    // Packets are counted over HEALTH_FIRST_CHECK_MS and their acknowledgements over
    // HEALTH_ACK_GRACE_MS longer, so the ones still in flight when the window closes are not
    // missed. Without the grace period healthy gateways read 0.73 to 0.76 in Balanced, where more
    // packets are in flight at any moment, against 0.83 to 1.00 in Maximum.
    const readNow = () => (mixnetClient && generation === clientGeneration ? mixnetClient.client.wymGatewayTraffic().catch(() => null) : Promise.resolve(null))
    firstHealthCheckTimer = setTimeout(async () => {
      const packetsEnd = await readNow()
      firstHealthCheckTimer = setTimeout(async () => {
        const start = await startReading
        const acknowledgementsEnd = await readNow()
        if (firstCheck !== thisCheck || !start || !packetsEnd || !acknowledgementsEnd) return
        const packetsOut = packetsEnd.binaryMessagesOut - start.binaryMessagesOut
        const acknowledgements = faultInjection.hideAcknowledgementsUntil > Date.now() ? 0 : acknowledgementsEnd.acknowledgementsIn - start.acknowledgementsIn
        thisCheck.acknowledgementReturn = packetsOut > 0 ? Math.round(acknowledgements / packetsOut * 100) / 100 : 0
        concludeFirstCheck()
      }, HEALTH_ACK_GRACE_MS)
    }, HEALTH_FIRST_CHECK_MS)
    Promise.all(Array.from({ length: HEALTH_PROBES }, (unused, index) =>
      new Promise(resolve => setTimeout(resolve, index * HEALTH_PROBE_SPACING_MS))
        .then(() => node.probeSelf(HEALTH_PROBE_TIMEOUT_MS))
        .catch(() => null)
    )).then(probeMs => {
      if (firstCheck !== thisCheck) return
      thisCheck.probeMs = probeMs
      concludeFirstCheck()
    })
  }
  /** Resolves once the first check has a verdict, or after timeoutMs, whichever is first. */
  node.waitForHealthVerdict = timeoutMs => {
    if (node.health.state !== 'checking') return Promise.resolve(node.health.state)
    return new Promise(resolve => {
      const timer = setTimeout(() => {
        healthWaiters = healthWaiters.filter(entry => entry !== waiter)
        resolve('checking')
      }, timeoutMs)
      const waiter = () => { clearTimeout(timer); resolve(node.health.state) }
      healthWaiters.push(waiter)
    })
  }

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

  const pendingProbes = new Map()
  // Logs when each network step of the latest connect happened, relative to the moment its Nym
  // client was created: Nym API fetches, gateway sockets opening, open and closed, and connected.
  const logConnectSteps = purpose => {
    const connectedAfterMs = Math.round(performance.now() - lastClientStartedAt)
    mixnetClient?.client.wymConnectTimeline().then(timeline => {
      node.lastConnectSteps = { purpose, connectedAfterMs, timeline }
      diagnostics.info('nym', 'connect steps', { purpose, connectedAfterMs, steps: timeline.map(describeConnectStep) })
    }).catch(error => diagnostics.warn('nym', 'connect steps unavailable', error))
  }
  node.waitUntilUsable = waitUntilUsable
  // senderTag is set when the message carried reply blocks (see build/nym-reply-patch.mjs),
  // and null for replies, which carry none.
  const handleRawMessage = event => {
    // Test only: hold every incoming message to imitate a slow mixnet path (?faults=1).
    if (faultInjection.incomingDelayMs > 0 && !event.faultDelayed) {
      setTimeout(() => handleRawMessage(Object.assign({}, event, { faultDelayed: true })), faultInjection.incomingDelayMs)
      return
    }
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
    // A message this client sent to itself (gateway test): settle it and stop here.
    if (message?.kind === 'probe' && typeof message.nonce === 'string' && pendingProbes.has(message.nonce)) {
      pendingProbes.get(message.nonce)()
      return
    }
    const transitMs = typeof message?.sentAt === 'number' ? Date.now() - message.sentAt : null
    diagnostics.log(transitMs !== null && transitMs > SLOW_CONTROL_MESSAGE_MS ? 'warn' : 'info', 'control', 'received ' + message?.kind, Object.assign(describeControlMessage(message), { transitMs, replyTag: describeReplyTag(senderTag) }))
    try {
      node.onControl?.(message, senderTag)
    } catch (error) {
      diagnostics.error('control', 'handler failed for ' + message?.kind, error)
    }
  }

  // The Nym client retries a lost gateway connection by itself (10 attempts, 5 s apart). The
  // node gives it NYM_INTERNAL_RECONNECT_GRACE_MS before replacing the client.
  const handleSocketState = ({ state, code, wasClean, openSockets }) => {
    lastSocketActivityAt = Date.now()
    if (state === 'open') {
      if (socketGraceTimer) {
        clearTimeout(socketGraceTimer)
        socketGraceTimer = null
        diagnostics.info('nym', 'gateway connection restored by the Nym client', { afterMs: Math.round(performance.now() - socketLostAt) })
        reportNetworkStatus('connected')
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
    reportNetworkStatus('reconnecting')
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
  let lastClientStartedAt = 0
  let stopConnectWait = () => {}
  const startClient = async (purpose, preferredGateway) => {
    if (abortSignal?.aborted) throw createAbortError()
    const generation = ++clientGeneration
    const attemptStartedAt = performance.now()
    const { createNymMixnetClient } = await loadLibraries()
    lastClientStartedAt = performance.now()
    const candidate = await createNymMixnetClient()
    // Test only (?faults=1): this attempt sees none of its gateway's events, as if it had stalled.
    const stallThisAttempt = faultInjection.stallConnects > 0
    if (stallThisAttempt) faultInjection.stallConnects -= 1
    let connectedAddress = null
    // The wait below wakes on the connected event itself, not on a polling timer: a tab in the
    // background for more than five minutes gets its timers run only once a minute, which made a
    // 5 s connect look like 28 s and would slow every reconnect of a sharing tab left open.
    let wakeWait = () => {}
    candidate.events.subscribeToConnected(event => {
      if (generation !== clientGeneration || stallThisAttempt) return
      connectedAddress = event.args.address
      wakeWait()
    })
    candidate.events.subscribeToRawMessageReceivedEvent(event => { if (generation === clientGeneration) handleRawMessage(event) })
    let lastGatewayEventAt = 0
    candidate.events.subscribeToWymSocketState(event => {
      if (generation !== clientGeneration || stallThisAttempt) return
      lastGatewayEventAt = Date.now()
      handleSocketState(event.args)
      wakeWait()
    })
    const startOptions = { clientId, nymApiUrl: NYM_API_URL, forceTls: true }
    if (NYM_CLIENT_OVERRIDES[mode]) startOptions.clientOverride = NYM_CLIENT_OVERRIDES[mode]
    if (preferredGateway) startOptions.preferredGateway = preferredGateway
    try {
      await candidate.client.start(startOptions)
    } catch (error) {
      await shutDownClient(candidate, purpose)
      throw error
    }
    diagnostics.info('nym', 'client started, waiting for gateway', { purpose, gatewayRequested: Boolean(preferredGateway), ms: Math.round(performance.now() - attemptStartedAt) })
    const attemptStartedWall = Date.now()
    const hardDeadline = attemptStartedWall + NYM_CONNECT_ATTEMPT_MAX_MS
    const currentDeadline = () => Math.min(hardDeadline, Math.max(attemptStartedWall + NYM_CONNECT_ATTEMPT_TIMEOUT_MS, lastSocketActivityAt + NYM_CONNECT_ACTIVITY_GRACE_MS))
    let extensionLogged = false
    const onAbort = () => wakeWait()
    abortSignal?.addEventListener('abort', onAbort)
    let gatewayUnresponsive = false
    const stalledAt = () => Math.max(attemptStartedWall, lastGatewayEventAt) + GATEWAY_STALL_TIMEOUT_MS
    while (!connectedAddress && Date.now() < currentDeadline() && generation === clientGeneration && !abortSignal?.aborted) {
      if (Date.now() >= stalledAt()) {
        gatewayUnresponsive = true
        break
      }
      if (!extensionLogged && Date.now() > attemptStartedWall + NYM_CONNECT_ATTEMPT_TIMEOUT_MS) {
        extensionLogged = true
        diagnostics.info('nym', 'still connecting; the gateway connection is active, so waiting longer', { purpose, waitedMs: Date.now() - attemptStartedWall })
      }
      // Re-check the moving deadline at least once a second; the connected event, an abort or the
      // node stopping (stopConnectWait) end the wait at once.
      await new Promise(resolve => {
        const nextCheckAt = Math.min(currentDeadline(), stalledAt())
        const timer = setTimeout(resolve, Math.max(0, Math.min(1000, nextCheckAt - Date.now())))
        wakeWait = () => { clearTimeout(timer); resolve() }
        stopConnectWait = wakeWait
      })
    }
    wakeWait = () => {}
    stopConnectWait = () => {}
    abortSignal?.removeEventListener('abort', onAbort)
    if (abortSignal?.aborted && !connectedAddress) {
      // The page asked for another mode or went idle while this client was still connecting.
      await shutDownClient(candidate, purpose)
      throw createAbortError()
    }
    if (generation !== clientGeneration || node.state === 'stopped') {
      // The node was stopped while this client was connecting; do not leave it running.
      await shutDownClient(candidate, purpose)
      throw new Error('The Nym client was stopped while connecting.')
    }
    if (gatewayUnresponsive) {
      if (rememberFailures && preferredGateway && (!stallThisAttempt || faultInjection.rememberFaultFailures)) {
        rememberGatewayFailure({ identity: preferredGateway, performance: await gatewayPerformance(preferredGateway) }, 'stalled while connecting')
      }
      diagnostics.warn('nym', 'connecting made no progress for ' + GATEWAY_STALL_TIMEOUT_MS / 1000 + ' s; trying another gateway', { purpose, gateway: preferredGateway ? preferredGateway.slice(0, 6) + '...' : 'chosen by the Nym client', gatewayEventsSeen: lastGatewayEventAt > 0 })
      await shutDownClient(candidate, purpose)
      const error = new Error('The gateway stopped responding while connecting (no progress for ' + GATEWAY_STALL_TIMEOUT_MS / 1000 + ' seconds).')
      error.name = 'GatewayUnresponsiveError'
      throw error
    }
    if (!connectedAddress) {
      diagnostics.warn('nym', 'no gateway connection after ' + Math.round((Date.now() - attemptStartedWall) / 1000) + ' s; discarding this client', { purpose, mode })
      await shutDownClient(candidate, purpose)
      throw new Error('Could not connect to the Nym network within ' + Math.round((Date.now() - attemptStartedWall) / 1000) + ' seconds.')
    }
    mixnetClient = candidate
    return { address: connectedAddress, ms: Math.round(performance.now() - attemptStartedAt) }
  }

  try {
    const chosen = await chooseGateway(gatewayBand ?? {})
    if (chosen) diagnostics.info('nym', 'gateway chosen', describeGateway(chosen))
    const { address } = await startClient('initial', chosen?.identity ?? null)
    node.address = address
    node.gateway = chosen && gatewayOfAddress(address) === chosen.identity ? chosen : { identity: gatewayOfAddress(address), performance: await gatewayPerformance(gatewayOfAddress(address)) }
    if (node.gateway.identity) gatewayDirectory.triedThisPage.add(node.gateway.identity)
  } catch (error) {
    // A first attempt that never connected leaves nothing worth keeping.
    clearInterval(gatewayTrafficTimer)
    stopHeartbeat()
    indexedDB.deleteDatabase(NYM_STORAGE_PREFIX + clientId)
    throw error
  }
  setState('connected')
  node.connectMs = Math.round(performance.now() - startedAt)
  diagnostics.info('nym', 'connected', { address: redactNymAddress(node.address), ms: node.connectMs, gateway: describeGateway(node.gateway) })
  logConnectSteps('initial')
  beginHealthCheck()

  // Replaces the Nym client, keeping this node's identity (its keys), so a reconnect to the same
  // gateway keeps the address. Concurrent calls share one attempt. With newGateway, the first
  // attempt already moves to another gateway, which changes the address; otherwise the current
  // gateway is tried NYM_RECONNECT_SAME_GATEWAY_ATTEMPTS times first. Each new gateway is chosen
  // as at startup (scored, random, never one this page already tried).
  node.reconnect = (reason, { newGateway = false, status = 'reconnecting' } = {}) => {
    if (node.state === 'stopped') return Promise.resolve(false)
    if (reconnectPromise) return reconnectPromise
    reconnectPromise = (async () => {
      const reconnectStartedAt = performance.now()
      setState('reconnecting')
      clearTimeout(firstHealthCheckTimer)
      reportNetworkStatus(status)
      diagnostics.warn('nym', newGateway ? 'moving this identity to another gateway' : 'replacing the Nym client with the same identity', { reason })
      const previousClient = mixnetClient
      mixnetClient = null
      if (previousClient) await shutDownClient(previousClient, 'replaced')
      const currentGateway = gatewayOfAddress(node.address)
      const sameGatewayAttempts = newGateway ? 0 : NYM_RECONNECT_SAME_GATEWAY_ATTEMPTS
      for (let attempt = 1; node.state === 'reconnecting'; attempt += 1) {
        const keepGateway = Boolean(currentGateway) && attempt <= sameGatewayAttempts
        if (!newGateway && attempt === sameGatewayAttempts + 1) diagnostics.warn('nym', 'the current gateway did not accept ' + sameGatewayAttempts + ' reconnects; trying a new gateway, which changes the address')
        try {
          const chosen = keepGateway ? null : await chooseGateway()
          if (chosen) diagnostics.info('nym', 'gateway chosen', describeGateway(chosen))
          const { address, ms } = await startClient(newGateway ? 'switch' : 'reconnect', keepGateway ? currentGateway : chosen?.identity ?? null)
          node.counters.reconnects += 1
          const sameAddress = address === node.address
          node.lastReconnectMs = Math.round(performance.now() - reconnectStartedAt)
          diagnostics.info('nym', newGateway ? 'moved to another gateway' : 'reconnected', { attempt, ms, totalMs: node.lastReconnectMs, sameAddress })
          if (!sameAddress) {
            diagnostics.warn('nym', 'the Nym address changed while reconnecting', { previous: redactNymAddress(node.address), current: redactNymAddress(address) })
            node.address = address
            const identity = gatewayOfAddress(address)
            node.gateway = chosen?.identity === identity ? chosen : { identity, performance: await gatewayPerformance(identity) }
            gatewayDirectory.triedThisPage.add(identity)
          }
          setState('connected')
          logConnectSteps(newGateway ? 'switch' : 'reconnect')
          beginHealthCheck()
          reportNetworkStatus('connected')
          try { node.onReconnected?.({ sameAddress }) } catch (error) { diagnostics.error('nym', 'reconnect handler failed', error) }
          return true
        } catch (error) {
          // An unresponsive new gateway is simply replaced by another one; no need to pause.
          const delayMs = !keepGateway && error?.name === 'GatewayUnresponsiveError' ? 0 : Math.min(NYM_RECONNECT_MAX_DELAY_MS, 2000 * 2 ** (attempt - 1))
          diagnostics.warn('nym', 'reconnect attempt ' + attempt + ' failed; next try in ' + delayMs / 1000 + ' s', error)
          reportNetworkStatus('failed')
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
  node.send = async (payload, recipient, { replySurbs = RECIPIENT_REPLY_SURBS_PER_MESSAGE } = {}) => {
    try {
      await waitUntilUsable()
      countOutgoing(payload)
      await mixnetClient.client.rawSend({ payload, recipient, replySurbs })
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
  // Gateway test hooks: raw counters, and a message sent to this client's own address, which
  // crosses the mixnet out and back like any other message. Resolves to its round trip in ms.
  node.readGatewayTraffic = () => (mixnetClient ? mixnetClient.client.wymGatewayTraffic() : null)
  node.probeSelf = timeoutMs => new Promise((resolve, reject) => {
    const nonce = bytesToHex(crypto.getRandomValues(new Uint8Array(8)))
    const sentAt = performance.now()
    const timer = setTimeout(() => { pendingProbes.delete(nonce); reject(new Error('no answer within ' + timeoutMs + ' ms')) }, timeoutMs)
    pendingProbes.set(nonce, () => { clearTimeout(timer); pendingProbes.delete(nonce); resolve(Math.round(performance.now() - sentAt)) })
    // No reply blocks: the message comes back to this client by itself, as a single packet.
    node.send(encodeControlMessage({ kind: 'probe', nonce }), node.address, { replySurbs: 0 }).catch(error => { clearTimeout(timer); pendingProbes.delete(nonce); reject(error) })
  })
  node.stop = async () => {
    clearInterval(gatewayTrafficTimer)
    clearTimeout(firstHealthCheckTimer)
    flushGatewayTrafficWindow()
    diagnostics.info('nym', 'stopping client', Object.assign({}, node.counters, { gatewayTraffic: node.describeGatewayTraffic() }))
    setState('stopped')
    stopConnectWait()
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
// getNymNode(mode) always resolves to a client running in that mode. Asking for a different mode
// cancels a client that is still connecting at once (its abort signal ends the connect wait) and
// stops one that already connected, then starts the new one. Each switch is chained to the
// previous promise, so switching repeatedly can never stop the same client twice or leave two
// clients running. stopNymNode() disconnects without starting another (idle disconnect).
let nymNodePromise = null
let nymNodeMode = null
let nymNodeAbortController = null
let currentNymNode = null

function createAbortError () {
  const error = new Error('Connecting was cancelled.')
  error.name = 'AbortError'
  return error
}

function getNymNode (mode) {
  if (nymNodePromise && nymNodeMode === mode) return nymNodePromise
  const previousPromise = nymNodePromise
  nymNodeAbortController?.abort()
  const abortController = new AbortController()
  nymNodeAbortController = abortController
  nymNodeMode = mode
  currentNymNode = null
  setNetworkStatus('connecting')
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
      if (abortController.signal.aborted) throw createAbortError()
      try {
        return await createNymNode(mode, abortController.signal)
      } catch (error) {
        if (error?.name === 'AbortError' || attempt >= NYM_CONNECT_ATTEMPTS) throw error
        diagnostics.warn('nym', 'connection attempt ' + attempt + ' of ' + NYM_CONNECT_ATTEMPTS + ' failed; retrying', error)
      }
    }
  })().then(node => {
    attachNodeDispatch(node)
    if (nymNodePromise === promise) {
      currentNymNode = node
      setNetworkStatus('connected')
    }
    return node
  }, error => {
    if (error?.name === 'AbortError') diagnostics.info('nym', 'connecting cancelled', { mode })
    if (nymNodePromise === promise) {
      setNetworkStatus(error?.name === 'AbortError' ? 'paused' : 'failed')
      nymNodePromise = null
      nymNodeMode = null
    }
    throw error
  })
  nymNodePromise = promise
  return promise
}

/** Disconnects the page's Nym client without starting another one. */
async function stopNymNode (reason) {
  const promise = nymNodePromise
  if (!promise) return
  nymNodeAbortController?.abort()
  nymNodePromise = null
  nymNodeMode = null
  nymNodeAbortController = null
  currentNymNode = null
  diagnostics.info('nym', 'disconnecting', { reason })
  setNetworkStatus('paused')
  const node = await promise.catch(() => null)
  if (node) await node.stop()
}

/** Connects in the selected mode unless a client is already running or connecting. */
function ensureNymConnected (reason) {
  if (nymNodePromise) return nymNodePromise
  diagnostics.info('nym', 'connecting', { reason, mode: currentMode() })
  const promise = getNymNode(currentMode())
  promise.catch(error => { if (error?.name !== 'AbortError') diagnostics.error('nym', 'connection failed', error) })
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
// recipientViews: recipient id -> what the sender's Recipients list shows for it (a number,
// state, latest reply tag and bytes sent over retired links). stoppedShareInfoHashes: shares this
// page stopped; a recipient still asking about one is told it stopped.
const sendSession = { torrent: null, client: null, node: null, links: new Map(), framesAwaitingLink: new Map(), closedLinkIds: new Set(), lateFramesDropped: 0, recipients: new Map(), finished: new Set(), recipientLimit: 5, statsTimer: null, stopSnapshots: null, qrDataUrl: null, linkFields: null, recipientViews: new Map(), recipientRows: new Map(), nextRecipientNumber: 1, preparing: false, mode: null }
const stoppedShareInfoHashes = new Set()
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

// ---------------------------------------------------------------------------
// Interface helpers: views, status blocks, buttons, dialogs, network mode
// ---------------------------------------------------------------------------
const VIEW_IDS = ['view-choose', 'view-share', 'view-receive']
function currentView () {
  return VIEW_IDS.find(id => !elementById(id).classList.contains('hidden'))
}
function showView (viewId) {
  const changed = currentView() !== viewId
  for (const id of VIEW_IDS) elementById(id).classList.toggle('hidden', id !== viewId)
  updateModeControl()
  updateDocumentTitle()
  if (changed) window.scrollTo({ top: 0 })
}

/** Replaces a container's icon. className is added to the generated svg (for example "spin"). */
function setIcon (container, iconName, className) {
  const attributes = { 'data-lucide': iconName }
  if (className) attributes.class = className
  container.replaceChildren(createElement('i', attributes))
  renderIcons()
}

/** Sets a button's icon and label, skipping the work when nothing changed. */
function setButtonContent (button, iconName, label) {
  const key = iconName + '|' + label
  if (button.dataset.contentKey === key) return
  button.dataset.contentKey = key
  const children = []
  if (iconName) children.push(createElement('i', iconName === 'loader-circle' ? { 'data-lucide': iconName, class: 'spin' } : { 'data-lucide': iconName }))
  children.push(createElement('span', { text: label }))
  button.replaceChildren(...children)
  renderIcons()
}

function formatElapsed (seconds) {
  const whole = Math.max(0, Math.floor(seconds))
  if (whole < 60) return whole + ' s'
  return Math.floor(whole / 60) + ' min ' + (whole % 60) + ' s'
}

/**
 * Renders a status block (share-status or receive-status): an icon, one line of text, the time
 * spent in the current stage, a bar and a caption. progress is a number from 0 to 1 for a
 * determinate bar, 'indeterminate' while the length of a wait is unknown, or null for no bar.
 */
function renderStatus (prefix, { tone = 'neutral', icon, spin = false, text, caption = '', progress = null, startedAt = null }) {
  const block = elementById(prefix + '-status')
  block.dataset.tone = tone
  const iconContainer = elementById(prefix + '-status-icon')
  const iconKey = icon + (spin ? ' spin' : '')
  if (iconContainer.dataset.icon !== iconKey) {
    iconContainer.dataset.icon = iconKey
    setIcon(iconContainer, icon, spin ? 'spin' : null)
  }
  elementById(prefix + '-status-text').textContent = text
  const captionElement = elementById(prefix + '-status-caption')
  captionElement.textContent = caption
  captionElement.classList.toggle('hidden', !caption)
  const track = elementById(prefix + '-status-track')
  const fill = elementById(prefix + '-status-fill')
  track.classList.toggle('hidden', progress === null)
  if (progress === 'indeterminate') {
    track.dataset.mode = 'indeterminate'
    fill.style.width = ''
  } else if (typeof progress === 'number') {
    delete track.dataset.mode
    fill.style.width = (Math.min(1, Math.max(0, progress)) * 100).toFixed(1) + '%'
  }
  block.dataset.startedAt = startedAt === null ? '' : String(startedAt)
  renderElapsed(prefix)
}
function renderElapsed (prefix) {
  const startedAt = Number(elementById(prefix + '-status').dataset.startedAt)
  elementById(prefix + '-status-elapsed').textContent = startedAt ? formatElapsed((performance.now() - startedAt) / 1000) : ''
}

/**
 * Asks the person to confirm an action in a modal sheet. Resolves true only for the confirm
 * button; Escape, the backdrop and the cancel button all resolve false. Focus starts on the
 * cancel button, so pressing Enter by reflex never confirms a destructive action.
 */
function confirmAction ({ title, message, confirmLabel, cancelLabel }) {
  const dialog = elementById('confirm-dialog')
  if (typeof dialog.showModal !== 'function') return Promise.resolve(window.confirm(title + '\n\n' + message))
  if (dialog.open) return Promise.resolve(false)
  elementById('confirm-title').textContent = title
  elementById('confirm-message').textContent = message
  elementById('confirm-accept').textContent = confirmLabel
  elementById('confirm-cancel').textContent = cancelLabel
  dialog.returnValue = ''
  return new Promise(resolve => {
    dialog.addEventListener('close', () => resolve(dialog.returnValue === 'accept'), { once: true })
    dialog.showModal()
    elementById('confirm-cancel').focus()
  })
}

function showChooseError (text) {
  const element = elementById('choose-error')
  element.textContent = text
  element.classList.toggle('hidden', !text)
}
function showPasteError (text) {
  const element = elementById('paste-error')
  element.textContent = text
  element.classList.toggle('hidden', !text)
  elementById('paste-input').setAttribute('aria-invalid', text ? 'true' : 'false')
}

function describeFileTotals (files) {
  const totalBytes = files.reduce((sum, file) => sum + file.size, 0)
  return (files.length === 1 ? '1 file, ' : files.length + ' files, ') + formatBytes(totalBytes)
}

// Network mode: a page-wide setting in the header. It can only change on the start page, because
// changing it replaces the Nym client, which would end a share or a download in progress.
function readStoredMode () {
  try {
    const stored = localStorage.getItem(MODE_STORAGE_KEY)
    return stored && Object.hasOwn(MODE_LABELS, stored) ? stored : DEFAULT_MODE
  } catch (error) {
    return DEFAULT_MODE
  }
}
function storeMode (mode) {
  try {
    localStorage.setItem(MODE_STORAGE_KEY, mode)
  } catch (error) {
    diagnostics.warn('env', 'could not remember the network mode', error)
  }
}
function currentMode () {
  return elementById('network-mode').value
}
// A native dropdown is as wide as its longest option. Sizing the header's mode menu to the option
// shown keeps the pill tight, with the chevron right after the text, and keeps it on one line on
// narrow phones.
let selectMeasureCanvas = null
function fitSelectToSelection (select) {
  const style = getComputedStyle(select)
  selectMeasureCanvas = selectMeasureCanvas ?? document.createElement('canvas')
  const context = selectMeasureCanvas.getContext('2d')
  context.font = style.fontWeight + ' ' + style.fontSize + ' ' + style.fontFamily
  const textWidth = context.measureText(select.options[select.selectedIndex]?.text ?? '').width
  select.style.width = Math.ceil(textWidth + parseFloat(style.paddingLeft) + parseFloat(style.paddingRight) + 2) + 'px'
}
function updateModeControl () {
  const select = elementById('network-mode')
  const locked = currentView() !== 'view-choose'
  select.disabled = locked
  select.title = locked ? 'Network mode. Return to the start page to change it.' : 'Network mode'
}

/** Puts the transfer state in the tab title, so it can be followed from another tab. */
function updateDocumentTitle () {
  let status = ''
  const view = currentView()
  if (view === 'view-receive') {
    if (receiveSession.downloading && receiveSession.torrent) status = Math.floor(receiveSession.torrent.progress * 100) + '%'
    else if (receiveSession.stage === 'done') status = 'Ready to save'
  } else if (view === 'view-share' && sendSession.torrent) {
    const states = [...sendSession.recipientViews.values()].map(recipientView => recipientView.state)
    const receiving = states.filter(state => state === 'receiving').length
    const done = states.filter(state => state === 'done').length
    status = receiving ? 'Sending to ' + receiving : done ? done + ' done' : 'Sharing'
  }
  document.title = status ? '(' + status + ') Nym Share' : 'Nym Share'
}

// Files in a list: name and size, then a Verified mark and a Save button once received.
function renderFileRows (listElement, files, options = {}) {
  listElement.replaceChildren(...files.map((file, index) => {
    const children = [
      createElement('i', { 'data-lucide': 'file' }),
      createElement('div', { className: 'file-text' }, [
        createElement('span', { className: 'file-name', text: file.name, title: file.name }),
        createElement('span', { className: 'file-size', text: formatBytes(file.size) })
      ])
    ]
    const verified = options.verified?.[index]
    if (verified === true) children.push(createElement('span', { className: 'verified' }, [createElement('i', { 'data-lucide': 'check' }), 'Verified']))
    if (verified === false) children.push(createElement('span', { className: 'verified', 'data-tone': 'error' }, [createElement('i', { 'data-lucide': 'circle-alert' }), 'Failed check']))
    if (options.onSave) {
      const saved = options.saved?.has(index)
      const saveButton = createElement('button', { className: 'button button-secondary', type: 'button', 'aria-label': (saved ? 'Save again: ' : 'Save ') + file.name }, [
        createElement('i', { 'data-lucide': saved ? 'check' : 'download' }),
        saved ? 'Saved' : 'Save'
      ])
      saveButton.addEventListener('click', () => options.onSave(index))
      children.push(saveButton)
    }
    return createElement('li', { className: 'file-row' }, children)
  }))
  renderIcons()
}

// ---------------------------------------------------------------------------
// Message routing: one Nym client serves whichever share or download is active
// ---------------------------------------------------------------------------
function attachNodeDispatch (node) {
  node.onControl = (message, senderTag) => dispatchControlMessage(node, message, senderTag)
  node.onData = (frame, senderTag) => dispatchDataFrame(frame, senderTag)
  node.onReconnected = ({ sameAddress }) => {
    if (sendSession.node === node) handleSenderReconnected(sameAddress)
    if (receiveSession.node === node) handleReceiverReconnected(sameAddress)
  }
  node.onHealthChange = health => handleNodeHealth(node, health)
}

// What the page does when its gateway stops delivering incoming messages (see the health check in
// createNymNode). With no link out, moving to another gateway costs nothing visible, so it moves
// at once. A sender whose link is already out first reconnects to the same gateway, which keeps the
// address and the link; only if that does not help does it move, and then shows the new link.
// A recipient's address is in no link, so it moves at once and reopens its link to the sender.
// A node changes gateway at most HEALTH_SWITCH_LIMIT times within HEALTH_SWITCH_WINDOW_MS, so a
// wider outage cannot cause endless moves, while a tab left open for hours can still recover later.
const HEALTH_SWITCH_LIMIT = 3
const HEALTH_SWITCH_WINDOW_MS = 10 * 60 * 1000
function handleNodeHealth (node, health) {
  if (health.state !== 'degraded' || node.state !== 'connected') return
  const now = Date.now()
  node.healthSwitchTimes = (node.healthSwitchTimes ?? []).filter(time => now - time < HEALTH_SWITCH_WINDOW_MS)
  if (node.healthSwitchTimes.length >= HEALTH_SWITCH_LIMIT) {
    diagnostics.warn('nym', 'incoming messages are still not arriving after ' + HEALTH_SWITCH_LIMIT + ' gateway changes in ' + HEALTH_SWITCH_WINDOW_MS / 60000 + ' minutes; staying put for now', { acknowledgementsPerPacketOut: health.acknowledgementReturn })
    return
  }
  node.healthSwitchTimes.push(now)
  node.healthSwitches += 1
  const linkShared = sendSession.node === node && Boolean(sendSession.linkFields)
  const keepAddress = linkShared && !node.healthSameGatewayTried
  if (keepAddress) node.healthSameGatewayTried = true
  const reason = 'only ' + Math.round(health.acknowledgementReturn * 100) + '% of acknowledgements came back'
  diagnostics.warn('nym', keepAddress ? 'incoming messages are not arriving; reconnecting to the same gateway to keep the shared link' : 'incoming messages are not arriving; moving to another gateway', { reason, switches: node.healthSwitches })
  node.reconnect(reason, { newGateway: !keepAddress, status: keepAddress ? 'reconnecting' : 'switching' })
}

function dispatchControlMessage (node, message, senderTag) {
  const infoHash = message?.infoHash
  if (sendSession.torrent && infoHash === sendSession.torrent.infoHash) {
    handleSenderControl(message, senderTag)
    return
  }
  if (receiveSession.link && infoHash === receiveSession.link.infoHash) {
    handleReceiverControl(message)
    return
  }
  // A recipient of a share this page stopped: tell it, so it does not wait for an answer.
  if (senderTag && stoppedShareInfoHashes.has(infoHash) && (message.kind === 'hello' || message.kind === 'open')) {
    diagnostics.info('send', 'told a recipient that the share was stopped', describeControlMessage(message))
    node.replyControl({ kind: 'stopped', infoHash }, senderTag).catch(() => {})
    return
  }
  diagnostics.warn('nym', 'control message for no active share ignored', describeControlMessage(message))
}

let framesWithoutSession = 0
function dispatchDataFrame (frame, senderTag) {
  if (sendSession.torrent) {
    routeSenderFrame(frame, senderTag)
    return
  }
  if (receiveSession.link) {
    routeReceiverFrame(frame)
    return
  }
  // Late frames of a share or download that already ended.
  framesWithoutSession += 1
  if (framesWithoutSession === 1 || framesWithoutSession % 100 === 0) diagnostics.info('link', 'data frames after the transfer ended dropped', { frames: framesWithoutSession })
}

// ---------------------------------------------------------------------------
// Sender: preparing, sharing, recipients, stopping
// ---------------------------------------------------------------------------
async function startSharing (fileList) {
  const chosen = Array.from(fileList ?? [])
  elementById('file-input').value = ''
  if (sendSession.torrent || sendSession.preparing || chosen.length === 0) return
  const files = chosen.filter(file => file.size > 0)
  if (files.length === 0) {
    showChooseError(chosen.length === 1 ? 'That file is empty, so there is nothing to send.' : 'Those files are empty, so there is nothing to send.')
    return
  }
  const totalBytes = files.reduce((sum, file) => sum + file.size, 0)
  if (totalBytes > MAX_TOTAL_BYTES) {
    showChooseError('These files total ' + formatBytes(totalBytes) + '. The limit is ' + formatBytes(MAX_TOTAL_BYTES) + ', because everything is held in memory.')
    return
  }
  showChooseError(files.length < chosen.length ? 'Empty files were left out.' : '')

  sendSession.preparing = true
  sendSession.recipientLimit = Number(elementById('recipient-limit').value)
  const mode = currentMode()
  const shareStartedAt = performance.now()
  diagnostics.info('send', 'sharing started', { files: files.length, plaintextBytes: totalBytes, fileSizes: files.map(file => file.size), recipientLimit: sendSession.recipientLimit || 'none', mode })
  resetShareView()
  showView('view-share')
  renderFileRows(elementById('share-file-list'), files)
  elementById('share-file-summary').textContent = describeFileTotals(files)
  setShareHeading('Preparing your link', 'Files are encrypted here, in this tab, before anything leaves it.')
  const encryptCaption = 'Encrypting ' + (files.length === 1 ? 'the file' : 'all ' + files.length + ' files') + ' in your browser.'
  renderStatus('share', { icon: 'loader-circle', spin: true, text: 'Encrypting', caption: encryptCaption, progress: 0, startedAt: shareStartedAt })

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
      renderStatus('share', { icon: 'loader-circle', spin: true, text: 'Encrypting', caption: encryptCaption, progress: processedBytes / totalBytes, startedAt: shareStartedAt })
    }
    const encryptedList = await keychain.encryptMeta(textEncoder.encode(JSON.stringify(fileDescriptions)))
    diagnostics.info('send', 'encrypted', { ms: Math.round(performance.now() - shareStartedAt), encryptedBytes: encryptedFiles.reduce((sum, file) => sum + file.size, 0), encryptedListBytes: encryptedList.length, plaintextHashPrefixes: fileDescriptions.map(description => description.sha256.slice(0, 8)) })

    if (!currentNymNode || currentNymNode.mode !== mode) {
      renderStatus('share', { icon: 'loader-circle', spin: true, text: 'Connecting to Nym', caption: 'Joining the mixnet. This usually takes 5 to 10 seconds.', progress: 'indeterminate', startedAt: performance.now() })
    }
    sendSession.node = await nodePromise
    sendSession.mode = mode
    await confirmIncomingPathBeforeLink(sendSession.node)

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
    acquireWakeLock('sharing')

    elementById('share-link').value = shareLink
    sendSession.qrDataUrl = null
    elementById('share-status').classList.add('hidden')
    elementById('share-ready').classList.remove('hidden')
    elementById('native-share').classList.toggle('hidden', typeof navigator.share !== 'function')
    setShareHeading('Ready to share', 'Send this link to the people you want to have the files. It works while this tab stays open.')
    diagnostics.info('send', 'link ready', { linkVersion: LINK_VERSION, mode: sendSession.mode, linkCharacters: shareLink.length, senderAddress: redactNymAddress(sendSession.node.address), totalMs: Math.round(performance.now() - shareStartedAt) })
    renderRecipients()
    updateShareDataNotice()
    startSenderStats()
    sendSession.stopSnapshots = startSnapshots('sender', () => ({
      peers: sendSession.torrent?.numPeers,
      uploaded: sendSession.torrent?.uploaded,
      recipients: sendSession.recipients.size,
      finished: sendSession.finished.size,
      recipientStates: [...sendSession.recipientViews.values()].map(recipientView => recipientView.state),
      nymState: sendSession.node?.state,
      framesAwaitingLink: sendSession.framesAwaitingLink.size,
      lateFramesDropped: sendSession.lateFramesDropped,
      nym: sendSession.node?.counters,
      links: describeLinks(sendSession.links.values())
    }))
    updateDocumentTitle()
    elementById('copy-link').focus({ preventScroll: true })
  } catch (error) {
    showShareError(error)
  } finally {
    sendSession.preparing = false
  }
}

// Recipients announce themselves with "hello", then open a link for the transfer. Every answer
// goes back through the reply blocks attached to the recipient's message, identified by its
// reply tag, so the sender never learns where the recipient is. A message without a tag cannot
// be answered, and one without a recipient id cannot be counted; both are ignored.
function handleSenderControl (message, senderTag) {
  const torrent = sendSession.torrent
  if (!senderTag) {
    diagnostics.warn('send', 'control message without reply blocks ignored', describeControlMessage(message))
    return
  }
  const recipientId = typeof message.recipientId === 'string' && RECIPIENT_ID_PATTERN.test(message.recipientId) ? message.recipientId : null
  if (!recipientId) {
    diagnostics.warn('send', 'control message without a recipient id ignored', describeControlMessage(message))
    return
  }
  const recipientView = noteRecipient(recipientId, senderTag)
  const knownRecipient = sendSession.recipients.has(recipientId)
  const limitReached = sendSession.recipientLimit > 0 && sendSession.recipients.size >= sendSession.recipientLimit && !knownRecipient
  const linkId = typeof message.linkId === 'string' && /^[0-9a-f]{32}$/.test(message.linkId) ? message.linkId : null

  if (message.kind === 'hello') {
    if (limitReached && recipientView.state === 'viewing') recipientView.state = 'refused'
    sendSession.node.replyControl({ kind: limitReached ? 'refused' : 'available', infoHash: torrent.infoHash, reason: limitReached ? 'limit' : undefined, attempt: typeof message.attempt === 'number' ? message.attempt : undefined }, senderTag).catch(() => {})
  } else if (message.kind === 'open' && linkId) {
    if (limitReached) {
      recipientView.state = 'refused'
      sendSession.node.replyControl({ kind: 'refused', infoHash: torrent.infoHash, reason: 'limit' }, senderTag).catch(() => {})
      renderRecipients()
      return
    }
    if (sendSession.links.has(linkId) || sendSession.closedLinkIds.has(linkId)) {
      diagnostics.info('send', 'duplicate open ignored', { link: linkId.slice(0, 8) })
      return
    }
    const recipient = sendSession.recipients.get(recipientId) ?? { linkIds: new Set() }
    sendSession.recipients.set(recipientId, recipient)
    recipientView.state = 'receiving'
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
    recipientView.state = message.verified === false ? 'failed' : 'done'
    diagnostics.info('send', 'recipient finished', { finished: sendSession.finished.size, verified: message.verified, gatewayTraffic: sendSession.node?.describeGatewayTraffic() })
    // The recipient has destroyed its side, but nothing travels back over the mixnet to tell
    // this link stream. Close it here so the wire, the counts and the logs settle.
    if (linkId && sendSession.links.get(linkId)?.recipientId === recipientId) retireSenderLink(linkId, 'recipient finished')
  } else if (message.kind === 'cancel') {
    // The recipient left. Its place under the recipient limit is freed for someone else.
    for (const previousLinkId of [...(sendSession.recipients.get(recipientId)?.linkIds ?? [])]) retireSenderLink(previousLinkId, 'recipient cancelled')
    sendSession.recipients.delete(recipientId)
    recipientView.state = 'cancelled'
    recipientView.cancelledWhile = message.stage === 'downloading' ? 'downloading' : 'before-download'
    diagnostics.info('send', 'recipient cancelled', { stage: recipientView.cancelledWhile, recipients: sendSession.recipients.size })
  } else {
    diagnostics.warn('send', 'unexpected control message', describeControlMessage(message))
    return
  }
  renderRecipients()
  updateDocumentTitle()
}

/** Returns the Recipients list entry for a recipient, creating it on first contact. */
function noteRecipient (recipientId, senderTag) {
  let recipientView = sendSession.recipientViews.get(recipientId)
  if (!recipientView) {
    recipientView = { number: sendSession.nextRecipientNumber, state: 'viewing', replyTag: senderTag, retiredBytes: 0, cancelledWhile: null }
    sendSession.nextRecipientNumber += 1
    sendSession.recipientViews.set(recipientId, recipientView)
  }
  recipientView.replyTag = senderTag
  return recipientView
}

function retireSenderLink (linkId, reason) {
  const link = sendSession.links.get(linkId)
  if (!link) return
  sendSession.links.delete(linkId)
  sendSession.closedLinkIds.add(linkId)
  sendSession.recipients.get(link.recipientId)?.linkIds.delete(linkId)
  const recipientView = sendSession.recipientViews.get(link.recipientId)
  if (recipientView) recipientView.retiredBytes += link.stats.bytesOut
  diagnostics.info('send', 'link retired', { link: linkId.slice(0, 8), reason })
  link.destroy()
}

// The Recipients list. Each recipient is numbered in the order it first made contact; nothing
// about it is known beyond its random session id, so a number is all the list can show.
const RECIPIENT_STATE_ICONS = { viewing: 'user-round', receiving: 'download', done: 'circle-check', failed: 'circle-alert', cancelled: 'circle-slash', refused: 'circle-slash' }

/** Share of the files sent to one recipient, from the bytes its links carried. */
function recipientProgress (recipientId, recipientView) {
  if (recipientView.state === 'done' || recipientView.state === 'failed') return 1
  const totalBytes = sendSession.torrent?.length
  if (!totalBytes) return 0
  let bytes = recipientView.retiredBytes
  for (const link of sendSession.links.values()) if (link.recipientId === recipientId) bytes += link.stats.bytesOut
  // Bytes include BitTorrent messages, so the share stops short of 100 % until the recipient confirms.
  return Math.min(0.99, bytes / totalBytes)
}

function describeRecipientState (recipientView, progress) {
  switch (recipientView.state) {
    case 'viewing': return 'Opened the link'
    case 'receiving': return progress >= 0.01 ? 'Receiving, ' + Math.floor(progress * 100) + '%' : 'Connecting'
    case 'done': return 'Received and verified'
    case 'failed': return 'Received, but the integrity check failed'
    case 'cancelled': return recipientView.cancelledWhile === 'downloading' ? 'Cancelled the download' : 'Left without downloading'
    case 'refused': return 'Turned away, the limit was reached'
    default: return ''
  }
}

function renderRecipients () {
  const list = elementById('recipient-list')
  const entries = [...sendSession.recipientViews.entries()]
  elementById('recipient-empty').classList.toggle('hidden', entries.length > 0)
  list.classList.toggle('hidden', entries.length === 0)
  const limit = sendSession.recipientLimit
  elementById('recipient-count').textContent = limit > 0 ? sendSession.recipients.size + ' of ' + limit + (limit === 1 ? ' place' : ' places') + ' used' : 'No limit'

  let iconsAdded = false
  const rows = entries.map(([recipientId, recipientView]) => {
    let row = sendSession.recipientRows.get(recipientId)
    if (!row || row.dataset.state !== recipientView.state) {
      const stateElement = createElement('span', { className: 'recipient-state' })
      const bodyChildren = [createElement('div', { className: 'recipient-text' }, [createElement('span', { className: 'recipient-name', text: 'Recipient ' + recipientView.number }), stateElement])]
      let progressFill = null
      if (recipientView.state === 'receiving') {
        progressFill = createElement('div')
        bodyChildren.push(createElement('div', { className: 'recipient-progress', role: 'presentation' }, [progressFill]))
      }
      row = createElement('li', { className: 'recipient-row', 'data-state': recipientView.state }, [
        createElement('i', { 'data-lucide': RECIPIENT_STATE_ICONS[recipientView.state] ?? 'user-round' }),
        createElement('div', { className: 'recipient-body' }, bodyChildren)
      ])
      row.stateElement = stateElement
      row.progressFill = progressFill
      sendSession.recipientRows.set(recipientId, row)
      iconsAdded = true
    }
    const progress = recipientProgress(recipientId, recipientView)
    row.stateElement.textContent = describeRecipientState(recipientView, progress)
    if (row.progressFill) row.progressFill.style.width = (progress * 100).toFixed(1) + '%'
    return row
  })
  const sameRows = list.children.length === rows.length && rows.every((row, index) => list.children[index] === row)
  if (!sameRows) list.replaceChildren(...rows)
  if (iconsAdded) renderIcons()
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
  setButtonContent(elementById('toggle-qr'), 'qr-code', 'Show QR code')
  diagnostics.warn('send', 'share link replaced after the Nym address changed', { linkCharacters: shareLink.length })
  showShareNotice('This page moved to another Nym gateway, so the old link no longer works. Send this new link instead.')
}

function showShareNotice (text) {
  elementById('share-notice-text').textContent = text
  elementById('share-notice').classList.remove('hidden')
}
function hideShareNotice () {
  elementById('share-notice').classList.add('hidden')
}

/** How much data this tab uses per hour while connected: measured once possible, else estimated. */
function updateShareDataNotice () {
  const node = sendSession.node
  const mode = node?.mode ?? currentMode()
  const measuredMegabits = node?.measuredMegabitsPerSecond?.() ?? null
  const gigabytesPerHour = measuredMegabits === null ? ESTIMATED_GIGABYTES_PER_HOUR[mode] : measuredMegabits * 3600 / 8 / 1000
  elementById('share-data-text').textContent = 'While this tab is open it uses about ' + gigabytesPerHour.toFixed(1) + ' GB of data an hour, even when nobody is downloading. ' +
    (measuredMegabits === null ? 'Estimated for ' + MODE_LABELS[mode] + '.' : 'Measured on this connection.')
}

function startSenderStats () {
  const meter = new RateMeter()
  clearInterval(sendSession.statsTimer)
  sendSession.statsTimer = setInterval(() => {
    const torrent = sendSession.torrent
    if (!torrent) return
    elementById('stat-sent').textContent = formatBytes(torrent.uploaded)
    elementById('stat-upload').textContent = formatBytes(meter.update(torrent.uploaded)) + '/s'
    renderRecipients()
    updateShareDataNotice()
    updateDocumentTitle()
  }, 1000)
}

// The link carries this page's address, so before making it the page waits for the first check
// that messages can reach it (about 8 s after connecting; usually already done while files were
// being chosen). If the check fails, the node moves to another gateway and is checked again.
// Past HEALTH_WAIT_BEFORE_LINK_MS in total the link is made anyway; the checks keep running.
const HEALTH_WAIT_BEFORE_LINK_MS = 30000
async function confirmIncomingPathBeforeLink (node) {
  if (node.health.state === 'healthy' && node.state === 'connected') return
  const startedAt = performance.now()
  const deadline = startedAt + HEALTH_WAIT_BEFORE_LINK_MS
  renderStatus('share', { icon: 'loader-circle', spin: true, text: 'Checking the connection', caption: 'Making sure messages can reach you before the link is made. This takes a few seconds.', progress: 'indeterminate', startedAt })
  while (performance.now() < deadline) {
    if (node.state !== 'connected') {
      renderStatus('share', { icon: 'loader-circle', spin: true, text: 'Moving to another gateway', caption: 'The first gateway was not delivering messages. This usually takes 5 to 10 seconds.', progress: 'indeterminate', startedAt })
      try {
        await node.waitUntilUsable()
      } catch (error) {
        break
      }
      renderStatus('share', { icon: 'loader-circle', spin: true, text: 'Checking the connection', caption: 'Making sure messages can reach you before the link is made. This takes a few seconds.', progress: 'indeterminate', startedAt })
    }
    const verdict = await node.waitForHealthVerdict(Math.max(0, deadline - performance.now()))
    if (verdict === 'healthy' && node.state === 'connected') {
      diagnostics.info('send', 'incoming path confirmed before making the link', { waitedMs: Math.round(performance.now() - startedAt) })
      return
    }
    if (verdict === 'checking') break
    // A failed check starts a move (handleNodeHealth). If none began, the switch limit was
    // reached and waiting longer cannot help.
    await new Promise(resolve => setTimeout(resolve, 250))
    if (node.state === 'connected' && node.health.state === 'degraded') break
  }
  diagnostics.warn('send', 'making the link before the incoming path was confirmed', { waitedMs: Math.round(performance.now() - startedAt), health: node.health.state })
}

function setShareHeading (title, subtitle) {
  elementById('share-title').textContent = title
  elementById('share-subtitle').textContent = subtitle
  elementById('share-subtitle').classList.toggle('hidden', !subtitle)
}

function showShareError (error) {
  diagnostics.error('send', 'sharing failed', error)
  const message = error?.message ?? String(error)
  if (sendSession.linkFields) {
    // The link is already out; keep sharing and show what went wrong.
    showShareNotice('Something went wrong: ' + message)
    return
  }
  setShareHeading('Could not prepare the link', '')
  elementById('share-status').classList.remove('hidden')
  renderStatus('share', { tone: 'error', icon: 'circle-alert', text: 'Something went wrong', caption: message, progress: null })
  elementById('share-error-actions').classList.remove('hidden')
}

/** Puts the share view back to its initial state, ready for the next files. */
function resetShareView () {
  elementById('share-ready').classList.add('hidden')
  elementById('share-status').classList.remove('hidden')
  elementById('share-error-actions').classList.add('hidden')
  elementById('qr-image').classList.add('hidden')
  elementById('qr-image').removeAttribute('src')
  elementById('toggle-qr').setAttribute('aria-expanded', 'false')
  setButtonContent(elementById('toggle-qr'), 'qr-code', 'Show QR code')
  setButtonContent(elementById('copy-link'), 'copy', 'Copy link')
  elementById('share-link').value = ''
  elementById('recipient-list').replaceChildren()
  elementById('share-file-list').replaceChildren()
  elementById('share-file-summary').textContent = ''
  elementById('stat-sent').textContent = '0 B'
  elementById('stat-upload').textContent = '0 B/s'
  elementById('stop-sharing').disabled = false
  hideShareNotice()
}

async function requestStopSharing () {
  const receiving = [...sendSession.recipientViews.values()].filter(recipientView => recipientView.state === 'receiving').length
  const confirmed = await confirmAction({
    title: 'Stop sharing?',
    message: receiving
      ? (receiving === 1 ? 'One person is still receiving the files.' : receiving + ' people are still receiving the files.') + ' They will be told you stopped, and the link will stop working.'
      : 'The link will stop working. Anyone you sent it to will not be able to download the files.',
    confirmLabel: 'Stop sharing',
    cancelLabel: 'Keep sharing'
  })
  if (confirmed) await stopSharing({ notifyRecipients: true })
}

async function stopSharing ({ notifyRecipients }) {
  const torrent = sendSession.torrent
  const node = sendSession.node
  diagnostics.info('send', 'stopping', { uploaded: torrent?.uploaded, recipients: sendSession.recipients.size, finished: sendSession.finished.size, links: describeLinks(sendSession.links.values()) })
  elementById('stop-sharing').disabled = true
  if (torrent) stoppedShareInfoHashes.add(torrent.infoHash)
  // Tell everyone who has not finished, through the reply blocks they sent, so no recipient is
  // left waiting for an answer that will never come.
  if (notifyRecipients && torrent && node) {
    const notices = []
    for (const recipientView of sendSession.recipientViews.values()) {
      if (recipientView.replyTag && (recipientView.state === 'viewing' || recipientView.state === 'receiving')) {
        notices.push(node.replyControl({ kind: 'stopped', infoHash: torrent.infoHash }, recipientView.replyTag))
      }
    }
    if (notices.length > 0) {
      await Promise.race([Promise.allSettled(notices), new Promise(resolve => setTimeout(resolve, STOP_NOTICE_WAIT_MS))])
      diagnostics.info('send', 'told recipients that sharing stopped', { recipients: notices.length })
    }
  }
  releaseWakeLock('sharing')
  clearInterval(sendSession.statsTimer)
  sendSession.stopSnapshots?.()
  if (sendSession.client) await new Promise(resolve => sendSession.client.destroy(resolve))
  Object.assign(sendSession, { torrent: null, client: null, links: new Map(), framesAwaitingLink: new Map(), closedLinkIds: new Set(), lateFramesDropped: 0, recipients: new Map(), finished: new Set(), qrDataUrl: null, stopSnapshots: null, linkFields: null, recipientViews: new Map(), recipientRows: new Map(), nextRecipientNumber: 1, statsTimer: null, preparing: false })
  diagnostics.info('send', 'stopped')
  resetShareView()
  showView('view-choose')
  noteUserActivity()
}

// ---------------------------------------------------------------------------
// Receiver
// ---------------------------------------------------------------------------
// recipientId: random per receiving session; the sender counts it against the recipient limit
// and lets it reopen links after a stall. retiredLinkIds: links replaced after a stall, whose
// late frames are dropped. stall: the recovery state (see checkReceiverHealth). token: changes
// whenever the person leaves the receive view, so work still in flight for an earlier link can
// tell that it no longer applies.
function createReceiveSessionState () {
  return {
    link: null, keychain: null, files: null, totalBytes: 0, client: null, torrent: null, node: null, linkStream: null, LinkStream: null,
    results: null, savedIndexes: new Set(), replyTimer: null, giveUpTimer: null, uiTimer: null, monitorTimer: null, stopSnapshots: null,
    recipientId: null, downloading: false, downloadRequested: false, senderOnline: false, retiredLinkIds: new Set(), lateFramesDropped: 0,
    linkGeneration: 0, lastDataAt: 0, stall: null, hellosSent: 0, helloTimer: null, helloStartedAt: 0, helloSentAt: new Map(), roundTrips: [],
    stage: null, stageStartedAt: 0, stageCaption: null, rateMeter: null, downloadStartedAt: 0, token: 0
  }
}
const receiveSession = createReceiveSessionState()

// What the receive view shows in each stage. progress 'transfer' follows the download.
const RECEIVE_STAGE_DISPLAY = {
  opening: { icon: 'loader-circle', spin: true, text: 'Opening the link', caption: 'Decrypting the file list from the link.', progress: 'indeterminate' },
  connecting: { icon: 'loader-circle', spin: true, text: 'Connecting to Nym', caption: 'Joining the mixnet. This usually takes 5 to 10 seconds.', progress: 'indeterminate', timed: true },
  reaching: { icon: 'loader-circle', spin: true, text: 'Reaching the sender', caption: "Asking the sender's tab whether it is online. This usually takes a few seconds.", progress: 'indeterminate', timed: true },
  'reaching-slow': { tone: 'warning', icon: 'hourglass', text: 'Still trying to reach the sender', caption: "The sender's tab may be closed, asleep or offline. This page keeps asking for 3 minutes.", progress: 'indeterminate', timed: true },
  online: { tone: 'positive', icon: 'circle-check', text: 'The sender is online', caption: 'Download when you are ready.', progress: null },
  'setting-up': { icon: 'loader-circle', spin: true, text: 'Setting up the transfer', caption: 'Exchanging the first messages with the sender. This usually takes 5 to 10 seconds.', progress: 'indeterminate', timed: true },
  receiving: { icon: 'download', text: 'Receiving', caption: '', progress: 'transfer', timed: true },
  reconnecting: { tone: 'warning', icon: 'loader-circle', spin: true, text: 'Reconnecting to the sender', caption: 'The transfer paused. What you have received so far is kept.', progress: 'transfer', timed: true },
  'waiting-sender': { tone: 'warning', icon: 'hourglass', text: 'Waiting for the sender', caption: "The sender's tab may be closed, asleep or offline. What you have received so far is kept.", progress: 'transfer', timed: true },
  lost: { tone: 'error', icon: 'circle-alert', text: 'Lost contact with the sender', caption: "What you have received so far is kept. Try again once the sender's tab is open.", progress: 'transfer' },
  checking: { icon: 'loader-circle', spin: true, text: 'Checking the files', caption: 'Decrypting each file and comparing it with what the sender shared.', progress: 1 },
  done: { tone: 'positive', icon: 'circle-check', text: 'Received and verified', caption: '', progress: null },
  'failed-check': { tone: 'error', icon: 'circle-alert', text: 'A file failed the integrity check', caption: 'At least one file does not match what the sender shared. Do not trust it.', progress: null },
  unreachable: { tone: 'error', icon: 'circle-alert', text: 'The sender is not answering', caption: "Links only work while the sender keeps their tab open. Their tab may be closed, asleep or offline.", progress: null },
  stopped: { tone: 'neutral', icon: 'circle-slash', text: 'The sender stopped sharing', caption: 'Ask them for a new link if you still need the files.', progress: null },
  full: { tone: 'neutral', icon: 'circle-slash', text: 'This share is full', caption: 'The sender limited how many people can download, and that limit has been reached.', progress: null },
  refused: { tone: 'neutral', icon: 'circle-slash', text: 'The sender refused the connection', caption: '', progress: null },
  'invalid-link': { tone: 'error', icon: 'circle-alert', text: 'This link does not work', caption: 'The key in the link could not decrypt the file list. Check that the whole link was copied.', progress: null },
  error: { tone: 'error', icon: 'circle-alert', text: 'Something went wrong', caption: '', progress: null }
}
// Stages in which nothing is in progress: the page may disconnect from Nym after a while.
const RECEIVE_TERMINAL_STAGES = new Set(['done', 'failed-check', 'unreachable', 'stopped', 'full', 'refused', 'invalid-link', 'error'])
// Stages from which Try again starts over.
const RECEIVE_RETRY_STAGES = new Set(['unreachable', 'lost', 'error'])

function setReceiveStage (stage, { caption = null, keepTimer = false } = {}) {
  if (receiveSession.stage !== stage) {
    diagnostics.info('receive', 'stage ' + stage)
    receiveSession.stage = stage
    if (!keepTimer) receiveSession.stageStartedAt = performance.now()
  }
  receiveSession.stageCaption = caption
  renderReceiveStatus()
  updateDocumentTitle()
}

function renderReceiveStatus () {
  const stage = receiveSession.stage
  const display = RECEIVE_STAGE_DISPLAY[stage]
  if (!display) return
  let progress = display.progress
  if (progress === 'transfer') progress = receiveSession.torrent ? receiveSession.torrent.progress : 0
  const text = stage === 'receiving' ? 'Receiving, ' + Math.floor(progress * 100) + '%' : display.text
  renderStatus('receive', {
    tone: display.tone ?? 'neutral',
    icon: display.icon,
    spin: Boolean(display.spin),
    text,
    caption: receiveSession.stageCaption ?? display.caption,
    progress,
    startedAt: display.timed ? receiveSession.stageStartedAt : null
  })
  updateReceiveControls()
}

/** Shows the buttons that fit the current stage: Back, Cancel or Done; Download; Try again; Save. */
function updateReceiveControls () {
  const stage = receiveSession.stage
  const finished = stage === 'done' || stage === 'failed-check'
  const navigation = finished ? 'done' : receiveSession.downloading ? 'cancel' : 'back'
  const navigationButton = elementById('receive-back')
  if (navigationButton.dataset.kind !== navigation) {
    navigationButton.dataset.kind = navigation
    navigationButton.dataset.tone = navigation === 'cancel' ? 'destructive' : ''
    if (navigation === 'back') setIcon(elementById('receive-back-icon'), 'chevron-left')
    else elementById('receive-back-icon').replaceChildren()
    elementById('receive-back-label').textContent = navigation === 'done' ? 'Done' : navigation === 'cancel' ? 'Cancel' : 'Back'
    navigationButton.setAttribute('aria-label', navigation === 'done' ? 'Done, return to the start page' : navigation === 'cancel' ? 'Cancel the download' : 'Back to the start page')
  }

  const downloadButton = elementById('start-download')
  const canDownload = Boolean(receiveSession.files) && !receiveSession.downloading && !finished && !RECEIVE_TERMINAL_STAGES.has(stage) && stage !== 'checking' && stage !== 'lost'
  downloadButton.classList.toggle('hidden', !canDownload)
  if (canDownload) {
    const waiting = receiveSession.downloadRequested
    downloadButton.disabled = waiting
    downloadButton.dataset.busy = String(waiting)
    if (waiting) setButtonContent(downloadButton, 'loader-circle', 'Starts when the sender answers')
    else setButtonContent(downloadButton, 'download', receiveSession.files.length === 1 ? 'Download' : 'Download all')
  }
  elementById('try-again').classList.toggle('hidden', !RECEIVE_RETRY_STAGES.has(stage))
  const saveAll = elementById('save-all')
  saveAll.classList.toggle('hidden', stage !== 'done')
  if (stage === 'done') setButtonContent(saveAll, 'download', receiveSession.files.length === 1 ? 'Save file' : 'Save all')
  elementById('receive-stats').classList.toggle('hidden', !receiveSession.downloading)
}

function setReceiveHeading (title, subtitle) {
  elementById('receive-title').textContent = title
  elementById('receive-subtitle').textContent = subtitle
  elementById('receive-subtitle').classList.toggle('hidden', !subtitle)
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

/** Puts the receive view back to its initial state. */
function resetReceiveView () {
  setReceiveHeading('Files for you', '')
  elementById('receive-file-list').replaceChildren()
  elementById('receive-file-summary').textContent = ''
  elementById('receive-mode').textContent = ''
  elementById('stat-received').textContent = '0 B'
  elementById('stat-download').textContent = '0 B/s'
  elementById('stat-eta').textContent = 'Estimating'
  delete elementById('receive-back').dataset.kind
  hideReceiveNotice()
}

// Round-trip samples to the sender: each answered hello (matched by its attempt number) and the
// time from opening a link to its first frame. The slowest recent sample sets the thresholds.
function recordRoundTrip (source, milliseconds) {
  if (!Number.isFinite(milliseconds) || milliseconds <= 0) return
  const samples = receiveSession.roundTrips
  samples.push(Math.round(milliseconds))
  if (samples.length > ROUND_TRIP_SAMPLES_KEPT) samples.shift()
  const thresholds = stallThresholds()
  diagnostics.info('receive', 'round trip to the sender measured', Object.assign({ source, roundTripMs: Math.round(milliseconds), slowestRecentMs: Math.max(...samples) }, thresholds))
}

function stallThresholds () {
  const slowest = receiveSession.roundTrips.length ? Math.max(...receiveSession.roundTrips) : 0
  const scaled = (minimum, roundTrips) => Math.min(STALL_THRESHOLD_CAP_MS, Math.max(minimum, slowest * roundTrips))
  return {
    relinkAfterMs: scaled(STALL_RELINK_AFTER_MS, STALL_RELINK_ROUND_TRIPS),
    senderCheckAfterRelinkMs: scaled(STALL_SENDER_CHECK_AFTER_RELINK_MS, STALL_SENDER_CHECK_ROUND_TRIPS),
    senderCheckIntervalMs: scaled(STALL_SENDER_CHECK_INTERVAL_MS, STALL_SENDER_CHECK_ROUND_TRIPS)
  }
}

function newStallState () {
  return { stage: 'healthy', relinks: 0, senderChecks: 0, lastSenderCheckAt: 0, stalledAt: 0, relinkedAt: 0 }
}

/** The page address without the link's #fragment, which holds the key. */
function cleanPageUrl () {
  return location.pathname + location.search
}

/**
 * Opens a share link. The key never stays in the address bar or the session history: a link from
 * the address bar has its entry replaced with the bare page address, and the receive view gets its
 * own history entry (also without the key) so the browser's Back button returns to the start page.
 */
async function openShareLink (linkText, { fromAddressBar = false } = {}) {
  const link = parseShareLink(linkText)
  if (!link) {
    diagnostics.warn('receive', 'not a valid share link', { characters: linkText.length, hasHash: linkText.includes('#'), fromAddressBar })
    if (fromAddressBar) {
      history.replaceState({ view: 'choose' }, '', cleanPageUrl())
      showPasteError('The link in the address bar is incomplete. Paste the whole link here.')
    } else {
      showPasteError(linkText ? 'This is not a Nym Share link. Check that the whole link was copied.' : 'Paste the link you were sent.')
    }
    return
  }
  showPasteError('')
  elementById('paste-input').value = ''
  diagnostics.info('receive', 'opening link', { linkVersion: link.linkVersion, senderMode: link.mode, infoHash: link.infoHash.slice(0, 8), sender: redactNymAddress(link.senderAddress), linkCharacters: linkText.length, fromAddressBar })
  if (fromAddressBar) history.replaceState({ view: 'choose' }, '', cleanPageUrl())
  history.pushState({ view: 'receive' }, '', cleanPageUrl())

  Object.assign(receiveSession, createReceiveSessionState(), { token: receiveSession.token + 1 })
  const token = receiveSession.token
  receiveSession.link = link
  resetReceiveView()
  showView('view-receive')
  setReceiveStage('opening')
  clearInterval(receiveSession.uiTimer)
  receiveSession.uiTimer = setInterval(updateReceiveProgress, 1000)

  try {
    const { Keychain } = await loadLibraries()
    receiveSession.keychain = new Keychain(link.keyB64Url, base64UrlToBytes(link.saltB64Url))
    // The file list is decrypted locally from the link; no network request is needed.
    const files = JSON.parse(textDecoder.decode(await receiveSession.keychain.decryptMeta(base64UrlToBytes(link.encryptedListB64Url))))
    if (receiveSession.token !== token) return
    receiveSession.files = files
    receiveSession.totalBytes = files.reduce((sum, file) => sum + file.size, 0)
    diagnostics.info('receive', 'file list decrypted from link', { files: files.length, fileSizes: files.map(file => file.size), plaintextHashPrefixes: files.map(file => String(file.sha256).slice(0, 8)) })
  } catch (error) {
    if (receiveSession.token !== token) return
    diagnostics.error('receive', 'file list could not be decrypted', error)
    setReceiveHeading('This link does not work', '')
    setReceiveStage('invalid-link')
    return
  }

  const files = receiveSession.files
  setReceiveHeading(files.length === 1 ? 'A file for you' : files.length + ' files for you', 'Encrypted end to end. Only people with this link can open them.')
  renderFileRows(elementById('receive-file-list'), files)
  elementById('receive-file-summary').textContent = describeFileTotals(files)
  // Each side runs its own network mode, and each mode only shapes that side's own traffic, so
  // they do not need to match. The sentence says so, because "the sender uses another mode" reads
  // as if the recipient had to match it.
  const ownMode = MODE_LABELS[currentMode()]
  elementById('receive-mode').textContent = link.mode === currentMode()
    ? 'Your network mode: ' + ownMode + ', the same as the sender. Each side\'s mode only affects its own connection.'
    : 'Your network mode: ' + ownMode + '. It only affects your own connection; the sender chose ' + MODE_LABELS[link.mode] + ' for theirs.'
  await connectReceiver()
}

/** Joins Nym (reusing the running client) and asks the sender whether it is online. */
async function connectReceiver () {
  const token = receiveSession.token
  receiveSession.senderOnline = false
  setReceiveStage(currentNymNode ? 'reaching' : 'connecting')
  let node
  try {
    node = await getNymNode(currentMode())
  } catch (error) {
    if (receiveSession.token !== token) return
    diagnostics.error('receive', 'could not join Nym', error)
    setReceiveStage('error', { caption: 'Could not connect to the Nym network: ' + (error?.message ?? String(error)) })
    return
  }
  if (receiveSession.token !== token) return
  receiveSession.node = node
  if (!receiveSession.recipientId) receiveSession.recipientId = bytesToHex(crypto.getRandomValues(new Uint8Array(16)))
  setReceiveStage('reaching')
  startHelloRetries()
  clearTimeout(receiveSession.replyTimer)
  clearTimeout(receiveSession.giveUpTimer)
  receiveSession.replyTimer = setTimeout(() => {
    if (receiveSession.token !== token || receiveSession.stage !== 'reaching') return
    diagnostics.warn('receive', 'sender did not answer within ' + SENDER_REPLY_TIMEOUT_MS / 1000 + ' s; still trying', { hellosSent: receiveSession.hellosSent })
    setReceiveStage('reaching-slow', { keepTimer: true })
  }, SENDER_REPLY_TIMEOUT_MS)
  receiveSession.giveUpTimer = setTimeout(() => {
    if (receiveSession.token !== token || (receiveSession.stage !== 'reaching' && receiveSession.stage !== 'reaching-slow')) return
    stopHelloRetries()
    receiveSession.downloadRequested = false
    diagnostics.warn('receive', 'sender did not answer within ' + RECEIVER_GIVE_UP_MS / 1000 + ' s; stopped asking', { hellosSent: receiveSession.hellosSent })
    setReceiveStage('unreachable')
  }, RECEIVER_GIVE_UP_MS)
}

// Sends "hello" now and repeats it until the sender answers or refuses. Each repeat carries the
// same recipient id, so the sender counts this recipient once however many arrive.
function startHelloRetries () {
  stopHelloRetries()
  receiveSession.hellosSent = 0
  receiveSession.helloSentAt = new Map()
  receiveSession.helloStartedAt = performance.now()
  sendHelloAndScheduleNext()
}
// No return address: the sender answers through the reply blocks attached to each hello.
function sendHelloAndScheduleNext () {
  sendNumberedHello()
  const waitedMs = performance.now() - receiveSession.helloStartedAt
  receiveSession.helloTimer = setTimeout(sendHelloAndScheduleNext, waitedMs < SENDER_REPLY_TIMEOUT_MS ? HELLO_RETRY_INTERVAL_MS : HELLO_RETRY_SLOW_INTERVAL_MS)
}
// Sends one hello with the next attempt number and remembers when, so the answer (which echoes the
// number) gives a true round trip even when answers arrive out of order.
function sendNumberedHello () {
  receiveSession.hellosSent += 1
  receiveSession.helloSentAt.set(receiveSession.hellosSent, performance.now())
  receiveSession.node.sendControl({ kind: 'hello', infoHash: receiveSession.link.infoHash, recipientId: receiveSession.recipientId, attempt: receiveSession.hellosSent }, receiveSession.link.senderAddress).catch(() => {})
}

function stopHelloRetries () {
  clearTimeout(receiveSession.helloTimer)
  receiveSession.helloTimer = null
}

function handleReceiverControl (message) {
  const helloSentAt = typeof message.attempt === 'number' ? receiveSession.helloSentAt.get(message.attempt) : undefined
  const replyMs = helloSentAt === undefined ? null : Math.round(performance.now() - helloSentAt)
  if (replyMs !== null && (message.kind === 'available' || message.kind === 'refused')) recordRoundTrip('hello ' + message.attempt, replyMs)
  const finished = receiveSession.stage === 'done' || receiveSession.stage === 'failed-check' || receiveSession.stage === 'checking'

  if (message.kind === 'stopped') {
    diagnostics.warn('receive', 'the sender stopped sharing', { downloading: receiveSession.downloading })
    if (finished) return
    endReceiverTransfer()
    setReceiveStage('stopped')
    return
  }
  if (message.kind === 'refused') {
    diagnostics.warn('receive', 'sender refused', { reason: message.reason, roundTripMs: replyMs })
    if (finished) return
    endReceiverTransfer()
    setReceiveStage(message.reason === 'limit' ? 'full' : 'refused')
    return
  }
  if (message.kind !== 'available') {
    diagnostics.warn('receive', 'unexpected control message', describeControlMessage(message))
    return
  }
  if (receiveSession.downloading) {
    // An answer to a sender check made during a stall: the sender is up, so open a fresh link.
    const stall = receiveSession.stall
    if (stall.stage === 'checking-sender' || stall.stage === 'gave-up') {
      diagnostics.info('receive', 'sender answered during a stall; opening a new link', { roundTripMs: replyMs, senderChecks: stall.senderChecks })
      stall.stage = 'relinked'
      stall.relinks += 1
      setReceiveStage('reconnecting')
      openReceiverLink('sender answered after a stall')
    }
    return
  }
  if (receiveSession.senderOnline) {
    // Repeated hellos can each be answered; only the first answer matters.
    diagnostics.info('receive', 'extra answer to an earlier hello', { answeredAttempt: message.attempt ?? null })
    return
  }
  if (finished || (RECEIVE_TERMINAL_STAGES.has(receiveSession.stage) && receiveSession.stage !== 'unreachable')) return
  receiveSession.senderOnline = true
  clearTimeout(receiveSession.replyTimer)
  clearTimeout(receiveSession.giveUpTimer)
  stopHelloRetries()
  diagnostics.info('receive', 'sender is online', { roundTripMs: replyMs, hellosSent: receiveSession.hellosSent, sinceFirstHelloMs: Math.round(performance.now() - receiveSession.helloStartedAt), answeredAttempt: message.attempt ?? null, downloadAlreadyRequested: receiveSession.downloadRequested })
  if (receiveSession.downloadRequested) beginDownload()
  else setReceiveStage('online')
}

/** Download pressed. Before the sender has answered, the download waits for that answer. */
function requestDownload () {
  if (receiveSession.downloading || !receiveSession.files) return
  if (!receiveSession.senderOnline) {
    receiveSession.downloadRequested = true
    diagnostics.info('receive', 'download requested before the sender answered; it starts on the answer')
    updateReceiveControls()
    return
  }
  beginDownload()
}

function beginDownload () {
  receiveSession.downloadRequested = false
  startDownload().catch(error => {
    diagnostics.error('receive', 'download could not start', error)
    endReceiverTransfer()
    setReceiveStage('error', { caption: error?.message ?? String(error) })
  })
}

async function startDownload () {
  const link = receiveSession.link
  const { WebTorrent } = await loadLibraries()
  receiveSession.downloading = true
  receiveSession.downloadStartedAt = performance.now()
  receiveSession.rateMeter = new RateMeter()
  setReceiveStage('setting-up')
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
  if (!receiveSession.downloading || receiveSession.torrent !== torrent) return

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
    stage: receiveSession.stage,
    stall: Object.assign({ quietMs: Date.now() - receiveSession.lastDataAt, linkGeneration: receiveSession.linkGeneration, lateFramesDropped: receiveSession.lateFramesDropped, roundTripsMs: receiveSession.roundTrips }, receiveSession.stall, stallThresholds()),
    nym: receiveSession.node.counters,
    links: describeLinks([receiveSession.linkStream])
  }))
  torrent.once('done', () => finishDownload(torrent))
}

/** Runs every second while the receive view is open: elapsed time, progress, speed, time left. */
function updateReceiveProgress () {
  const torrent = receiveSession.torrent
  if (receiveSession.downloading && torrent) {
    const received = Math.min(receiveSession.totalBytes, Math.round(torrent.progress * receiveSession.totalBytes))
    const speed = receiveSession.rateMeter.update(torrent.downloaded)
    elementById('stat-received').textContent = formatBytes(received)
    elementById('stat-download').textContent = formatBytes(speed) + '/s'
    elementById('stat-eta').textContent = torrent.length && speed > 0 ? formatDuration((torrent.length - torrent.downloaded) / speed) : 'Estimating'
    if (receiveSession.stage === 'setting-up' && torrent.downloaded > 0) setReceiveStage('receiving')
    else renderReceiveStatus()
    updateDocumentTitle()
    return
  }
  renderElapsed('receive')
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
  // WebTorrent closes a peer whose BitTorrent handshake never arrives, and a link can also fail
  // on a write error. Either way, waiting longer on it cannot help.
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
    if (current.stats.framesIn === 0) recordRoundTrip('link ' + receiveSession.linkGeneration + ' first frame', performance.now() - current.openedAt)
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
  setReceiveStage(receiveSession.torrent?.downloaded > 0 ? 'receiving' : 'setting-up')
}

// This page moved to another gateway (its own gateway stopped delivering). The sender answers
// through reply blocks that lead to the old gateway, so a new link, which carries fresh ones, is
// opened at once instead of waiting for the stall timer.
function handleReceiverReconnected (sameAddress) {
  if (sameAddress) return
  // Still waiting for the sender's first answer: an answer to an earlier hello would go to the old
  // gateway, so ask again now, with reply blocks for the new one, instead of at the next retry.
  if (!receiveSession.downloading && receiveSession.helloTimer && !receiveSession.senderOnline) {
    diagnostics.info('receive', 'this page moved to another gateway; asking the sender again now', { hellosSent: receiveSession.hellosSent })
    stopHelloRetries()
    sendHelloAndScheduleNext()
    return
  }
  if (!receiveSession.downloading || !receiveSession.stall) return
  const stall = receiveSession.stall
  diagnostics.info('receive', 'this page moved to another gateway; opening a new link to the sender', { linkGeneration: receiveSession.linkGeneration })
  if (stall.stage === 'healthy') stall.stalledAt = receiveSession.lastDataAt
  stall.stage = 'relinked'
  stall.relinks += 1
  setReceiveStage('reconnecting')
  openReceiverLink('this page moved to another gateway')
}

// Runs every STALL_CHECK_INTERVAL_MS while downloading. While this page's own Nym client is
// reconnecting, the node handles recovery and the stall clock is not acted on.
function checkReceiverHealth () {
  if (!receiveSession.downloading || !receiveSession.stall) return
  const node = receiveSession.node
  if (node.state !== 'connected') return
  const stall = receiveSession.stall
  if (stall.stage === 'gave-up') return
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

  const thresholds = stallThresholds()
  if (stall.stage === 'healthy' && quietMs >= thresholds.relinkAfterMs) {
    stall.stage = 'relinked'
    stall.stalledAt = receiveSession.lastDataAt
    stall.relinks += 1
    diagnostics.warn('receive', 'no data for ' + Math.round(quietMs / 1000) + ' s; opening a new link', Object.assign(transferState(), thresholds))
    setReceiveStage('reconnecting')
    openReceiverLink('stalled')
    return
  }
  if (stall.stage === 'checking-sender' && now - stall.stalledAt >= RECEIVER_STALL_GIVE_UP_MS) {
    stall.stage = 'gave-up'
    diagnostics.warn('receive', 'no data for ' + Math.round((now - stall.stalledAt) / 1000) + ' s and no answer from the sender; stopped asking', transferState())
    setReceiveStage('lost')
    return
  }
  if (stall.stage !== 'healthy' && now - stall.relinkedAt >= thresholds.senderCheckAfterRelinkMs && now - stall.lastSenderCheckAt >= thresholds.senderCheckIntervalMs) {
    checkSenderDuringStall('no data on the new link', Object.assign(transferState(), thresholds))
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
  if (receiveSession.stage !== 'waiting-sender') setReceiveStage('waiting-sender')
  sendNumberedHello()
}

/** Try again: after the sender stopped answering, before or during the download. */
function retryReceive () {
  diagnostics.info('receive', 'trying again', { stage: receiveSession.stage })
  if (receiveSession.stage === 'lost' && receiveSession.downloading && receiveSession.stall) {
    receiveSession.stall.stage = 'checking-sender'
    receiveSession.stall.stalledAt = Date.now()
    checkSenderDuringStall('trying again')
    return
  }
  if (receiveSession.downloading) endReceiverTransfer()
  connectReceiver()
}

/** Stops everything this download has running: hellos, timers, the torrent and the wake lock. */
function endReceiverTransfer () {
  stopHelloRetries()
  clearTimeout(receiveSession.replyTimer)
  clearTimeout(receiveSession.giveUpTimer)
  clearInterval(receiveSession.monitorTimer)
  receiveSession.monitorTimer = null
  receiveSession.stopSnapshots?.()
  receiveSession.stopSnapshots = null
  receiveSession.downloadRequested = false
  if (receiveSession.linkStream && !receiveSession.linkStream.destroyed) {
    receiveSession.linkStream.retiredByReceiver = true
    receiveSession.linkStream.destroy()
  }
  if (receiveSession.client) {
    const client = receiveSession.client
    receiveSession.client = null
    client.destroy(error => { if (error) diagnostics.warn('receive', 'webtorrent client did not close cleanly', error) })
  }
  receiveSession.downloading = false
  receiveSession.torrent = null
  receiveSession.linkStream = null
  releaseWakeLock('receiving')
}

async function finishDownload (torrent) {
  if (receiveSession.torrent !== torrent) return
  receiveSession.downloading = false
  clearInterval(receiveSession.monitorTimer)
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
    nym: receiveSession.node.counters,
    gatewayTraffic: receiveSession.node.describeGatewayTraffic()
  })
  setReceiveStage('checking')
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
    if (receiveSession.torrent !== torrent) return
    receiveSession.results = results
    const allVerified = results.every(result => result.verified)
    receiveSession.node.sendControl({ kind: 'complete', infoHash: receiveSession.link.infoHash, linkId: bytesToHex(receiveSession.linkStream.linkIdBytes), recipientId: receiveSession.recipientId, verified: allVerified }, receiveSession.link.senderAddress).catch(() => {})

    setReceiveHeading(allVerified ? 'Ready to save' : 'Do not trust these files', allVerified ? 'Every file was decrypted and matches what the sender shared.' : '')
    renderReceivedFiles()
    if (allVerified) {
      setReceiveStage('done', { caption: 'Received ' + formatBytes(receiveSession.totalBytes) + ' in ' + formatElapsed(transferSeconds) + '. Save the files before you leave; they exist only in this tab.' })
    } else {
      setReceiveStage('failed-check')
    }
    await new Promise(resolve => receiveSession.client ? receiveSession.client.destroy(resolve) : resolve())
    receiveSession.client = null
    diagnostics.info('receive', 'done', { allVerified, totalSeconds: Number(((performance.now() - receiveSession.downloadStartedAt) / 1000).toFixed(1)) })
    if (allVerified) elementById('save-all').focus({ preventScroll: true })
  } catch (error) {
    diagnostics.error('receive', 'decryption failed', error)
    setReceiveStage('error', { caption: 'Decryption failed: ' + (error?.message ?? String(error)) })
  }
}

function renderReceivedFiles () {
  renderFileRows(elementById('receive-file-list'), receiveSession.files, {
    verified: receiveSession.results.map(result => result.verified),
    saved: receiveSession.savedIndexes,
    onSave: saveFile
  })
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
  receiveSession.savedIndexes.add(index)
  renderReceivedFiles()
}

async function saveAllFiles () {
  for (let index = 0; index < (receiveSession.results?.length ?? 0); index += 1) {
    saveFile(index)
    await new Promise(resolve => setTimeout(resolve, 400)) // browsers drop rapid back-to-back downloads
  }
}

function hasUnsavedFiles () {
  return Boolean(receiveSession.results) && receiveSession.results.some((result, index) => !receiveSession.savedIndexes.has(index))
}

/**
 * Back, Cancel or Done in the receive view, or the browser's Back button. A download in progress
 * and verified files not yet saved each ask first. When the browser's Back button started it and
 * the person chooses to stay, the receive view's history entry is put back.
 */
let ignoreNextPopState = false
async function requestLeaveReceiveView ({ fromHistory = false } = {}) {
  const stayInView = () => { if (fromHistory) history.pushState({ view: 'receive' }, '', cleanPageUrl()) }
  if (receiveSession.downloading) {
    const confirmed = await confirmAction({ title: 'Stop receiving?', message: 'What you have received so far will be discarded, and the sender will be told you cancelled.', confirmLabel: 'Stop receiving', cancelLabel: 'Keep receiving' })
    if (!confirmed) return stayInView()
  } else if (receiveSession.stage === 'done' && hasUnsavedFiles()) {
    const confirmed = await confirmAction({ title: 'Leave without saving?', message: 'The files exist only in this tab. After you leave, the sender would have to share them again.', confirmLabel: 'Leave', cancelLabel: 'Stay' })
    if (!confirmed) return stayInView()
  }
  leaveReceiveView()
  if (!fromHistory && history.state?.view === 'receive') {
    ignoreNextPopState = true
    history.back()
  }
}

function leaveReceiveView () {
  const stage = receiveSession.stage
  // Tell the sender this recipient is gone, unless the sender already knows or never heard of it.
  const senderKnowsUs = receiveSession.hellosSent > 0 && !['done', 'failed-check', 'stopped', 'full', 'refused'].includes(stage)
  if (senderKnowsUs && receiveSession.node && receiveSession.link) {
    receiveSession.node.sendControl({ kind: 'cancel', infoHash: receiveSession.link.infoHash, recipientId: receiveSession.recipientId, stage: receiveSession.downloading ? 'downloading' : 'before-download' }, receiveSession.link.senderAddress).catch(() => {})
  }
  diagnostics.info('receive', 'left the receive view', { stage, toldSender: senderKnowsUs })
  endReceiverTransfer()
  clearInterval(receiveSession.uiTimer)
  Object.assign(receiveSession, createReceiveSessionState(), { token: receiveSession.token + 1 })
  resetReceiveView()
  showView('view-choose')
  noteUserActivity()
}

// ---------------------------------------------------------------------------
// Gateway test (?gatewaytest=N)
// ---------------------------------------------------------------------------
// A measurement tool, not part of normal use. Opened with ?gatewaytest=N, the page connects N
// times in a row, each time with a fresh identity on a random gateway, cycling through three
// score bands so they can be compared. For each run it records the gateway's published score,
// how long connecting took and when each network step happened, the share of acknowledgements
// that came back over the first check and over a further 20 s, the round trip of messages sent
// to its own address, and how long reconnecting to the same gateway and moving to a new one took.
// Every client is stopped before the next starts. Results go to the Diagnostics log and to
// window.nymShareGatewayTest; a table on the page shows progress.
const GATEWAY_TEST_BANDS = [
  { label: 'below 0.95', minimumPerformance: 0.5, maximumPerformance: 0.95 },
  { label: '0.95 to 0.98', minimumPerformance: 0.95, maximumPerformance: 0.99 },
  { label: '0.99 and up', minimumPerformance: 0.99, maximumPerformance: Infinity }
]
const GATEWAY_TEST_STEADY_MS = 20000
const GATEWAY_TEST_PROBES = 3
const GATEWAY_TEST_PROBE_TIMEOUT_MS = 20000
const GATEWAY_TEST_MAX_RUNS = 60

function median (values) {
  const numbers = values.filter(value => typeof value === 'number' && Number.isFinite(value)).sort((left, right) => left - right)
  if (numbers.length === 0) return null
  const middle = Math.floor(numbers.length / 2)
  return numbers.length % 2 ? numbers[middle] : Math.round((numbers[middle - 1] + numbers[middle]) / 2 * 100) / 100
}

/** Summarises the connect timeline: when the Nym API work ended and the gateway socket opened. */
function summariseConnectSteps (steps) {
  const timeline = steps?.timeline ?? []
  const nymApi = timeline.filter(step => step.event === 'fetched' && step.target.startsWith('nym api'))
  const opened = timeline.filter(step => step.event === 'gateway socket open')
  const closed = timeline.filter(step => step.event === 'gateway socket closed')
  return {
    nymApiFetches: nymApi.length,
    nymApiDoneMs: nymApi.length ? Math.max(...nymApi.map(step => step.atMs)) : null,
    firstGatewaySocketOpenMs: opened.length ? opened[0].atMs : null,
    gatewaySocketsOpened: opened.length,
    gatewaySocketsClosedBeforeConnected: closed.filter(step => step.atMs <= (steps?.connectedAfterMs ?? Infinity)).length,
    connectedMs: steps?.connectedAfterMs ?? null
  }
}

async function runGatewayTest (runs) {
  const mode = currentMode()
  const results = []
  const state = { mode, runs, results, summary: null, running: true }
  window.nymShareGatewayTest = state
  const progress = createElement('p', { className: 'muted small' })
  const table = createElement('div', { className: 'log-output', role: 'log' })
  const card = createElement('section', { className: 'card' }, [createElement('h2', { text: 'Gateway test' }), progress, table])
  document.querySelector('main').prepend(card)
  const render = () => {
    progress.textContent = (state.running ? 'Run ' + Math.min(results.length + 1, runs) + ' of ' + runs : 'Finished ' + runs + ' runs') + ' in ' + MODE_LABELS[mode] + '. Each run takes about a minute; keep this tab in front.'
    table.textContent = results.map(result => [
      String(result.run).padStart(2), result.band.padEnd(12), String(result.gateway?.score ?? '-').padEnd(5),
      'connect ' + (result.connectMs ?? '-') + ' ms', 'acks ' + (result.firstCheckAcknowledgements ?? '-') + '/' + (result.steadyAcknowledgements ?? '-'),
      'probe ' + (result.probeMs?.map(value => value ?? 'lost').join(',') ?? '-'), 'reconnect ' + (result.reconnectMs ?? '-') + ' ms', 'move ' + (result.moveMs ?? '-') + ' ms',
      result.error ? 'ERROR ' + result.error : ''
    ].join('  ')).join('\n') + (state.summary ? '\n\n' + JSON.stringify(state.summary, null, 1) : '')
  }
  render()
  diagnostics.info('gwtest', 'gateway test started', { runs, mode, bands: GATEWAY_TEST_BANDS.map(band => band.label) })

  for (let run = 1; run <= runs; run += 1) {
    const band = GATEWAY_TEST_BANDS[(run - 1) % GATEWAY_TEST_BANDS.length]
    const result = { run, band: band.label }
    let node = null
    try {
      // The test samples bands as published: it neither skips nor records failed gateways.
      node = await createNymNode(mode, null, { gatewayBand: Object.assign({ skipRecentFailures: false }, band), rememberFailures: false })
      result.gateway = describeGateway(node.gateway)
      result.connectMs = node.connectMs
      const verdict = await node.waitForHealthVerdict(HEALTH_FIRST_CHECK_MS + 6000)
      result.firstCheck = verdict
      result.firstCheckAcknowledgements = node.health.acknowledgementReturn
      result.connectSteps = summariseConnectSteps(node.lastConnectSteps)

      const before = await node.readGatewayTraffic()
      const steadyStartedAt = performance.now()
      result.probeMs = []
      for (let probe = 0; probe < GATEWAY_TEST_PROBES; probe += 1) {
        try {
          result.probeMs.push(await node.probeSelf(GATEWAY_TEST_PROBE_TIMEOUT_MS))
        } catch (error) {
          result.probeMs.push(null)
        }
      }
      const remainingMs = GATEWAY_TEST_STEADY_MS - (performance.now() - steadyStartedAt)
      if (remainingMs > 0) await new Promise(resolve => setTimeout(resolve, remainingMs))
      const after = await node.readGatewayTraffic()
      const packetsOut = after.binaryMessagesOut - before.binaryMessagesOut
      const acknowledgements = after.acknowledgementsIn - before.acknowledgementsIn
      const fullPackets = (after.binaryMessagesIn - after.acknowledgementsIn) - (before.binaryMessagesIn - before.acknowledgementsIn)
      result.steadySeconds = Math.round((after.sampledAtMs - before.sampledAtMs) / 1000)
      result.steadyPacketsOut = packetsOut
      result.steadyAcknowledgements = packetsOut ? Math.round(acknowledgements / packetsOut * 100) / 100 : null
      result.steadyFullPacketsBack = packetsOut ? Math.round(fullPackets / packetsOut * 100) / 100 : null

      // The two kinds of switch: reconnecting to the same gateway (keeps the address) and moving
      // this identity to a new gateway (what a failed health check does).
      const addressBefore = node.address
      if (await node.reconnect('gateway test: reconnect to the same gateway')) {
        result.reconnectMs = node.lastReconnectMs
        result.reconnectKeptAddress = node.address === addressBefore
      }
      if (await node.reconnect('gateway test: move to a new gateway', { newGateway: true })) {
        result.moveMs = node.lastReconnectMs
        result.movedTo = describeGateway(node.gateway)
      }
    } catch (error) {
      result.error = error?.message ?? String(error)
    } finally {
      if (node) await node.stop()
    }
    results.push(result)
    diagnostics.info('gwtest', 'run ' + run + ' of ' + runs, result)
    render()
  }

  state.summary = Object.fromEntries(GATEWAY_TEST_BANDS.map(band => {
    const inBand = results.filter(result => result.band === band.label)
    const completed = inBand.filter(result => !result.error)
    const probes = completed.flatMap(result => result.probeMs ?? [])
    return [band.label, {
      runs: inBand.length,
      failedToConnect: inBand.filter(result => result.connectMs === undefined).length,
      firstCheckFailed: completed.filter(result => result.firstCheck === 'degraded').length,
      medianConnectMs: median(completed.map(result => result.connectMs)),
      medianFirstCheckAcknowledgements: median(completed.map(result => result.firstCheckAcknowledgements)),
      medianSteadyAcknowledgements: median(completed.map(result => result.steadyAcknowledgements)),
      lowestSteadyAcknowledgements: completed.length ? Math.min(...completed.map(result => result.steadyAcknowledgements ?? 1)) : null,
      medianProbeMs: median(probes),
      probesLost: probes.filter(value => value === null).length + ' of ' + probes.length,
      medianReconnectMs: median(completed.map(result => result.reconnectMs)),
      medianMoveMs: median(completed.map(result => result.moveMs))
    }]
  }))
  state.running = false
  diagnostics.info('gwtest', 'gateway test finished', state.summary)
  render()
}

// ---------------------------------------------------------------------------
// Idle disconnect
// ---------------------------------------------------------------------------
// A connected tab uses about 0.8 to 2 GB of data an hour even with nothing to send. With nothing
// in progress (the start page, or a receive view that has ended), the page disconnects after
// NYM_IDLE_DISCONNECT_MS without activity. A click, a key press, a drag or returning to the tab
// reconnects on the start page; elsewhere the next action that needs Nym reconnects.
let idleTimer = null
function nothingInProgress () {
  const view = currentView()
  if (view === 'view-choose') return true
  if (view === 'view-receive') return RECEIVE_TERMINAL_STAGES.has(receiveSession.stage)
  return false
}
function noteUserActivity () {
  if (window.nymShareGatewayTest) return // the gateway test manages its own connections
  clearTimeout(idleTimer)
  idleTimer = setTimeout(disconnectIfIdle, NYM_IDLE_DISCONNECT_MS)
  if (!nymNodePromise && currentView() === 'view-choose') ensureNymConnected('activity on the start page')
}
function disconnectIfIdle () {
  if (!nymNodePromise) return
  if (!nothingInProgress()) {
    idleTimer = setTimeout(disconnectIfIdle, NYM_IDLE_DISCONNECT_MS)
    return
  }
  stopNymNode('no activity for ' + NYM_IDLE_DISCONNECT_MS / 60000 + ' minutes')
}

// Leaving the page loses a share in progress, a download in progress, or files not yet saved.
function shouldWarnBeforeLeaving () {
  return Boolean(sendSession.torrent) || receiveSession.downloading || (receiveSession.stage === 'done' && hasUnsavedFiles())
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

  const modeSelect = elementById('network-mode')
  modeSelect.addEventListener('change', () => {
    const mode = modeSelect.value
    fitSelectToSelection(modeSelect)
    storeMode(mode)
    diagnostics.info('nym', 'network mode changed', { mode })
    getNymNode(mode).catch(error => { if (error?.name !== 'AbortError') diagnostics.error('nym', 'mode switch failed', error) })
  })

  elementById('copy-link').addEventListener('click', async () => {
    const button = elementById('copy-link')
    try {
      await navigator.clipboard.writeText(elementById('share-link').value)
      setButtonContent(button, 'check', 'Copied')
    } catch (error) {
      elementById('share-link').select()
      setButtonContent(button, 'copy', /Mac|iPhone|iPad/.test(navigator.userAgent) ? 'Press Cmd+C' : 'Press Ctrl+C')
    }
    clearTimeout(button.resetTimer)
    button.resetTimer = setTimeout(() => setButtonContent(button, 'copy', 'Copy link'), 2000)
  })

  elementById('native-share').addEventListener('click', async () => {
    try {
      await navigator.share({ url: elementById('share-link').value })
    } catch (error) {
      if (error?.name !== 'AbortError') diagnostics.warn('send', 'share sheet failed', error)
    }
  })

  elementById('toggle-qr').addEventListener('click', async () => {
    const image = elementById('qr-image')
    const button = elementById('toggle-qr')
    if (!sendSession.qrDataUrl) {
      const { QRCode } = await loadLibraries()
      sendSession.qrDataUrl = await QRCode.toDataURL(elementById('share-link').value, { errorCorrectionLevel: 'L', margin: 1, width: 440 })
      image.src = sendSession.qrDataUrl
    }
    const showing = image.classList.toggle('hidden') === false
    button.setAttribute('aria-expanded', String(showing))
    setButtonContent(button, 'qr-code', showing ? 'Hide QR code' : 'Show QR code')
  })

  elementById('stop-sharing').addEventListener('click', () => requestStopSharing())
  elementById('share-start-over').addEventListener('click', () => stopSharing({ notifyRecipients: false }))

  const pasteInput = elementById('paste-input')
  elementById('paste-form').addEventListener('submit', event => {
    event.preventDefault()
    openShareLink(pasteInput.value.trim())
  })
  // A pasted link that parses opens straight away; anything else waits for Open.
  pasteInput.addEventListener('paste', () => setTimeout(() => {
    const pasted = pasteInput.value.trim()
    if (parseShareLink(pasted)) openShareLink(pasted)
  }, 0))
  pasteInput.addEventListener('input', () => showPasteError(''))

  elementById('receive-back').addEventListener('click', () => requestLeaveReceiveView())
  elementById('start-download').addEventListener('click', () => requestDownload())
  elementById('try-again').addEventListener('click', () => retryReceive())
  elementById('save-all').addEventListener('click', () => saveAllFiles())

  window.addEventListener('popstate', event => {
    if (ignoreNextPopState) {
      ignoreNextPopState = false
      return
    }
    if (currentView() === 'view-receive' && event.state?.view !== 'receive') {
      requestLeaveReceiveView({ fromHistory: true })
    } else if (currentView() !== 'view-receive' && event.state?.view === 'receive') {
      // Forward to a download that has already ended: there is nothing to return to.
      history.replaceState({ view: 'choose' }, '', cleanPageUrl())
    }
  })
  window.addEventListener('beforeunload', event => {
    if (!shouldWarnBeforeLeaving()) return
    event.preventDefault()
    event.returnValue = ''
  })
  for (const eventName of ['pointerdown', 'keydown', 'dragenter', 'touchstart']) {
    document.addEventListener(eventName, () => noteUserActivity(), { capture: true, passive: true })
  }
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') noteUserActivity() })

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

diagnostics.info('diag', 'page loaded', { session: SESSION_ID, pageVersion: PAGE_VERSION, faultInjection: FAULT_INJECTION_ENABLED, networkMode: readStoredMode() })
if (FAULT_INJECTION_ENABLED) {
  // Test controls for recovery. Each action is logged so test logs show exactly what was injected.
  window.nymShareFaults = {
    dropIncomingData (seconds) {
      faultInjection.dropIncomingDataUntil = Date.now() + seconds * 1000
      diagnostics.warn('fault', 'dropping all incoming data frames', { seconds })
    },
    delayIncomingMessages (milliseconds) {
      faultInjection.incomingDelayMs = Math.max(0, Number(milliseconds) || 0)
      diagnostics.warn('fault', 'delaying every incoming message', { milliseconds: faultInjection.incomingDelayMs })
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
    },
    // Makes the health check see no acknowledgements for this long, as on a gateway that stopped
    // delivering incoming messages, so the page's response can be tested on a working gateway.
    // Makes the next count connects see no progress from their gateway, so the page's response to
    // a stalled connect (abandon it after 8 s, try again) can be tested on a working gateway.
    stallConnects (count = 1) {
      faultInjection.stallConnects = Math.max(0, Number(count) || 0)
      diagnostics.warn('fault', 'the next connects will look stalled', { count: faultInjection.stallConnects })
    },
    // Lets failures caused by these controls be remembered like real ones, to test the memory.
    rememberFaultFailures (enabled = true) {
      faultInjection.rememberFaultFailures = Boolean(enabled)
      diagnostics.warn('fault', 'failures caused by fault controls ' + (enabled ? 'will' : 'will not') + ' be remembered')
    },
    rememberedGatewayFailures () {
      return Object.entries(readGatewayFailures()).map(([identity, failedAt]) => ({ gateway: identity.slice(0, 6) + '...', minutesAgo: Math.round((Date.now() - failedAt) / 60000) }))
    },
    hideAcknowledgements (seconds) {
      faultInjection.hideAcknowledgementsUntil = Date.now() + seconds * 1000
      diagnostics.warn('fault', 'hiding acknowledgements from the health check', { seconds })
    }
  }
  diagnostics.warn('fault', 'fault injection controls enabled through ?faults=1')
}
logEnvironment()
elementById('network-mode').value = readStoredMode()
fitSelectToSelection(elementById('network-mode'))
wireUserInterface()
updateModeControl()
renderIcons()
const gatewayTestRuns = Number.parseInt(new URLSearchParams(location.search).get('gatewaytest') ?? '', 10)
if (Number.isInteger(gatewayTestRuns) && gatewayTestRuns > 0) {
  // Measurement only: no normal connection, no idle disconnect.
  elementById('diagnostics').open = true
  runGatewayTest(Math.min(gatewayTestRuns, GATEWAY_TEST_MAX_RUNS)).catch(error => diagnostics.error('gwtest', 'gateway test failed', error))
} else if (location.hash.length > 1) {
  diagnostics.info('diag', 'link found in address bar; opening receive view')
  openShareLink(location.href, { fromAddressBar: true })
  noteUserActivity()
} else {
  history.replaceState({ view: 'choose' }, '', location.href)
  // Connect while the sender is still choosing files.
  ensureNymConnected('page opened')
  noteUserActivity()
}

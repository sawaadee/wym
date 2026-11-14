<!--
  README.md
  Purpose: what wym is, how it protects files and addresses, and how to build, verify and host it.
  Created: 2026-11-14
-->

# wym

End-to-end encrypted file sharing in the browser, where neither side learns the other's IP address and no server stores anything.

## How it works

The sender's browser encrypts each file with [wormhole-crypto](https://github.com/SocketDev/wormhole-crypto) (RFC 8188, AES-128-GCM) and shares the encrypted files as a private WebTorrent swarm. Every byte between sender and recipient travels through the [Nym mixnet](https://nym.com) as client-to-client messages, so the two browsers never connect to each other directly.

The share link carries everything a recipient needs after the `#`: the sender's Nym address, the torrent's infohash, the decryption key and an encrypted list of file names, sizes and SHA-256 checksums. Browsers never send the part after `#` to any server. Each received file is decrypted and checked against its checksum before it can be saved.

## What is and is not protected

- File contents and names are encrypted end to end. Only someone with the link can read them.
- Neither side learns the other's IP address. Each side's Nym entry node (gateway) sees that side's IP, but not who it is talking to.
- The sender never learns the recipient's Nym address. The recipient attaches single-use reply blocks to its messages, and the sender answers only through those. The recipient does learn the sender's Nym address, from the link.
- The sender's tab has to stay open until recipients finish. There is no cloud copy.
- Throughput through the mixnet is low. In testing, a 1 MB file took about 40 seconds.

## Using it

Open the page, drop in files and send the link. The recipient opens the link, or pastes it into the Receive box, and clicks Download. The Diagnostics panel at the bottom keeps a timestamped log that never contains keys, links, file names or full Nym addresses.

## Reliability

- If a Nym gateway connection drops and the Nym client does not restore it within 15 seconds, the page starts a new client with the same keys and the same gateway, so the address in a shared link keeps working. Only if that gateway refuses three reconnects does the page move to a new one, and then the sender sees a new link to send.
- A recipient that receives no data for 20 seconds opens a new link to the sender. If that brings nothing within 15 seconds, or a link closes early, it checks whether the sender is online every 20 seconds and resumes when the sender answers. Pieces already received are kept. On slow paths these waits grow with the measured round trip to the sender (three round trips before a new link, two before a check), up to three minutes, and WebTorrent's own handshake and request timeouts are raised from 25 and 30 seconds to two minutes (`build/webtorrent-latency-patch.mjs`).
- Recipients repeat their first message to the sender until it answers, because messages through the mixnet can be delayed or lost.
- While sending or receiving, the page asks the browser to keep the screen awake.

## Testing

The Diagnostics panel logs every step, including how long each control message spent in transit. It also measures what the page actually sends to and receives from its Nym gateway: every 10 seconds it reads how many Sphinx packets and bytes went each way, and logs a `gateway traffic` entry with packets per second, megabits per second and the share of the rate Nym's settings ask for (55 packets per second in Maximum, 505 in Balanced). Windows in which data or control messages crossed the mixnet are logged as `busy` every 10 seconds; quiet windows are logged as `idle` once a minute. Each entry carries the running idle and busy averages, which also appear when a transfer finishes and when a client stops.

Opening the page with `?faults=1` adds test controls in the browser console:

- `nymShareFaults.dropIncomingData(seconds)` discards all incoming data for that long.
- `nymShareFaults.delayIncomingMessages(milliseconds)` holds every incoming message for that long, imitating a slow path. Pass 0 to stop.
- `nymShareFaults.closeGatewaySockets()` closes this page's connection to its Nym gateway.
- `nymShareFaults.replaceNymClient()` replaces the Nym client immediately.

Share links made with `?faults=1` open with the same controls on the recipient's side.

## Building

```sh
npm ci
npm run build
```

`build.mjs` bundles `src/app.js` with every library it imports, at the versions pinned in `package-lock.json`, and inlines the result into `src/page.html`. It also applies `build/nym-reply-patch.mjs` to the Nym SDK, whose web worker otherwise drops the tag needed to answer through reply blocks; the build stops if the SDK version or the patched code changes. The output is a single file, `docs/index.html`, which loads nothing from a CDN at runtime.

## Verifying a build

`docs/SHA256SUMS` holds the checksum of `docs/index.html`. The build does not depend on the time or machine it runs on, so anyone can reproduce it:

```sh
npm ci
npm run verify
```

To check the page a browser loaded, save it and compare `shasum -a 256 index.html` with `docs/SHA256SUMS` at the matching commit.

## Hosting on GitHub Pages

In the repository's Settings, open Pages and set the source to **Deploy from a branch**, branch `main`, folder `/docs`.

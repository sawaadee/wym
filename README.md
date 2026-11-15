<!--
  README.md
  Purpose: what wym is, how it protects files and addresses, and how to build, verify and host it.
  Created: 2026-11-14
-->

# wym

End-to-end encrypted file sharing in the browser, where neither side learns the other's IP address and no server stores anything.

## How it works

The sender's browser encrypts each file with [wormhole-crypto](https://github.com/SocketDev/wormhole-crypto) (RFC 8188, AES-128-GCM) and shares the encrypted files as a private WebTorrent swarm. Every byte between sender and recipient travels through the [Nym mixnet](https://nym.com) as client-to-client messages, so the two browsers never connect to each other directly.

The share link carries everything a recipient needs after the `#`: the sender's Nym address, the torrent's infohash, the decryption key and an encrypted list of file names, sizes and SHA-256 checksums. Browsers never send the part after `#` to any server. As soon as a link is opened, the page replaces it in the address bar and the session history with the bare page address, so the key does not stay there. Each received file is decrypted and checked against its checksum before it can be saved.

## What is and is not protected

- File contents and names are encrypted end to end. Only someone with the link can read them.
- Neither side learns the other's IP address. Each side's Nym entry node (gateway) sees that side's IP, but not who it is talking to.
- The sender never learns the recipient's Nym address. The recipient attaches single-use reply blocks to its messages, and the sender answers only through those. The recipient does learn the sender's Nym address, from the link.
- The sender's tab has to stay open until recipients finish. There is no cloud copy.
- Throughput through the mixnet is low. In testing, a transfer spent 15 to 25 seconds on setup, then moved roughly 15 to 25 KB per second.

## Using it

Open the page, drop in files (up to 500 MB in total, because both sides hold everything in memory) and send the link. The recipient opens the link, or pastes it into the Receive box, and clicks Download; pressing Download before the sender has answered starts the download as soon as it does. The sender sees each recipient in a list, numbered in the order they made contact, with their progress.

### Received files

Once every file is decrypted and matches its checksum, each one can be saved. Photos, videos, audio and plain text can also be previewed in the page: images (JPEG, PNG, GIF, WebP, AVIF, BMP, and HEIC where the browser supports it, up to 40 MB), MP4, MOV and WebM video, common audio formats, and the first 256 KB of a text file. Only types on that list are shown, and only through image, video, audio or plain-text elements, where a file cannot run code; SVG, HTML and PDF are never previewed. Files that fail the check can be saved but are never previewed. On phones and tablets, Share opens the system share sheet; on an iPhone or iPad that is how a photo or video reaches Photos (Save Image or Save Video), since Save puts it in Files. Previews are released when the recipient leaves the page's receive view.

### Network mode

The mode menu at the top applies to the whole page and is remembered in the browser. Balanced asks the Nym client for a packet every 11 ms instead of Nym's default 20 ms: about 96 packets a second with cover traffic (about 1.9 Mbps up, inside the 0.7 to 2 Mbps range NymVPN users can choose), against 55 (about 1.1 Mbps) for Maximum privacy, which uses Nym's defaults. Balanced used to ask for 2 ms, which no browser delivered: desktop browsers capped it at about 135 a second and Brave with DevTools open at about 66, so its rate depended on the machine. At 11 ms the rate is what was asked for. The two sides do not need the same mode: each mode only shapes that side's own traffic. Changing the mode while a client is still connecting cancels it at once instead of waiting for it to finish.

### Data use

A connected tab uses about 0.8 GB of data an hour in Maximum privacy and about 1.4 GB in Balanced, even with nothing to send, because the Nym client keeps a steady stream of cover traffic. The share view shows the rate measured on its own connection. With nothing in progress (the start page, or a finished or failed download), the page disconnects after 5 minutes without activity and reconnects on the next click, key press or return to the tab.

### Updates

An open tab keeps running the version it loaded, so the page checks whether the site has a newer one: when the tab comes back into view, and every 30 minutes while it stays in view, it reads `version.json` from the same site that served it, with no cookies or referrer. If the site's version is newer, the start page shows a notice with a Reload button. The notice never appears during a share or a download; it waits until the person is back on the start page. Not now hides it until the next version.

### Stopping and cancelling

- Stop sharing asks first, then tells every recipient who has not finished that sharing stopped, through the reply blocks they sent. A recipient who opens the link later is told the same.
- A recipient can go back before downloading, cancel during a download (it asks first and tells the sender, which frees the place under the recipient limit), or press Done afterwards (it asks first if files are not saved yet). The browser's Back button does the same as the on-page button.
- A recipient stops asking an unresponsive sender after 3 minutes before the download, or after 5 minutes of a stalled download, and offers Try again. Pieces already received are kept.

## Reliability

- If a Nym gateway connection drops and the Nym client does not restore it within 15 seconds, the page starts a new client with the same keys and the same gateway, so the address in a shared link keeps working. Only if that gateway refuses three reconnects does the page move to a new one, and then the sender sees a new link to send.
- If the Nym client fails to start, the page notices at once instead of waiting out the 8-second stall limit (the Nym SDK only logs such failures, so `build/nym-reply-patch.mjs` passes them to the page) and tries another gateway. These failures are usually network-wide: on 15 November 2026 a new Nym epoch began at 00:26 UTC while the Nym API still served the node list it built at 00:22, and every client started in the next minutes refused to start because one mixing layer looked empty. So failed starts are retried with pauses that double from 1 to 20 seconds, for up to 5 minutes, without using up the three normal connect attempts.
- Every call into the Nym client's worker has a time limit (30 seconds to load it, 10 seconds for a start or a send, 3 seconds to stop it, after which it is ended anyway), so a worker that stops answering can never hold a connect, reconnect or mode switch open. A worker that does not answer the page's 10-second traffic reading is replaced.
- A recipient that receives no data for 20 seconds opens a new link to the sender. If that brings nothing within 15 seconds, or a link closes early, it checks whether the sender is online every 20 seconds and resumes when the sender answers. Pieces already received are kept. On slow paths these waits grow with the measured round trip to the sender (three round trips before a new link, two before a check), up to three minutes, and WebTorrent's own handshake and request timeouts are raised from 25 and 30 seconds to two minutes (`build/webtorrent-latency-patch.mjs`).
- Recipients repeat their first message to the sender until it answers, because messages through the mixnet can be delayed or lost.
- While sending or receiving, the page asks the browser to keep the screen awake.

## Gateway choice and health

Each side connects to the Nym mixnet through one gateway, and a gateway can keep its connection open while delivering almost nothing back. Measured with the page's gateway test (`?gatewaytest=24`, below) on 14 November 2026, with 24 fresh connections across Nym's published score bands:

| Gateway score | Runs | Failed to connect | Broken or slow at connect | Median connect | Median reconnect, same gateway | Median move to a new gateway |
| --- | --- | --- | --- | --- | --- | --- |
| below 0.95 | 8 | 1 | 4 | 6.5 s | 3.4 s | 4.7 s |
| 0.95 to 0.98 | 8 | 0 | 2 | 5.6 s | 3.9 s | 6.7 s |
| 0.99 and up | 8 | 0 | 2 | 5.8 s | 3.3 s | 5.4 s |

So the page does three things:

- It fetches Nym's gateway list once per page load and picks a gateway at random among those a browser can reach that score at least 0.95 (560 of 580 at the time), never one it already tried, and none that failed in this browser in the last 24 hours (the browser keeps at most 50 such failures, dropping the oldest). The same gateway failed every time it was drawn, across two days, while its score moved from 0.94 to 0.95. A connect that never hears from its gateway at all is only held against the gateway once some other gateway has connected from this page, because a network that blocks the gateways' port makes every gateway look like that. Only failures are remembered (in local storage): returning to a gateway that worked would tie visits together, while leaving a few out of a random draw does not. Random choice keeps users of this page spread across the network instead of concentrated on a few gateways.
- About 8 seconds after connecting (9.5 seconds including a grace period for acknowledgements still in flight), it checks the incoming path two ways. Every packet sent, real or cover, earns an acknowledgement back through the gateway: healthy gateways returned 0.83 to 1.00 per packet sent in that time, broken or slow ones 0.09 to 0.61, so the check needs at least 0.75. And it sends three messages to its own address: healthy gateways returned them in 0.4 to 2.3 seconds, slow ones took 3 to 17 seconds or lost them, so the median must be 3 seconds or less. Afterwards, two 10-second windows in a row below 0.6 acknowledgements per packet also count as a failure; windows that begin within 10 seconds of a connect are left out, because acknowledgements trail their packets.
- On a failure it moves to another gateway. Before a link exists this is invisible apart from a few seconds of "Reconnecting"; a sender waits for the check to pass before making the link. A recipient moves at once; if it is still waiting for the sender's first answer it asks again right away (the answer to an earlier request would go to the old gateway), and if it is downloading it reopens its link to the sender. A sender whose link is already out first reconnects to the same gateway, which keeps the link working, and only moves (showing the new link) if that does not help. A connect that makes no progress for 8 seconds (a healthy one shows a new step every 1 to 2 seconds) is abandoned for another gateway; in testing, one slow gateway otherwise made a move take 45 seconds, and another registered but never opened its working connection, holding a start for 30 seconds. Each connection changes gateway at most three times in any 10 minutes.

The connect timeline in the log shows where the 4 to 7 seconds go: fetching the gateway list (about 0.5 s), registering with the gateway (about 2 s, the connection that closes twice), loading the network map from the Nym API (about 1 s), then opening and authenticating the working connection (about 1.7 s). Reconnecting to the same gateway skips registration.

The Nym client itself writes a console line for every message it sends, naming the recipient's full Nym address, and for every gateway connection, naming the gateway's host. The page drops that routine output and keeps the client's warnings and errors with addresses, keys and host names replaced by placeholders (`build/nym-reply-patch.mjs`), so nothing copied from the browser console reveals them. Any run of 20 or more letters and digits is replaced unless it is made only of capitalised words, such as an error name. A run with exactly the length of a base58-encoded reply tag (20 to 22 characters) or key (42 to 44) is always replaced, whatever its shape, and so is every full Nym address. In a test of 200,000 messages built from random tags, keys, addresses and hosts, none of them leaked.

## Testing

Opening the page with `?debug=1` shows the Diagnostics panel at the bottom, a timestamped log of the session that never contains keys, links, file names or full Nym addresses. It is hidden otherwise, and also shown with `?faults=1` and `?gatewaytest=N`. The panel logs every step, including how long each control message spent in transit. It also measures what the page actually sends to and receives from its Nym gateway: every 10 seconds it reads how many Sphinx packets and bytes went each way, and logs a `gateway traffic` entry with packets per second, megabits per second and the share of the rate Nym's settings ask for (55 packets per second in Maximum, 96 in Balanced). Windows in which data or control messages crossed the mixnet are logged as `busy` every 10 seconds; quiet windows are logged as `idle` once a minute. Each entry carries the running idle and busy averages, which also appear when a transfer finishes and when a client stops.

Opening the page with `?faults=1` adds test controls in the browser console:

- `nymShareFaults.dropIncomingData(seconds)` discards all incoming data for that long.
- `nymShareFaults.delayIncomingMessages(milliseconds)` holds every incoming message for that long, imitating a slow path. Pass 0 to stop.
- `nymShareFaults.closeGatewaySockets()` closes this page's connection to its Nym gateway.
- `nymShareFaults.replaceNymClient()` replaces the Nym client immediately.
- `nymShareFaults.stallConnects(count)` makes the next count connects see no progress from their gateway, so abandoning a stalled connect after 8 seconds can be tested.
- `nymShareFaults.failStarts(count)` makes the next count client starts fail (they ask for a gateway that does not exist), so moving on after a failed start can be tested.
- `nymShareFaults.rememberFaultFailures(true)` lets failures caused by these controls be remembered like real ones, and `nymShareFaults.rememberedGatewayFailures()` lists what is remembered, so the 24-hour memory can be tested.
- `nymShareFaults.hideAcknowledgements(seconds)` makes the health check see no acknowledgements for that long, as on a broken gateway, so the page's gateway move can be tested on a working one.

Opening the page with `?gatewaytest=N` (up to 60) runs the gateway test instead of the normal page: N fresh connections in a row, cycling through the score bands above, each recording the gateway's score, the connect timeline, the acknowledgement checks, three round trips to its own address, and the time to reconnect to the same gateway and to move to a new one. Each run takes about a minute and uses about 15 MB of data in Maximum privacy. Results appear in a table on the page, in the log, and in `window.nymShareGatewayTest`.

Share links made with `?faults=1` open with the same controls on the recipient's side.

## Building

```sh
npm ci
npm run build
```

`build.mjs` bundles `src/app.js` with every library it imports, at the versions pinned in `package-lock.json`, and inlines the result into `src/page.html`. It also applies `build/nym-reply-patch.mjs` to the Nym SDK, whose web worker otherwise drops the tag needed to answer through reply blocks; the build stops if the SDK version or the patched code changes. The `ip` package, which WebTorrent's tracker server code imports and which has unfixed advisories, is replaced through `overrides` in `package.json` by `build/ip-replacement`, a small module implementing the one function that code calls; the page never includes either. The output is a single file, `docs/index.html`, which loads nothing from a CDN at runtime.

## Verifying a build

`docs/SHA256SUMS` holds the checksum of `docs/index.html`, and `docs/version.json` its version, which the verify step also checks. The build does not depend on the time or machine it runs on, so anyone can reproduce it:

```sh
npm ci
npm run verify
```

To check the page a browser loaded, save it and compare `shasum -a 256 index.html` with `docs/SHA256SUMS` at the matching commit.

## Hosting on GitHub Pages

In the repository's Settings, open Pages and set the source to **Deploy from a branch**, branch `main`, folder `/docs`.

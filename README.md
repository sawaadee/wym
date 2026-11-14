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
- The recipient currently sends its own Nym address to the sender. That address identifies the recipient's gateway, not its IP.
- The sender's tab has to stay open until recipients finish. There is no cloud copy.
- Throughput through the mixnet is low. In testing, a 1 MB file took about 40 seconds.

## Using it

Open the page, drop in files and send the link. The recipient opens the link, or pastes it into the Receive box, and clicks Download. The Diagnostics panel at the bottom keeps a timestamped log that never contains keys, links, file names or full Nym addresses.

## Building

```sh
npm ci
npm run build
```

`build.mjs` bundles `src/app.js` with every library it imports, at the versions pinned in `package-lock.json`, and inlines the result into `src/page.html`. The output is a single file, `docs/index.html`, which loads nothing from a CDN at runtime.

## Verifying a build

`docs/SHA256SUMS` holds the checksum of `docs/index.html`. The build does not depend on the time or machine it runs on, so anyone can reproduce it:

```sh
npm ci
npm run verify
```

To check the page a browser loaded, save it and compare `shasum -a 256 index.html` with `docs/SHA256SUMS` at the matching commit.

## Hosting on GitHub Pages

In the repository's Settings, open Pages and set the source to **Deploy from a branch**, branch `main`, folder `/docs`.

/*
  build.mjs
  Purpose: builds docs/index.html, the single self-contained page GitHub Pages serves.
  It bundles src/app.js together with every library it imports (pinned in package-lock.json),
  inlines the bundle into src/page.html, and writes docs/SHA256SUMS so anyone can check that
  the page they loaded matches a build from this repository. The output does not depend on
  the time or machine of the build, so running it again from the same commit must reproduce
  the same checksum; pass --check to verify that without writing anything.
  Created: 2026-11-14
*/
import { build } from 'esbuild'
import { createHash } from 'node:crypto'
import { mkdir, readFile, writeFile } from 'node:fs/promises'

const PAGE_TEMPLATE_PATH = 'src/page.html'
const APP_ENTRY_PATH = 'src/app.js'
const OUTPUT_DIRECTORY = 'docs'
const OUTPUT_PAGE_PATH = OUTPUT_DIRECTORY + '/index.html'
const OUTPUT_CHECKSUM_PATH = OUTPUT_DIRECTORY + '/SHA256SUMS'
const SCRIPT_MARKER = '<!-- APP_SCRIPT -->'

const checkOnly = process.argv.includes('--check')
const packageManifest = JSON.parse(await readFile('package.json', 'utf8'))

const bundleResult = await build({
  entryPoints: [APP_ENTRY_PATH],
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: 'es2022',
  minify: true,
  write: false,
  charset: 'utf8',
  legalComments: 'eof',
  define: { PAGE_VERSION: JSON.stringify(packageManifest.version) },
  logLevel: 'warning'
})
let bundledScript = bundleResult.outputFiles[0].text

// An inline <script> ends at the first "</script" the HTML parser sees, even inside a JavaScript
// string, so every occurrence is rewritten as "<\/script", which JavaScript reads as the same
// characters. "<!--" can also switch the parser into a legacy escape mode; the build refuses to
// continue if one appears rather than guessing at a rewrite that could change a regular expression.
bundledScript = bundledScript.replace(/<\/script/gi, '<\\/script')
if (bundledScript.includes('<!--')) {
  throw new Error('The bundle contains "<!--", which is unsafe inside an inline script. Inspect the library that introduced it.')
}

const pageTemplate = await readFile(PAGE_TEMPLATE_PATH, 'utf8')
if (pageTemplate.split(SCRIPT_MARKER).length !== 2) {
  throw new Error(PAGE_TEMPLATE_PATH + ' must contain exactly one ' + SCRIPT_MARKER + ' marker.')
}
// A replacer function keeps "$" sequences in the bundle from being read as replacement patterns.
const pageHtml = pageTemplate.replace(SCRIPT_MARKER, () => '<script type="module">\n' + bundledScript + '</script>')

const pageDigest = createHash('sha256').update(pageHtml, 'utf8').digest('hex')
const checksumFile = pageDigest + '  index.html\n'

if (checkOnly) {
  const committedChecksums = await readFile(OUTPUT_CHECKSUM_PATH, 'utf8').catch(() => '')
  if (committedChecksums !== checksumFile) {
    console.error('Checksum mismatch.\n  built:     ' + checksumFile.trim() + '\n  committed: ' + (committedChecksums.trim() || '(none)'))
    process.exit(1)
  }
  console.log('Reproduced ' + OUTPUT_PAGE_PATH + ' exactly: ' + pageDigest)
} else {
  await mkdir(OUTPUT_DIRECTORY, { recursive: true })
  await writeFile(OUTPUT_PAGE_PATH, pageHtml, 'utf8')
  await writeFile(OUTPUT_CHECKSUM_PATH, checksumFile, 'utf8')
  const sizeMegabytes = (Buffer.byteLength(pageHtml, 'utf8') / 1e6).toFixed(2)
  console.log('Wrote ' + OUTPUT_PAGE_PATH + ' (' + sizeMegabytes + ' MB), sha256 ' + pageDigest)
}

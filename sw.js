// The Argus site's service worker, written by tools/publish.mjs from site/lock-core.js, site/sw-core.js and site/sw-glue.js, in that order. Edit those, never this.
const VERSION = 'argus-site-a81e77fed7f7'
// The lock's crypto core (docs/specs/2026-11-03-access-and-invites-design.md, section 3). Web Crypto
// only: globalThis.crypto.subtle and crypto.getRandomValues, no library. One file serves three places:
// the site's service worker (tools/site-build.mjs joins it into the site's sw.js as classic script, so
// it imports nothing and every top-level declaration is a plain one or an `export function`,
// `export async function` or `export const`), Philip's tools (tools/setup-access.mjs,
// tools/publish.mjs) and the tests. Nothing here prints anything.

const ITERATIONS = 600000
const SALT_BYTES = 16
const IV_BYTES = 12
const APP_KEY_BYTES = 32
const N8N_KEY_BYTES = 32
const N8N_KEY_PREFIX = 'argus-n8n-'
const PASSCODE_ALPHABET = 'ACDEFHJKMNPQRTUVWXY3479'
const PASSCODE_LENGTH = 20
// The largest multiple of the alphabet's 23 letters that fits in a byte: a random byte at or above
// it is thrown away, so every letter is equally likely.
const PASSCODE_BYTE_LIMIT = 253
const PASSCODE_SHAPE = new RegExp(`^[${PASSCODE_ALPHABET}]{${PASSCODE_LENGTH}}$`)
const MAGIC = 'ARGUS1'
const FORMAT = 1
const INFO = Object.freeze({ tag: 'argus-entry-tag', key: 'argus-entry-key', app: 'argus-app-key', admin: 'argus-admin-key' })
// The only fields a keys file and an entry may hold (spec 2: no names, no email addresses).
const ENTRY_FIELDS = Object.freeze(['v', 'tag', 'pub', 'priv', 'wrap', 'admin'])
// The ceiling on keys.json's seq (2^31 - 1): a seq is raised by 1 per write, and a file far above any real
// count is a fault or a plant, refused before it can pin a device's floor out of reach.
const SEQ_MAX = 2147483647
const KEYS_FIELDS = Object.freeze(['v', 'seq', 'salt', 'app', 'entries', 'invites', 'test'])

function randomBytes(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n))
}

function b64u(bytes) {
  let s = ''
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function unb64u(text) {
  if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) throw new TypeError('not base64url')
  const s = atob(text.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((text.length + 3) % 4))
  const out = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
  return out
}

function hex(bytes) {
  let s = ''
  for (const b of bytes) s += b.toString(16).padStart(2, '0')
  return s
}

function utf8(text) {
  return new TextEncoder().encode(text)
}

async function sha256(bytes) {
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes))
}

// Philip's passcode (spec 3): 20 letters of the alphabet, about 90 bits, shown in four groups of five.
function makePasscode(random = randomBytes) {
  let out = ''
  while (out.length < PASSCODE_LENGTH) {
    for (const b of random(32)) {
      if (b < PASSCODE_BYTE_LIMIT && out.length < PASSCODE_LENGTH) out += PASSCODE_ALPHABET[b % PASSCODE_ALPHABET.length]
    }
  }
  return out.match(/.{5}/g).join('-')
}

// What is stretched (spec 3, plan ruling R5): the text NFC normalised and trimmed at both ends; and
// when that text, without its spaces and dashes and in upper case, is 20 letters of the alphabet, it
// is Philip's passcode and those 20 letters are stretched ("Dashes and case are ignored when typed").
// The dashes are the hyphen and the Unicode dashes a phone keyboard can type in its place (U+2010 to
// U+2015, U+2212). Anything else is a passphrase (Plan 7) and is stretched as typed.
function canonicalSecret(text) {
  if (typeof text !== 'string') throw new TypeError('a passcode is text')
  const typed = text.normalize('NFC').trim()
  const letters = typed.replace(/[\s\u2010-\u2015\u2212-]/g, '').toUpperCase()
  return PASSCODE_SHAPE.test(letters) ? letters : typed
}

// Web Crypto copies the bytes it imports, so ours are zeroed as soon as it has taken them: the typed
// secret, the stretch, the ECDH bits, the raw app key. Best effort (JavaScript promises nothing about other
// copies), but no buffer of ours is left holding a secret. A bare ArrayBuffer (what deriveBits returns) is
// zeroed through a view of the same memory.
async function importRawAndZero(raw, algorithm, usages) {
  const bytes = raw instanceof ArrayBuffer ? new Uint8Array(raw) : raw
  try {
    return await globalThis.crypto.subtle.importKey('raw', bytes, algorithm, false, usages)
  } finally {
    bytes.fill(0)
  }
}

// Both HKDF uses take a zero-length salt: PBKDF2 already took the site's (plan ruling R6).
function hkdfParams(info) {
  return { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8(info) }
}

// One stretch (spec 3): PBKDF2-SHA256, 600,000 iterations, 32 bytes, then HKDF-SHA256 to the entry
// tag (16 bytes, base64url) and the entry key (AES-256-GCM, non-extractable).
async function entryKeys(secret, salt) {
  const subtle = globalThis.crypto.subtle
  const base = await importRawAndZero(utf8(canonicalSecret(secret)), 'PBKDF2', ['deriveBits'])
  const bits = await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS }, base, 256)
  const ikm = await importRawAndZero(bits, 'HKDF', ['deriveBits', 'deriveKey'])
  const tag = b64u(new Uint8Array(await subtle.deriveBits(hkdfParams(INFO.tag), ikm, 128)))
  const key = await subtle.deriveKey(hkdfParams(INFO.key), ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
  return { tag, key }
}

function makeKeyPair() {
  return globalThis.crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
}

async function publicJwk(publicKey) {
  const { kty, crv, x, y } = await globalThis.crypto.subtle.exportKey('jwk', publicKey)
  return { kty, crv, x, y }
}

async function importPublic(jwk) {
  if (jwk?.kty !== 'EC' || jwk?.crv !== 'P-256' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') throw new TypeError('not a P-256 public key')
  return globalThis.crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, { name: 'ECDH', namedCurve: 'P-256' }, true, [])
}

async function gcmSeal(key, bytes) {
  const iv = randomBytes(IV_BYTES)
  const ct = new Uint8Array(await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes))
  return { iv: b64u(iv), ct: b64u(ct) }
}

async function gcmOpen(key, box) {
  return new Uint8Array(await globalThis.crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64u(box.iv) }, key, unb64u(box.ct)))
}

async function sharedKey(privateKey, publicKey, info) {
  const subtle = globalThis.crypto.subtle
  const shared = await subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256)
  const ikm = await importRawAndZero(shared, 'HKDF', ['deriveKey'])
  return subtle.deriveKey(hkdfParams(info), ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
}

// Sealed to a public key (spec 3): an ephemeral ECDH key, HKDF-SHA256 with info, AES-256-GCM. The
// ephemeral private key is used once and never exported, so it is made non-extractable; its public half
// still exports (a public key always does) and travels in the box as epk.
async function sealTo(pub, bytes, info) {
  const eph = await globalThis.crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
  const key = await sharedKey(eph.privateKey, await importPublic(pub), info)
  return { epk: await publicJwk(eph.publicKey), ...(await gcmSeal(key, bytes)) }
}

async function openSealed(sealed, privateKey, info) {
  return gcmOpen(await sharedKey(privateKey, await importPublic(sealed.epk), info), sealed)
}

// The n8n key as setup prints it and n8n stores it (plan ruling R26): argus-n8n- and the base64url of
// its 32 bytes. The prefix is what lets the token scan (tests/egress-scan.js) recognise one.
function formatN8nKey(bytes) {
  return `${N8N_KEY_PREFIX}${b64u(bytes)}`
}

// The app key's raw bytes: held in memory by the publish only, sealed to every entry, then zeroed.
function makeAppKey(random = randomBytes) {
  return random(APP_KEY_BYTES)
}

function appKeyFrom(raw) {
  return globalThis.crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

async function openAppKey(wrap, privateKey) {
  // The unlocked app only reads app.bin, so this key can decrypt and nothing else.
  return importRawAndZero(await openSealed(wrap, privateKey, INFO.app), { name: 'AES-GCM' }, ['decrypt'])
}

// A person's entry (spec 3): { v: 1, tag, pub, priv, wrap?, admin? }. priv is the PKCS#8 private key
// under the entry key; wrap the app key and admin the n8n key, each sealed to pub.
async function makeEntry({ secret, salt, keyPair, appKey = null, admin = null }) {
  const { tag, key } = await entryKeys(secret, salt)
  const pub = await publicJwk(keyPair.publicKey)
  const pkcs8 = new Uint8Array(await globalThis.crypto.subtle.exportKey('pkcs8', keyPair.privateKey))
  const entry = { v: 1, tag, pub, priv: await gcmSeal(key, pkcs8) }
  pkcs8.fill(0)
  if (appKey) entry.wrap = await sealTo(pub, appKey, INFO.app)
  if (admin) entry.admin = await sealTo(pub, admin, INFO.admin)
  return entry
}

// One stretch, then the entry whose tag matches: null when none does (a wrong passcode). The private
// key comes back non-extractable: it can be used, never read out (spec 4).
async function unlockEntry(keys, secret) {
  const { tag, key } = await entryKeys(secret, unb64u(keys.salt))
  const entry = keys.entries.find(e => e.tag === tag)
  if (!entry) return null
  const pkcs8 = await gcmOpen(key, entry.priv)
  try {
    const privateKey = await globalThis.crypto.subtle.importKey('pkcs8', pkcs8, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
    return { tag, entry, privateKey }
  } finally {
    pkcs8.fill(0)
  }
}

function listed(keys, tag) {
  return keys.entries.some(e => e.tag === tag)
}

// Every publish (spec 3): the new app key sealed to every listed public key, people and pending
// invites alike, and the version of the app.bin it opens. No passcode is needed and nothing else in
// an entry changes.
async function reseal(keys, appKey, version) {
  const entries = []
  for (const e of keys.entries) entries.push({ ...e, wrap: await sealTo(e.pub, appKey, INFO.app) })
  const invites = []
  for (const i of keys.invites ?? []) invites.push({ ...i, wrap: await sealTo(i.pub, appKey, INFO.app) })
  return { ...keys, app: version, entries, invites }
}

// The shape of every text field in an entry: an iv, a ciphertext, a JWK coordinate.
const B64U_TEXT = /^[A-Za-z0-9_-]+$/

// The keys file as the lock reads it, or a loud refusal (plan ruling R8). Its seq (access spec 3) is a whole
// number of 1 or more: 1 at setup, raised by 1 by every write, so a device can tell a stale copy from the
// current one. Every part of an entry is held
// to its exact fields (pub { kty, crv, x, y }; priv { iv, ct }; wrap and admin { epk, iv, ct }, epk a P-256
// public JWK of its own): anything extra is refused by only(), anything missing by the check on that field
// (each one is required), and always as "keys.json: ...".
function checkKeys(keys) {
  const bad = why => { throw new Error(`keys.json: ${why}`) }
  const only = (obj, names, what) => {
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) bad(`${what} is not an object`)
    for (const k of Object.keys(obj)) if (!names.includes(k)) bad(`${what}: unknown field ${k}`)
  }
  const text = (obj, k, what) => {
    if (typeof obj[k] !== 'string' || !B64U_TEXT.test(obj[k])) bad(`${what}: ${k} is not base64url text`)
  }
  const publicKey = (jwk, what) => {
    only(jwk, ['kty', 'crv', 'x', 'y'], what)
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') bad(`${what} is not a P-256 public key`)
    text(jwk, 'x', what)
    text(jwk, 'y', what)
  }
  const box = (obj, sealed, what) => {
    only(obj, sealed ? ['epk', 'iv', 'ct'] : ['iv', 'ct'], what)
    if (sealed) publicKey(obj.epk, `${what}.epk`)
    text(obj, 'iv', what)
    text(obj, 'ct', what)
  }
  if (!keys || typeof keys !== 'object' || keys.v !== 1) bad('not version 1')
  for (const k of Object.keys(keys)) if (!KEYS_FIELDS.includes(k)) bad(`unknown field ${k}`)
  if (!Number.isSafeInteger(keys.seq) || keys.seq < 1 || keys.seq > SEQ_MAX) bad('seq is not a whole number of 1 or more, and at most 2147483647')
  let saltBytes = 0
  try {
    saltBytes = unb64u(keys.salt).length
  } catch {
    // not base64url text: it counts as no bytes, and is refused below as keys.json
  }
  if (saltBytes !== SALT_BYTES) bad('the salt is not 16 bytes of base64url text')
  if (!Array.isArray(keys.entries)) bad('no entries list')
  if (keys.invites !== undefined && !Array.isArray(keys.invites)) bad('invites is not a list')
  if (keys.app !== undefined && !/^argus-site-[0-9a-f]{12}$/.test(keys.app)) bad('app is not a site version')
  if (keys.test !== undefined && keys.test !== true) bad('test is not true')
  const tags = new Set()
  for (const e of keys.entries) {
    if (e?.v !== 1 || typeof e.tag !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(e.tag)) bad('an entry has no tag')
    const what = `entry ${e.tag}`
    for (const k of Object.keys(e)) if (!ENTRY_FIELDS.includes(k)) bad(`${what}: unknown field ${k}`)
    if (tags.has(e.tag)) bad(`two entries share the tag ${e.tag}`)
    tags.add(e.tag)
    publicKey(e.pub, `${what}: pub`)
    box(e.priv, false, `${what}: priv`)
    if (e.wrap !== undefined) box(e.wrap, true, `${what}: wrap`)
    if (e.admin !== undefined) box(e.admin, true, `${what}: admin`)
  }
  if (keys.entries.filter(e => e.admin).length > 1) bad('more than one entry holds admin')
  return keys
}

// The pack (plan ruling R7): a 4-byte big-endian length, the JSON index, then each file's bytes in
// index order, offsets from the first byte after the index.
async function makePack(files, commit) {
  const index = { commit, files: [] }
  let offset = 0
  for (const f of files) {
    if (index.files.some(x => x.path === f.path)) throw new Error(`pack: ${f.path} twice`)
    index.files.push({ path: f.path, type: f.type, offset, length: f.bytes.length, sha256: hex(await sha256(f.bytes)) })
    offset += f.bytes.length
  }
  const head = utf8(JSON.stringify(index))
  const out = new Uint8Array(4 + head.length + offset)
  new DataView(out.buffer).setUint32(0, head.length)
  out.set(head, 4)
  let at = 4 + head.length
  for (const f of files) {
    out.set(f.bytes, at)
    at += f.bytes.length
  }
  return out
}

function readPack(pack) {
  if (pack.length < 4) throw new Error('pack: too short')
  const n = new DataView(pack.buffer, pack.byteOffset, pack.byteLength).getUint32(0)
  if (4 + n > pack.length) throw new Error('pack: the index runs past the end')
  const index = JSON.parse(new TextDecoder().decode(pack.subarray(4, 4 + n)))
  const data = pack.subarray(4 + n)
  const files = new Map()
  let next = 0
  for (const f of index.files) {
    if (files.has(f.path)) throw new Error(`pack: ${f.path} twice`)
    if (f.offset !== next || f.offset + f.length > data.length) throw new Error(`pack: ${f.path} is not where the index says`)
    files.set(f.path, { type: f.type, sha256: f.sha256, bytes: data.subarray(f.offset, f.offset + f.length) })
    next += f.length
  }
  if (next !== data.length) throw new Error('pack: bytes after the last file')
  return { commit: index.commit, files }
}

// app.bin (spec 3): the magic ARGUS1, a format byte, a 12-byte random IV, the AES-GCM ciphertext. The 7
// header bytes (magic and format) are the ciphertext's additional authenticated data, so the format byte
// cannot be altered without the decryption failing.
async function sealApp(pack, appKey) {
  const head = MAGIC.length + 1
  const header = new Uint8Array(head)
  header.set(utf8(MAGIC), 0)
  header[MAGIC.length] = FORMAT
  const iv = randomBytes(IV_BYTES)
  const ct = new Uint8Array(await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: header }, appKey, pack))
  const out = new Uint8Array(head + IV_BYTES + ct.length)
  out.set(header, 0)
  out.set(iv, head)
  out.set(ct, head + IV_BYTES)
  return out
}

async function openApp(bin, appKey) {
  const head = MAGIC.length + 1
  if (bin.length < head + IV_BYTES + 16 || new TextDecoder().decode(bin.subarray(0, MAGIC.length)) !== MAGIC) throw new Error('app.bin: not an Argus pack (no ARGUS1 at the start)')
  if (bin[MAGIC.length] !== FORMAT) throw new Error(`app.bin: format ${bin[MAGIC.length]}, and this reader knows format ${FORMAT} only`)
  const iv = bin.subarray(head, head + IV_BYTES)
  const pack = new Uint8Array(await globalThis.crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: bin.subarray(0, head) }, appKey, bin.subarray(head + IV_BYTES)))
  return readPack(pack)
}

// The site's VERSION (plan ruling R8): new with every app.bin, because every publish has a new app key.
async function siteVersion(bin) {
  return `argus-site-${hex(await sha256(bin)).slice(0, 12)}`
}

// The site's service worker, its decisions (docs/specs/2026-11-03-access-and-invites-design.md,
// section 4). Pure: the network, the cache, the store and the clock come in through createLock, so
// tests/site-worker.test.js drives it with fakes and site/sw-glue.js hands it the browser's.
// tools/site-build.mjs joins this file after site/lock-core.js into the site's classic sw.js and drops
// the import line below (its names are then in the same script) and each `export `.

const REMEMBER_MS = 30 * 24 * 60 * 60 * 1000
const CHECK_MS = 3000
const LOCK_DB = 'argus-lock'
// The unlock page's own files: cached at install with app.bin and keys.json, so the lock opens
// offline. Argus's files are never cached: they live in app.bin and, once opened, in memory only.
const SITE_FILES = Object.freeze(['index.html', 'unlock.js', 'unlock.css', 'manifest.webmanifest', 'icons/argus-192.png', 'icons/argus-512.png'])
// The three files the worker fetches for itself and never answers for a page (plan ruling R3).
const OWN_FILES = Object.freeze(['sw.js', 'app.bin', 'keys.json'])

// The request's path inside the scope ('' for the scope itself), or null when it is not the worker's
// to answer: another origin, outside the scope, or one of its own three files.
function inScope(url, scope) {
  const u = new URL(url)
  const s = new URL(scope)
  if (u.origin !== s.origin || !u.pathname.startsWith(s.pathname)) return null
  const rel = u.pathname.slice(s.pathname.length)
  return OWN_FILES.includes(rel) ? null : rel
}

// The caches a new worker may delete: this site's older ones only, by name. A cache it did not make
// is never its to delete, even on an origin it has to itself (plan rulings R21, R23).
function staleCaches(names, version) {
  return names.filter(n => /^argus-site-[0-9a-f]{12}$/.test(n) && n !== version)
}

function createLock({ version, net, cache, store, now, update, checkMs = CHECK_MS }) {
  let open = null // { tag, pack } while Argus is open in this worker's memory
  let opening = null // { tag, gen, promise, fresh } while app.bin is being opened (fresh: for an unlock, whose key is not stored yet)
  let gen = 0 // bumped by every forget, by an unlock and by a request that finds no key: an opening begun before it never lands
  let locks = 0 // bumped by every Lock: an unlock begun before it never stores its key
  let seqSeen = 0 // the highest keys.json seq this worker has seen (the cached file's, then any it accepts)
  let liveSeen = null // what the last read of the live keys.json found: 'ok', 'unreachable' or 'refused'; null before any

  const notFound = () => new Response('', { status: 404 })
  const json = body => new Response(body, { headers: { 'Content-Type': 'application/json' } })
  const askUpdate = () => { Promise.resolve().then(update).catch(() => {}) }

  async function cachedKeys() {
    const r = await cache.match('keys.json')
    if (!r) throw new Error('keys.json is not cached')
    const keys = checkKeys(JSON.parse(await r.text()))
    seqSeen = Math.max(seqSeen, keys.seq)
    return keys
  }

  // The live keys.json, read past every cache: { keys, text }, or null when it cannot be used. Null is
  // 'unreachable' (a network error, or no answer within checkMs) or 'refused' (an answer that is not 200,
  // not JSON, not a keys file, or stale: a lower seq than one already seen, which a CDN can serve after a
  // removal); the lock goes on with what it has either way, and liveSeen keeps which, for hello.
  async function liveKeys() {
    let timer
    let body
    try {
      const late = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('slow')), checkMs) })
      const r = await Promise.race([net('keys.json', { cache: 'no-store' }), late])
      if (r.status !== 200) {
        liveSeen = 'refused'
        return null
      }
      body = await Promise.race([r.text(), late])
    } catch {
      liveSeen = 'unreachable'
      return null
    } finally {
      clearTimeout(timer)
    }
    try {
      const found = { keys: checkKeys(JSON.parse(body)), text: body }
      if (found.keys.seq < seqSeen) {
        liveSeen = 'refused'
        return null
      }
      seqSeen = found.keys.seq
      liveSeen = 'ok'
      return found
    } catch {
      liveSeen = 'refused'
      return null
    }
  }

  // A removal seen in a reachable live keys.json, written into the cached one so it holds offline too:
  // a live keys.json of this publish replaces the cached one; one of another publish only takes the
  // person's entry out of the cached one (keys is the cached keys.json, which that case still holds) and
  // takes the live file's seq, so an older copy of this publish stays stale after a restart too.
  async function recordRemoval(live, keys, tag) {
    if (live.keys.app === version) await cache.put('keys.json', json(live.text))
    else await cache.put('keys.json', json(JSON.stringify({ ...keys, seq: Math.max(keys.seq, live.keys.seq), entries: keys.entries.filter(e => e.tag !== tag) })))
  }

  async function forget(ended) {
    gen++
    open = null
    opening = null
    await store.delete('key')
    if (ended) await store.put('ended', true)
  }

  // Argus opened for rec into memory: the app key from rec's wrap, then app.bin from the cache. One
  // opening serves every request that arrives while it runs.
  function openFor(rec, keys, mine, fresh = false) {
    if (mine !== gen) return Promise.reject(new Error('locked meanwhile'))
    if (open?.tag === rec.tag) return Promise.resolve(open)
    if (opening?.tag === rec.tag && opening.gen === mine) return opening.promise
    const promise = (async () => {
      const entry = keys.entries.find(e => e.tag === rec.tag)
      if (!entry?.wrap) throw new Error('keys.json holds no app key for this entry')
      const appKey = await openAppKey(entry.wrap, rec.privateKey)
      const bin = await cache.match('app.bin')
      if (!bin) throw new Error('app.bin is not cached')
      const pack = await openApp(new Uint8Array(await bin.arrayBuffer()), appKey)
      if (mine !== gen) throw new Error('locked meanwhile')
      open = { tag: rec.tag, pack }
      return open
    })()
    opening = { tag: rec.tag, gen: mine, promise, fresh }
    promise.catch(() => {}).finally(() => { if (opening?.promise === promise) opening = null })
    return promise
  }

  // 'open' (and Argus in memory), 'locked' or 'ended'. Online, the live keys.json is read too: a tag no
  // longer listed ends access on this device (spec 4, removal) and is written into the cached keys.json
  // first, so an offline unlock cannot bring it back; a live keys.json of this publish replaces the
  // cached one; one of a newer publish is a reason to ask for the update (plan ruling R8).
  async function state({ online }) {
    const mine = gen
    const rec = await store.get('key')
    if (!rec) {
      open = null
      // An opening begun from a key that has since vanished never lands. An unlock's own opening has no
      // stored key yet, so a request that finds none does not cancel it.
      if (!opening?.fresh) {
        gen++
        opening = null
      }
      return (await store.get('ended')) ? 'ended' : 'locked'
    }
    // Fails closed: a key is open only for a number of milliseconds left that is above zero and no more
    // than the window it was remembered for. No expiry, a text one, NaN, or a clock earlier than the
    // unlock (more left than a whole window) is the unlock page.
    const left = typeof rec.expires === 'number' ? rec.expires - now() : NaN
    if (!(left > 0 && left <= REMEMBER_MS)) {
      await forget(false)
      return 'locked'
    }
    let keys = await cachedKeys()
    if (online) {
      const live = await liveKeys()
      if (live && !listed(live.keys, rec.tag)) {
        await recordRemoval(live, keys, rec.tag)
        await forget(true)
        // A newer publish's file ended it: the device ran an older version, and the new worker waits for the
        // windows of this one, so ask for the update now (final wave I2 b).
        if (live.keys.app !== version) askUpdate()
        return 'ended'
      }
      if (live && live.keys.app === version) {
        keys = live.keys
        await cache.put('keys.json', json(live.text))
      } else if (live) {
        askUpdate()
      }
    }
    if (!listed(keys, rec.tag)) {
      await forget(true)
      return 'ended'
    }
    await openFor(rec, keys, mine)
    return 'open'
  }

  // A new worker's install: keys.json and app.bin of its own publish, refused if either is another
  // publish's (keys.json first, so the small file is checked before the large one is downloaded), and
  // the unlock page's files; each fetched past the browser's HTTP cache.
  async function install() {
    const keysRes = await net('keys.json', { cache: 'reload' })
    if (!keysRes.ok) throw new Error(`keys.json: HTTP ${keysRes.status}`)
    const body = await keysRes.text()
    if (checkKeys(JSON.parse(body)).app !== version) throw new Error('keys.json is not the one this service worker was published with')
    const binRes = await net('app.bin', { cache: 'reload' })
    if (!binRes.ok) throw new Error(`app.bin: HTTP ${binRes.status}`)
    const bin = new Uint8Array(await binRes.arrayBuffer())
    if ((await siteVersion(bin)) !== version) throw new Error('app.bin is not the one this service worker was published with')
    for (const name of SITE_FILES) {
      const r = await net(name, { cache: 'reload' })
      if (!r.ok) throw new Error(`${name}: HTTP ${r.status}`)
      await cache.put(name, r)
    }
    await cache.put('app.bin', new Response(bin, { headers: { 'Content-Type': 'application/octet-stream' } }))
    await cache.put('keys.json', json(body))
  }

  // The answer to one GET inside the scope (rel from inScope): Argus's files from memory while open;
  // the unlock page's files from the cache (the network only if the cache lost one) while not; 404 for
  // anything else, which the site does not hold either. A navigation checks the key first; a state
  // that cannot be read shows the unlock page and keeps the key.
  async function answer(rel, navigate) {
    let st
    try {
      st = !navigate && open ? 'open' : await state({ online: navigate })
    } catch {
      // The unlock page is shown, so nothing of Argus stays in memory behind it (as forget and the no-key
      // branch of state leave it): else js/app.js would go on being served while unlock.js is looked up in the pack.
      open = null
      st = 'locked'
    }
    const path = rel === '' ? 'index.html' : rel
    if (st === 'open') {
      const f = open?.pack.files.get(path)
      return f ? new Response(f.bytes, { headers: { 'Content-Type': f.type } }) : notFound()
    }
    if (!SITE_FILES.includes(path)) return notFound()
    return (await cache.match(path)) ?? net(path)
  }

  // The typed text, stretched once (site/lock-core.js). The key is kept only once it has opened this
  // app.bin, so a key that cannot open anything is never remembered. Answers { ok: true } or
  // { ok: false, why }: 'wrong' (no entry opens), 'ended' (a reachable live keys.json no longer lists the
  // person), 'locked' (a Lock came while this unlock was stretching or opening, and wins).
  async function unlock(secret) {
    if (typeof secret !== 'string' || secret.trim() === '') return { ok: false, why: 'wrong' }
    const asked = locks
    // The cached file first, so the highest seq seen is known when the live file is judged. It may be
    // missing or refused only when a reachable live one of this publish can stand in.
    let cached = null
    let unreadable = null
    try {
      cached = await cachedKeys()
    } catch (e) {
      unreadable = e
    }
    const live = await liveKeys()
    const same = live !== null && live.keys.app === version
    if (live && !same) askUpdate()
    if (unreadable && !same) throw unreadable
    // A reachable live keys.json of this publish replaces the cached one before anything is matched, as
    // state does: what the lock has seen of who is listed holds offline too, whatever the passcode.
    if (same) await cache.put('keys.json', json(live.text))
    // What opens Argus: the live keys.json of this publish when it is reachable, else the cached one. What
    // the passcode is matched against: those entries and the cached file's too, so a person the live file
    // no longer lists is recognised as removed, not as a wrong passcode.
    const keys = same ? live.keys : cached
    const matching = same && cached ? { ...keys, entries: [...keys.entries, ...cached.entries.filter(e => !listed(keys, e.tag))] } : keys
    const found = await unlockEntry(matching, secret)
    if (locks !== asked) return { ok: false, why: 'locked' }
    if (!found) return { ok: false, why: 'wrong' }
    if (live && !listed(live.keys, found.tag)) {
      await recordRemoval(live, cached, found.tag)
      await forget(true)
      return { ok: false, why: 'ended' }
    }
    const rec = { tag: found.tag, privateKey: found.privateKey, expires: now() + REMEMBER_MS }
    // An opening for this same person already running (a first unlock that has not finished) is waited
    // for, not cancelled: bumping gen would end it with 'locked meanwhile'.
    let mine = gen
    if (opening?.tag !== rec.tag) {
      gen++
      mine = gen
      open = null
      opening = null
    }
    try {
      await openFor(rec, keys, mine, true)
    } catch (e) {
      // A Lock that cut the opening short wins: the answer is locked, not an error.
      if (locks !== asked) return { ok: false, why: 'locked' }
      throw e
    }
    await store.put('key', rec)
    // A Lock that came while the key was being stored wins: the key is forgotten again.
    if (locks !== asked) {
      await forget(false)
      return { ok: false, why: 'locked' }
    }
    await store.delete('ended')
    return { ok: true }
  }

  async function lockNow() {
    locks++
    await forget(false)
    return { ok: true }
  }

  // The message protocol (plan ruling R20, amended): hello always carries lock: true, with state 'open',
  // 'locked', 'ended' or, when the state cannot be read, 'error' and message; live is what the last read
  // of the live keys.json found ('ok', 'unreachable', 'refused', or null before any).
  async function message(data) {
    try {
      if (data?.type === 'argus-hello') {
        let st
        try {
          st = await state({ online: false })
        } catch (e) {
          return { lock: true, state: 'error', message: String(e?.message ?? e) }
        }
        return { lock: true, state: st, version, commit: st === 'open' ? (open?.pack.commit ?? null) : null, live: liveSeen }
      }
      if (data?.type === 'argus-unlock') return await unlock(data.secret)
      if (data?.type === 'argus-lock') return await lockNow()
      return { ok: false, why: 'unknown' }
    } catch (e) {
      return { ok: false, why: 'error', message: String(e?.message ?? e) }
    }
  }

  return { install, answer, message, state }
}

// The site's service worker: the browser glue (docs/specs/2026-11-03-access-and-invites-design.md,
// section 4). Every decision is createLock's (site/sw-core.js, tested in Node with fakes). This file
// hands it the browser's Cache Storage, the IndexedDB database argus-lock, the one network call and
// the clock, and binds the four events. It is classic script: tools/site-build.mjs writes the site's
// sw.js as a VERSION line, site/lock-core.js, site/sw-core.js and this file, in that order. Argus's own
// register('sw.js') registers a classic worker at this same address, so with a classic worker here
// that call finds this registration and changes nothing (plan rulings R2 and R3).

function siteScope() {
  return self.registration.scope
}

// The one network call (tests/site-egress.test.js holds the site to it): a file of the site's own, by
// a name that resolves inside the scope, or a refusal.
function net(name, init) {
  const url = new URL(name, siteScope())
  if (!url.href.startsWith(siteScope())) return Promise.reject(new Error(`not a file of the site: ${name}`))
  return fetch(url, init)
}

// This publish's cache, by name. Only the unlock page's files, app.bin and keys.json are ever put in
// it (sw-core's install and its keys.json refresh), never a file of Argus.
const siteCache = {
  match: async name => (await caches.open(VERSION)).match(new URL(name, siteScope()).href),
  put: async (name, res) => (await caches.open(VERSION)).put(new URL(name, siteScope()).href, res),
}

function lockDb() {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(LOCK_DB, 1)
    r.onupgradeneeded = () => r.result.createObjectStore('lock')
    r.onsuccess = () => resolve(r.result)
    r.onerror = e => reject(e?.target?.error ?? r.error ?? new Error('the argus-lock database could not be opened'))
  })
}

// Every operation waits for the one called before it, so they land in the order they were called and
// not in the order the browser happens to bring their connections up: a Lock that comes while a key is
// being stored must delete what the put stores, never be overtaken by it. A failed operation rejects
// its own caller and holds up nobody.
let lockQueue = Promise.resolve()

function inLockDb(mode, use) {
  const run = async () => {
    const db = await lockDb()
    try {
      return await new Promise((resolve, reject) => {
        const t = db.transaction('lock', mode)
        const req = use(t.objectStore('lock'))
        t.oncomplete = () => resolve(req.result)
        t.onerror = e => reject(e?.target?.error ?? t.error ?? new Error('the argus-lock transaction failed'))
        t.onabort = () => reject(t.error ?? new Error('the argus-lock transaction was aborted'))
      })
    } finally {
      db.close()
    }
  }
  const done = lockQueue.then(run)
  lockQueue = done.then(() => {}, () => {})
  return done
}

// The key record (a non-extractable CryptoKey, the tag and the expiry) and the ended flag.
const lockStore = {
  get: async name => (await inLockDb('readonly', s => s.get(name))) ?? null,
  put: (name, value) => inLockDb('readwrite', s => s.put(value, name)),
  delete: name => inLockDb('readwrite', s => s.delete(name)),
}

const lock = createLock({
  version: VERSION,
  net,
  cache: siteCache,
  store: lockStore,
  now: () => Date.now(),
  update: () => self.registration.update(),
})

// A new worker WAITS for the pages of the old one; it never calls skipWaiting. A page that is running the
// previous Argus (decrypted into the old worker's memory) goes on asking for files after it has loaded:
// the OCR and scan workers, the OpenCV and Tesseract scripts and the language data. A worker that took
// over mid-session would answer those from its own, newer pack, and the page would run a mixed app. A
// waiting worker takes over when no page of the old one is left (a first install has no old one, so it
// activates at once). Cost: an update shows when every window of Argus has been closed, not before.
// clients.claim() below is safe on that footing: it can only reach a page that no older worker controls,
// which is the network-served unlock page, never a page running Argus.
self.addEventListener('install', event => {
  event.waitUntil(lock.install())
})

self.addEventListener('activate', event => {
  event.waitUntil(caches.keys()
    .then(names => Promise.all(staleCaches(names, VERSION).map(n => caches.delete(n))))
    .then(() => self.clients.claim()))
})

self.addEventListener('fetch', event => {
  const req = event.request
  if (req.method !== 'GET') return
  const rel = inScope(req.url, siteScope())
  if (rel === null) return
  event.respondWith(lock.answer(rel, req.mode === 'navigate'))
})

self.addEventListener('message', event => {
  const port = event.ports[0]
  if (!port || !String(event.source?.url ?? '').startsWith(siteScope())) return
  event.waitUntil(lock.message(event.data).then(reply => port.postMessage(reply)))
})

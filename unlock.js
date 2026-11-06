// The unlock page's script (docs/specs/2026-11-03-access-and-invites-design.md, section 4). It holds
// no key and does no crypto: the passcode goes to the site's service worker in one message, and the
// worker stretches it, finds the entry and keeps the key (site/sw-core.js; plan ruling R4). It exports
// its copy and its brake for tests/site-page.test.js; start() runs only where there is a document.

export const COPY = Object.freeze({
  locked: 'Argus is locked.',
  ended: 'Your access to Argus has ended.',
  wrong: 'That passcode does not open Argus.',
  opening: 'Opening Argus',
  failed: 'Argus could not start: ',
})
export const BRAKE_AFTER = 5
export const BRAKE_MS = 30000
export const READY_MS = 120000
export const ANSWER_MS = 60000

// Five wrong tries in a row wait 30 seconds before the next try (spec 4), and so does every try after
// them until one opens (plan ruling R10): the wait from now in ms, 0 to go. A nuisance only: a reload
// starts the count again, and the real defence is the passcode's length (spec 3). The wait is never more
// than BRAKE_MS: a clock set back (a last failure that lies ahead of now) cannot stretch it.
export function brakeWait(fails, lastFailAt, now) {
  return fails >= BRAKE_AFTER ? Math.min(BRAKE_MS, Math.max(0, lastFailAt + BRAKE_MS - now)) : 0
}

function within(promise, ms, what) {
  let timer
  const late = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${what} after ${ms / 1000} s`)), ms) })
  return Promise.race([promise, late]).finally(() => clearTimeout(timer))
}

// One message to the worker, answered through a port of its own (plan ruling R20).
function ask(worker, msg) {
  const ch = new MessageChannel()
  const answered = new Promise(resolve => { ch.port1.onmessage = e => resolve(e.data) })
  worker.postMessage(msg, [ch.port2])
  return within(answered, ANSWER_MS, 'no answer from the service worker').finally(() => ch.port1.close())
}

export function start({ doc = document, nav = navigator, loc = location, now = () => Date.now(), later = (fn, ms) => setTimeout(fn, ms) } = {}) {
  const $ = name => doc.querySelector(`[data-lock="${name}"]`)
  const headline = $('headline')
  const line = $('line')
  const field = $('secret')
  const key = $('unlock')
  // The note is never hidden (final wave P3.4): a hidden element is out of the accessibility tree, and an
  // empty one is taken care of by css (.note:empty).
  const say = text => { line.textContent = text }
  let fails = 0
  let lastFailAt = 0
  // dead: no worker will ever answer (nothing to register, a registration refused, an install that failed),
  // so the key stays off whatever a try's end would do. submitted: a try has started, and the page's one
  // hello, if it answers after that, is late news and says nothing.
  let dead = false
  let submitted = false
  const stop = text => {
    dead = true
    say(text)
    key.disabled = true
  }
  if (!nav.serviceWorker) {
    stop(`${COPY.failed}this browser has no service worker.`)
    return
  }
  // The same call Argus makes, with no options (plan ruling R3), so one registration serves both. A worker
  // that fails to install while none is active leaves nothing to answer (a failed update leaves the old one).
  nav.serviceWorker.register('sw.js')
    .then(reg => {
      const w = reg?.installing
      w?.addEventListener('statechange', () => {
        if (w.state === 'redundant' && !reg.active) stop(`${COPY.failed}the service worker did not install.`)
      })
    })
    .catch(e => stop(`${COPY.failed}${e.message}`))
  nav.serviceWorker.ready
    .then(r => ask(r.active, { type: 'argus-hello' }))
    .then(h => {
      if (h?.state === 'ended') headline.textContent = COPY.ended
      else if (h?.state === 'error' && !submitted) say(`${COPY.failed}${h.message ?? 'its state could not be read'}`)
    })
    .catch(() => {})
  $('form').addEventListener('submit', async e => {
    e.preventDefault()
    if (key.disabled || field.value.trim() === '') return
    submitted = true
    key.disabled = true
    field.readOnly = true
    say(COPY.opening)
    try {
      const reg = await within(nav.serviceWorker.ready, READY_MS, 'no service worker')
      const r = await ask(reg.active, { type: 'argus-unlock', secret: field.value })
      if (r?.ok === true) {
        field.value = ''
        loc.reload()
        return
      }
      if (r?.why === 'wrong') {
        fails++
        lastFailAt = now()
        say(COPY.wrong)
        field.focus()
      } else if (r?.why === 'ended') {
        // The passcode was a person this site no longer lists (access spec 4, removal): the field stays,
        // and it is no wrong try.
        headline.textContent = COPY.ended
        say('')
      } else if (r?.why === 'locked') {
        // A Lock came while this unlock was stretching and won (R20): the page stays as it was.
        say('')
      } else {
        say(`${COPY.failed}${r?.message ?? r?.why ?? 'no answer'}`)
      }
    } catch (err) {
      say(`${COPY.failed}${err.message}`)
    } finally {
      field.readOnly = false
      const wait = brakeWait(fails, lastFailAt, now())
      if (dead) key.disabled = true
      else if (wait > 0) later(() => { key.disabled = dead }, wait)
      else key.disabled = false
    }
  })
}

if (typeof document !== 'undefined') start()

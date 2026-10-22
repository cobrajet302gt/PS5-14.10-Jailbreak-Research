# Confirmed Vulnerabilities — PS5 14.10

Real memory safety bugs confirmed on device. Each hit a secondary wall that prevents full exploitation without an additional primitive.

> **Status key:** CONFIRMED = bug triggers on device. BLOCKED = exploitation blocked by secondary defense. The bugs are real — they become exploitable if the blocking wall is bypassed.

---

## 1. CVE-2026-43720 — Canvas getContext() Reentrant UAF

**Status:** CONFIRMED on device, BLOCKED by IsoHeap

**Bug:** `HTMLCanvasElement::getContext()` checks `m_context` at line 226, then calls `convert<IDLDictionary>()` at line 268 for settings. Dictionary conversion invokes JS property getters. A getter re-enters `getContext('2d')` on the same canvas — inner call creates context, outer call overwrites `m_context` via `unique_ptr` assignment, freeing the inner context while its JS wrapper survives.

**Trigger:**
```javascript
var innerCtx;
var canvas = document.createElement('canvas');
var settings = {};
Object.defineProperty(settings, 'desynchronized', {
  get: function() { innerCtx = canvas.getContext('2d'); return false; }
});
var outerCtx = canvas.getContext('2d', settings);
// innerCtx is now a dangling reference to freed memory
```

**Device evidence (V460/V461):**
- Re-entry confirmed: `thenCount=1, same=false`
- Same-type spray: bidirectional R/W via `innerCtx` ↔ `sprayCtxs[10]` (wrote 999.5, read 999.5)
- AB spray: CRASHES — `isContextLost()` dereferences `m_canvasBase` → SIGSEGV

**Why it's blocked:**
Canvas contexts use `WTF_MAKE_ISO_ALLOCATED` → IsoHeap. ArrayBuffer/string/Blob objects cannot reclaim the freed slot. Same-type spray gives aliased access but no memory corruption. All canvas operations check `isContextLost()` first, which dereferences `m_canvasBase` — non-context memory at that offset crashes.

**Unblock condition:** IsoHeap bypass, or a canvas operation that skips `isContextLost()`.

**Fix:** Commit 2693828e8d73 (2026-06-29): re-checks `m_context` after dictionary conversion. Not present in WK-1400.

---

## 2. CVE-2026-43715 — CSSFontFace UAF Write

**Status:** CONFIRMED on device, BLOCKED by Timer RELEASE_ASSERT

**Bug:** During `CSSFontFace::setStatus()`, `iterateClients` copies `Ref<Client>` (not `Ref<CSSFontFace>`). Client callback resolves a `DOMPromiseProxy` which fires a synchronous `.then` getter. The getter modifies `@font-face` rules via `setProperty()`, triggering `remove()` + `adopt()` which drops the last `Ref<CSSFontFace>`. The old face is FREED. `iterateClients` returns and `m_status = newStatus` at line 595 **writes to freed memory**.

**Device evidence (p458):**
- `A-RESULT: THEN-1-status=loading` → `.then` fires DURING `iterateClients`
- `B-CHECK: loadedIdx:[55]` → spray face #55's `m_status` overwritten to Success(3)
- `C: CRASHED` → AB sentinel data had invalid enum → `RELEASE_ASSERT`

**CSSFontFace layout (192 bytes):**
- Offset 130: `m_status` (1 byte) — **UAF write target** (writes 3=Success or 4=Failure)
- Offset 144-191: `m_timeoutTimer` (Timer, 48 bytes)
  - Offset 176: `m_thread` (Ref<Thread>) — **RELEASE_ASSERT blocker**

**Why it's blocked:**
`setStatus(Success)` unconditionally calls `m_timeoutTimer.stop()`, which calls `setNextFireTime()` at Timer.cpp:469: `RELEASE_ASSERT(canCurrentThreadAccessThreadLocalData(m_thread))`. AB spray puts garbage at offset 176 → Thread check fails → crash. Same-type groom works but 1-byte `m_status=3` write is harmless (no secondary corruption). CSSFontFace is the **sole occupant** of the 192-byte size class.

**Unblock condition:** Leak of `Thread::current()` address to craft valid Timer at offset 176. Or find a `setStatus()` code path that avoids Timer access (none exists for Success/Failure triggers).

---

## 3. ReadableStream tee() Type Confusion

**Status:** CONFIRMED on device, BLOCKED by JS builtin wall

**Bug:** `InternalReadableStream::fromObject()` (line 76-79) wraps ANY JSObject as InternalReadableStream with zero type check. By poisoning `Array.prototype[Symbol.iterator]` during `rs.tee()`, the SequenceConverter accepts attacker objects as stream branches.

**Two primitives confirmed:**

**Object substitution (V432):** Replace branch2 with any JSObject → `fromObject()` wraps it as a real ReadableStream (`instanceof` = true). `.locked` returns false, `.getReader()` throws.

**OOB read (V430/V432):** Return only 1 element from iterator → `results[1]` reads 8 bytes past Vector allocation. ASSERT compiled out on PS5. Crashes on ungroomed heap.

**Device evidence (V432):**
- Plain object wrapped as ReadableStream: confirmed
- ArrayBuffer wrapped as ReadableStream: confirmed
- OOB read: crashes at INTERCEPT (ungroomed)

**Why it's blocked:**
Every InternalReadableStream method goes through `invokeReadableStreamFunction()` → JS builtins. JS builtins read private slots via `@getByIdDirectPrivate`, which returns `undefined` on fake objects. No C++ code path directly accesses internal stream fields. Type confusion only manifests in JavaScript-level behavior, not memory corruption.

---

## 4. Private-Name Inversion via tee()

**Status:** CONFIRMED LIVE on device

**Bug:** Poisoning `Array.prototype[Symbol.iterator]` to yield the same object X twice to `tee()` → engine writes ReadableStream private slots (`disturbed`, `state`, `readableStreamController`) onto X.

**Device evidence:**
- `pidInverted=true` — `firstThrow=TypeError, secondThrow=none`
- Signal: `pair[0].cancel()` writes slots → `pair[1].cancel()` sees `state==@streamClosed` → resolves without throw

**Why it's contained:**
Same JS builtin wall as #3. Controller written to X is real, but operations go through JS builtins that handle state correctly. No memory corruption path from this alone.

---

## 5. TransformStream Double-Iteration Disconnect (V429)

**Status:** CONFIRMED on device

**Bug:** Override `Array.prototype[Symbol.iterator]` during `new ReadableStream(underlyingSource, strategy)` where strategy returns a TransformStream's readable/writable. The C++ layer stores attacker-supplied streams while JS internals use the real streams. This creates a disconnect where data flows through the real pipeline but control references point to attacker objects.

**Device evidence (V429):**
- Double-iteration substitution confirmed
- C++ stores attacker streams, JS internals use real streams
- Pipeline stays consistent under test

**Why it's contained:**
Same JS builtin wall. All stream operations on the confused references go through JS builtins.

---

## 6. HTMLParser Custom Element Double-Parent

**Status:** UNFIXED in WK-1400 source, BLOCKED by post-construction validation

**Bug:** HTML parser `insert()` at HTMLConstructionSite.cpp:137 has `ASSERT(!task.child->parentNode())` — stripped in release. `parserAppendChild()` blindly appends without checking parentNode. A custom element constructor that calls `altDiv.appendChild(this)` creates dual membership — element in both parent's child list and altDiv's child list.

**Why it's blocked:**
Post-construction validation at JSCustomElementInterface.cpp:173 checks `wrappedElement->parentNode()` — if non-null, throws NotSupportedError and creates HTMLUnknownElement fallback. Device-confirmed (V415): fallback inserted in original container, real element stays in altDiv.

**Open lead:** Microtask checkpoint at line 156 runs BETWEEN construction and validation. `document.write()`, DOM removal, or `document.open()` might bypass validation — untested.

---

## 7. CVE-2026-43727 — Clipboard Iterator UAF

**Status:** Real bug, BLOCKED by missing API

**Bug:** `clearItemTypeLoaders` invalidates iterators during clipboard operations.

**Why it's blocked:**
Clipboard API is absent on PS5 14.10 (`navigator.clipboard` undefined despite `isSecureContext: true`).

---

## Summary

| Vuln | Bug Class | Wall | Unblock Needed |
|------|-----------|------|----------------|
| CVE-2026-43720 Canvas | UAF | IsoHeap | IsoHeap bypass or `isContextLost()` skip |
| CVE-2026-43715 CSSFontFace | UAF write | Timer RELEASE_ASSERT | `Thread::current()` leak |
| tee() type confusion | Type confusion | JS builtin dispatch | C++ fast path that skips builtins |
| Private-name inversion | Slot injection | JS builtin dispatch | Same as above |
| TransformStream disconnect | Reference confusion | JS builtin dispatch | Same as above |
| HTMLParser CE | Double-parent | Post-construction validation | Microtask bypass |
| CVE-2026-43727 Clipboard | Iterator UAF | Missing API | Clipboard API presence |

The most promising are **CVE-2026-43720** (Canvas UAF — needs IsoHeap bypass) and **CVE-2026-43715** (CSSFontFace UAF — needs Thread pointer leak). Both are one primitive away from full exploitation.

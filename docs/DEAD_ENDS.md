# Dead-End Investigations

Comprehensive list of all investigated attack vectors confirmed dead on PS5 firmware 14.10. Documented to prevent duplicate effort.

All investigations were performed against retail PS5 hardware running firmware 14.10, targeting the built-in browser (Safari 17.0 / WebKit-1400, LLInt-only, no JIT).

---

## JSC / JavaScript Engine

### MetadataTable Integer Overflow (Bug 317632) — DEAD: OOM

38M entries x 104 bytes/node = 3.7 GB AST needed. PS5 WebContent OOM-kills at ~1.5 GB.

Mathematically impossible within PS5 memory limits. ThrowableExpressionData adds 36 bytes per call node, and no opcode can overflow within available memory. The `.length=81400` and `.length=79600` results were false positives (correct literal lengths: 817-char or 796-char chunks x 100). Inner function CodeBlocks are created lazily at first call, so the sweep never ran without an IIFE wrapper.

### ClonedArguments Butterfly UAF — DEAD: Conservative GC

All 9 bypass angles exhausted. Conservative GC scanning pins butterfly memory.

Conservative GC rooting blocks all butterfly reclaim strategies. The GC scans the stack conservatively and will pin any cell that looks like a heap pointer, preventing reuse of freed butterfly storage. Confirmed with V240/V241 (CORRUPT-0 result).

### DirectArguments OOB Write — DEAD: Bounds Check

`isMappedArgument(i)` checks `i < m_length` before `setIndexQuickly`.

Both the interpreter path and DFG path (irrelevant on PS5 anyway) perform bounds checking. No path from JavaScript to write past the mapped arguments boundary.

### sort() Detach UAF — DEAD: Cleared

On detach: `m_vector` cleared, `m_length` zeroed. All access returns `undefined`.

Device-confirmed with V422. TypedArray sort with concurrent detach is fully handled.

### Yarr C3 Position Corruption — DEAD: Match Failure

1-unit displacement always causes match failure, not exploitable state.

The corruption affects the pattern matcher's position tracking, but the resulting mismatch causes the regex engine to report "no match" rather than producing corrupted output that could be leveraged.

### Yarr Lookbehind Forward Reference — DEAD: Fixed in WK-1400

`{0}` quantification cleanup fixed at YarrPattern.cpp:1534-1537.

The bug allowed a forward reference inside a lookbehind to skip quantification cleanup, but WK-1400 contains the fix.

### structuredClone Re-entry — DEAD: Pool Roots Objects

`m_objectPool` roots all objects during serialization. No re-entry possible.

The serialization pool maintains strong references to all objects being cloned, preventing GC collection during the operation.

### structuredClone Pool Mismatch — DEAD: Fix Present

V287 confirmed gcBuffer split fix present on PS5 14.10 binary.

The pool mismatch vulnerability (where serialization and deserialization could reference different buffer pools) has been patched.

### structuredCloneForStream OOB — DEAD: Zero-Fill

V330 stale metadata confirmed on device but mmap zero-fill blocks info leak.

The stale metadata is real but newly mapped pages are zero-filled by the kernel, preventing information disclosure. V345 confirmed proper bounds checking on the JS `.length` property.

### ProxyObject JSScope Leak — DEAD: Binary Fix

14.10 has binary-level fix. Receiver is constructor, not JSScope.

The Relapse Stage-1 primitive. 54/54 attempts fail deterministically on 14.10. The binary contains a fix that ensures the receiver object is the constructor rather than leaking the JSScope chain.

### jsCast Unchecked Paths — SAFE: All Type-Guarded

Complete audit of all unchecked `jsCast<>` in JSC runtime.

Every unchecked jsCast is preceded by a C++ type check (@isRegExpObject, @isMap, etc.). No exploitable type confusion reachable from JavaScript.

---

## Streams API

### tee() Type Confusion — DEAD: JS Builtin Wall

Private-name inversion confirmed. BUT all operations go through JS builtins.

Can write ReadableStream private slots onto arbitrary objects via yielding the same object twice to tee(). However, ALL InternalReadableStream operations dispatch through `invokeReadableStreamFunction` to JS builtins, which call proper methods on the target. No direct C++ field access bypasses this wall.

### tee() OOB Read — DEAD: CrashOnOverflow

`Vector::at()` has CrashOnOverflow bounds check that kills the process before stale pointer access.

Device-confirmed with V438b: crashes were CrashOnOverflow trap (process termination), not exploitable stale pointer dereferences. AB cross-pollution approach also dead because it was premised on the OOB read.

### Stream Tee OOB via RAB Resize — DEAD: Bounds Checks

Per-element `inBounds()` checks `bufferByteLength`. IDL converters reject RAB views.

All WebCore APIs reject resizable views at `toWrapped()`, and the stream internals perform per-element bounds checking.

### BYOB Stream Prototype Poison — DEAD: No BYOB

PS5 14.10 lacks `ReadableStream` type:bytes entirely.

The `ReadableByteStreamController` and BYOB reader are not available. Device fingerprint confirms this.

---

## RAB (ResizableArrayBuffer)

### RAB TOCTOU (set/clone/copyWithin) — DEAD: Per-Element Bounds

`set()` has per-element `inBounds`. `copyWithin` bounded by `maxByteLength`. `structuredClone` within bounds.

V416 was a false positive (signed/unsigned comparison bug in analysis, not in WebKit). V418 showed zero corruption. V419 detach is caught.

### RAB byteLength Inversion — DEAD: Sinks Guarded

Inverted OOB check in byteLength getter is real but all downstream sinks have correct guards.

The inversion allows a view to report an incorrect byte length, but every consumer that uses this value performs its own bounds checking.

### RAB IDL Gate — SAFE

ALL WebCore APIs reject resizable views at `toWrapped()`. Only `structuredCloneForStream` bypasses this gate, and that path is separately bounded.

---

## DOM / Rendering

### CSSFontFace UAF (CVE-2026-43715) — DEAD: DoS-Only

UAF exists but free and use are synchronous. All grooming fails.

Eager promise + setProperty adopt path writes `m_status 0x03` to freed FastMalloc memory. However, no JS re-entry window exists between free and use. The 192-byte size class contains only CSSFontFace — no type confusion target. All spray strategies (AB, string, Blob) fail. Confirmed DoS-only with p504.

### Canvas getContext() UAF (CVE-2026-43720) — DEAD: IsoHeap

Canvas contexts use `WTF_MAKE_ISO_ALLOCATED`. IsoHeap prevents cross-type replacement.

Reentrant `getContext()` creates a dangling wrapper, but IsoHeap isolation means the freed context memory cannot be replaced with attacker-controlled data. AB/string/Blob/Path2D carriers all confirmed failed. Community-confirmed dead.

### OffscreenCanvas getContext() — DEAD: Same IsoHeap Wall

Identical reentrant pattern at OffscreenCanvas.cpp:243-263, same IsoHeap isolation.

The A4 audit identified the same vulnerability pattern, but the same mitigation applies.

### EventTarget UAF — DEAD: isJSExecutionForbidden

Guard blocks second handler execution. Document never freed during dispatch.

`isJSExecutionForbidden()` prevents handler re-entry in the critical window. V405 confirmed on device.

### XMLParser Custom Element UAF — DEAD: Fragment Guard

Line 810: `!m_parsingFragment` skips CE check. `innerHTML` cannot trigger.

The XMLParser custom element instantiation path is guarded by a fragment-parsing check. Since innerHTML uses fragment parsing, it cannot reach the vulnerable code. XHTML iframes are dead on PS5. Main-frame XHTML requires specific content-type serving.

### Font loca OOB — DEAD: Validated on PS5

PS5 renderer validates loca table offsets. All OOB produce notdef fallback glyph.

Device-confirmed with V260. The PS5 font renderer (possibly Sony-specific) performs offset validation that upstream WebKit may not.

### BMP OOB Read — DEAD: Fixed

V400 and V402 returned fill values instead of leaked memory.

PS5 binary has the fix or uses a different BMP decoding codepath.

### Popover API Re-entrancy — MOOT: Not Available

Popover API not available on PS5 14.10.

No `popoverAttribute`, `showPopover`, or `ToggleEvent`. Analysis showed the pattern is safe anyway (EventDispatcher Ref + validity rechecks).

### Clipboard Iterator UAF — DEAD: No Clipboard

Clipboard API not available on PS5 despite `isSecure:true`.

CVE-2026-43727 clearItemTypeLoaders invalidation requires SecureContext + user gesture, but the API itself is absent.

### NodeIterator Adoption — SAFE: RefPtr

All 5 tests passed. `RefPtr` keeps nodes alive through adoption, GC, removal.

---

## CVE Audit

### CVE-2023-42917 — DEAD: Patched

Fix present in WK-1400 Structure.cpp:917-933.

### All 2023-2024 WebKit CVEs — DEAD: JIT-Dependent

Every CVE from this period targets DFG, FTL, or B3 JIT tiers.

These tiers are completely unavailable on PS5 (LLInt-only execution).

### All WSA-2026-0003/0004 CVEs — DEAD

39 CVEs audited individually. All require WASM, JIT, WebGL, or user-interaction APIs not available on PS5.

### MSE SourceBuffer Re-entrancy — SAFE

All events use `queueTaskToDispatchEvent` (async delivery).

Device-confirmed: re-entrant append, SourceBuffer removal during callback, ArrayBuffer detach after append — all handled correctly.

---

## Kernel / Syscall (from browser context)

### UMTX CVE-2024-43102 — DEAD: SHM Stubbed

Sony removed shared memory subsystem on firmware 14.10.

The `USHMF_LINKED` single flag check is impossible because the SHM syscalls are stubbed. PS5Dev/PS5-UMTX-Jailbreak covers FW up to 13.60 only. Our probe 10 used the wrong syscall number, confirming the stub.

### Kernel Probes (CVE-2026-49418, CVE-2026-7270, poll/select UAF) — BLOCKED

All require code execution outside browser sandbox. Unreachable from JavaScript.

CVE-2026-49418 (msync device-pager UAF), CVE-2026-7270 (execve memmove OOB), and the poll/select race condition all need native syscall access that the browser sandbox restricts.

### Sony Crash Tests — DEAD: Harness-Only

54 `[Crash]` tests in PS5 TestExpectations all require `testRunner` or `UIHelper` APIs.

None are triggerable from the browser. Mostly UI/viewport tests. The postMessage OOM test was the only interesting candidate but requires the test harness.

---

## Summary

| Category | Investigated | Dead | Safe/Moot |
|----------|-------------|------|-----------|
| JSC Engine | 10 | 10 | 0 |
| Streams API | 4 | 4 | 0 |
| RAB | 3 | 2 | 1 |
| DOM / Rendering | 10 | 7 | 3 |
| CVE Audit | 4 | 4 | 0 |
| Kernel / Syscall | 3 | 3 | 0 |
| **Total** | **34** | **30** | **4** |

All 34 investigated vectors are either confirmed dead (vulnerability does not exist, is patched, or is unexploitable on this platform) or confirmed safe (no vulnerability exists).

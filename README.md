# PS5 14.10 Jailbreak Research

WebKit memory safety research for PlayStation 5 firmware 14.10. All data comes from probes that ran on the actual console via the built-in browser.

> **Disclaimer:** Authorized security research on personally owned hardware. For educational and research purposes only.

## Target

Validated on device (p163, V399, V520, V521).

| Property | Value |
|----------|-------|
| Platform | PlayStation 5 |
| Firmware | 14.10 |
| OS | Prospero (FreeBSD r230171) |
| CPU | AMD Zen 2, 16KB pages |
| Browser | Safari 17.0 / AppleWebKit 605.1.15 |
| Source tree | **WebKit-1400** (primary), WebKit-1200 (secondary) |
| JIT | Disabled (LLInt only) |
| Cores | 4 |
| Display | 1920x1080 |

### API Availability (device-confirmed)

**Available:** Workers, WebSocket, fetch, SubtleCrypto (ECDH/AES), Canvas 2D, ReadableStream, ResizableArrayBuffer, WeakRef, FinalizationRegistry, Proxy, BigInt, structuredClone, MediaSource (H.264/AAC, no WebM), TransformStream, CSS Animations, FontFace, Atomics, MessageChannel, Intl.Segmenter, URLSearchParams, Response.clone

**Not available:** WebAssembly, SharedArrayBuffer, WebGL, WebAudio, IndexedDB, ServiceWorker, ReadableStream BYOB, WebRTC, WebGPU, Popover API, Clipboard API, AbortSignal.any

## Source Reference

The PS5 WebKit binary is not publicly available. We use the open source **WebKit-1400** snapshot as the primary reference for structure layouts, function internals, and allocator behavior. This is the closest matching version to the Safari 17.0 / AppleWebKit 605.1.15 engine on the console. WebKit-1200 (December 2023) is used as a secondary reference. All assumptions from source are validated on device with probes.

## The Bug (Bug 317632)

> **STATUS: DEAD ON PS5 — OOM before overflow triggers.** The AST required to generate enough metadata entries exceeds the PS5 WebContent process memory limit. See [Finding 8](#key-findings) for the full analysis. The .length=81400 results were false positives — see [Finding 9](#key-findings).

JavaScriptCore Bug 317632. `UnlinkedMetadataTable::finalize()` in `UnlinkedMetadataTable.cpp` (lines 99 to 164) uses an `unsigned` accumulator without `CheckedArithmetic`. When a function has enough metadata entries, the total wraps and the allocator gets the wrong size.

### Overflow Math

```
op_call metadata stride:  112 bytes (BaselineCallLinkInfo=72 + ArrayProfile=12 + pad=4 + ValueProfile=24)
Target call count:        38,348,816  (ceil(2^32 / 112))
True allocation:          38,348,816 x 112 = 4,295,067,392 bytes
uint32 wrapped:           4,295,067,392 mod 2^32 = 100,096 bytes (~100KB)
```

The allocator reserves ~100KB. The LLInt interpreter writes 4.29GB forward into adjacent heap memory when the function executes.

### Why It's Dead on PS5

Each `op_call` metadata entry requires a `FunctionCallValueNode` in the AST: 88 bytes for the node + 16 bytes for the `ArgumentsNode`. With `ThrowableExpressionData` adding 36 bytes per call node, each entry costs ~104 bytes in AST memory.

```
38,348,816 entries × 104 bytes/entry = ~3.7 GB AST
PS5 WebContent process limit: ~1.5 GB (OOM-killed beyond this)
```

The parser runs out of memory and the process is killed before `finalize()` ever runs. The function must also be **called** (not just compiled) for the sweep to occur — IIFE wrapping is required but doesn't help with the OOM wall.

### Allocator Chain

```
MetadataTableMalloc = FastMalloc (not IsoHeap)    [DebugHeap.h:91]
FastMalloc = libpas bmalloc                       [BPlatform.h:341]
ArrayBuffer backing = FastMalloc (Gigacage off)   [Gigacage.cpp:37]
All in the same allocator namespace
```

### Allocator Properties (PS5 FreeBSD)

| Property | Value | Source |
|----------|-------|--------|
| Allocator | libpas (bmalloc) | BPlatform.h:341 |
| Gigacage | **Disabled** | GigacageConfig.h (requires Darwin or Linux) |
| Large free behavior | Pages stay mapped | BPlatform.h:362, BUSE_RELEASE_LARGE_FREE=0 |
| Page decommit | madvise(MADV_FREE) | pas_page_malloc.c:261 |
| Page size | 16KB (Zen 2) | Hardware spec |
| Freed blocks | Stay mapped, assertions off | 256 granules (16KB each) |

## WK-1400 Source Audit

Comprehensive source-level audit of 15+ WebKit subsystems against WK-1400. All findings validated against PS5 constraints (no JIT, LLInt-only, FreeBSD).

### Subsystems Audited

| Subsystem | Result | Notes |
|-----------|--------|-------|
| MetadataTable overflow | DEAD | OOM before overflow (3.7GB AST needed) |
| MSE SourceBuffer | SAFE | All events use `queueTaskToDispatchEvent` (async). PS guards = logging only |
| ReadableStream / tee() | SAFE | JS builtin wall blocks all C++ field access |
| ResizableArrayBuffer | SAFE | All WebCore APIs reject at `toWrapped()`, per-element bounds checks |
| Canvas 2D / OffscreenCanvas | IsoHeap | Contexts use `WTF_MAKE_ISO_ALLOCATED`, isolated from JSC objects |
| CSSFontFace UAF (CVE-2026-43715) | DoS-only | Free/use synchronous, no grooming window |
| Canvas getContext UAF (CVE-2026-43720) | DEAD | Community-confirmed, all carriers fail |
| structuredClone | SAFE | `m_objectPool` roots all objects, no re-entry |
| NodeIterator / TreeWalker | SAFE | RefPtr protects all nodes during filter callbacks |
| Yarr regex | SAFE | Lookbehind forward-ref fixed in WK-1400 |
| DirectArguments | SAFE | `isMappedArgument(i)` checks `i < m_length` |
| sort() detach | SAFE | `m_vector` cleared, `m_length` zeroed |
| XMLParser custom elements | SAFE | `!m_parsingFragment` skips CE check; iframes dead on PS5 |
| Popover API | ABSENT | Not available on PS5 14.10 |
| Clipboard API | ABSENT | Not available on PS5 14.10 |

### PLATFORM(PLAYSTATION) Guards

11 PlayStation-specific code guards found across WK-1400. **All are logging-only** (`PS_LOG` debug prints) or behavioral (skip buffering rate monitoring). No safety checks are skipped on PlayStation.

One notable finding: **JSC Config freeze is DISABLED** on PlayStation (`disableFreezingForTesting()` at VM.cpp:397). Runtime config values like `startOfStructureHeap` remain writable after init — useful as a post-exploitation primitive but not an entry bug.

### StructureID on PS5

Pure mask+offset decode with no validation in release builds. No StructureID table — direct pointer into 128MB structure heap. Recycling-based attacks are impossible (no table to manipulate).

## Probes

### MetadataTable Overflow Series (DEAD — false positives)

| Probe | What it does | Result |
|-------|-------------|--------|
| p141 | Overflow test (wrong stride) | SIGSEGV |
| p142 | Correct stride (112) | Overflow triggers |
| p143 | Targets before buffer | No corruption, sweep is forward only |
| p144 | Bait and switch | Forward write confirmed |
| p146 | Worker .length polling | **.length = 81400 — FALSE POSITIVE** (correct literal length) |
| p147, p148 | Substring and main thread views | StringImpl data intact |
| p149g | Read after compile, before call | Overflow is at runtime not compile time |
| p150 | Throwing callback | OOB read crashes before callback |
| p156 | charCodeAt scan | All 0x41, m_data8 points to original buffer |
| p159, p161 | Gradient strings | Crash, rope cells mess up heap |
| p160 | Relapse CVE set | **All patched on 14.10** |
| p163 | Device fingerprint | Complete |
| p165 | 400MB heap padding + multi read | Crashed at CALLING |
| p167 | 15+ read primitives, auto retry | Crashed at CALLING |
| p168 | Pre watch (compile only, no call) | **No corruption. Proves OOB is at runtime** |
| p169 | p156 pattern + extraction + retry | 3 attempts, all crashed at CALLING |
| p170 | CVE-2023-42890 FTP redirect UAF | **NetworkProcess survived all phases** |
| p171 | Mapped heap padding + CPU starvation | Crashed |

### Device Fingerprinting & API Probes

| Probe | What it does | Result |
|-------|-------------|--------|
| V399 | Comprehensive API availability map | Complete — see [API Availability](#api-availability-device-confirmed) |
| V515 | Clipboard API UAF probe | DEAD — Clipboard API absent |
| V518 | Popover re-entrancy probe | DEAD — Popover API absent |
| V519 | NodeIterator adoption during filter | ALL SAFE — RefPtr protects nodes, alive-after-gc: 10/10 |
| V520 | MSE SourceBuffer re-entrancy, mode switch, AB detach race | ALL SAFE — async events, proper state checks |
| V521 | Structure spray, butterfly realloc, megamorphic IC, GC probe | No anomalies |

### V520 MSE Results (device-confirmed)

```
MediaSource: YES | SourceBuffer: YES
H.264 Baseline (avc1.42E01E): YES | H.264 High (avc1.64001E): YES
AAC (mp4a.40.2): YES | WebM/VP8: NO

T2 — Re-entrant append in updateend: ALLOWED (updating=false at that point, spec-compliant)
T3 — SourceBuffer removal during callback: ALLOWED (async events)
T4 — AB detach after appendBuffer: Data already copied, endOfStream blocked (InvalidStateError)
T5 — Mode switch segments→sequence: Works. timestampOffset during update blocked (InvalidStateError)
```

### V521 Structure Spray Results (device-confirmed)

```
T1 — 500 shapes created, structure sharing works correctly
T2 — 10000 property add/delete/readd cycles: all values correct
T3 — Object.seal + sloppy mode: silent fail (expected, not a bug)
T4 — Butterfly grow/shrink/hole: sparse mode correct, dictionary keys correct
T5 — Megamorphic IC stress (200 shapes × 10 rounds): correct totals
T6 — WeakRef + GC pressure: 100/100 alive, 0 dead, no type confusion
```

## Key Findings

### MetadataTable Series (DEAD ON PS5 — false positives)

1. **MetadataTable integer overflow triggers on device.** JavaScriptCore Bug 317632. `UnlinkedMetadataTable::finalize()` uses an `unsigned` accumulator. 38,348,816 call sites wraps it to 100,096 bytes. The interpreter allocates a 100KB buffer but writes 4.29GB forward into heap memory.

2. **Bait and switch heap groom controls where the write lands.** Bait strings fill the heap first. Target strings go above them. Free the baits and run GC. The metadata buffer takes a freed bait slot. The sweep goes forward into the targets.

3. **The sweep corrupts JSString objects.** The overflow overwrites `m_fiber` in JSString headers inside MarkedSpace. All 14 targets report `.length = 81400` after the sweep.

4. **StringImpl backing data stays intact.** `charCodeAt` returns the original 0x41 because `m_data8` still points to the original buffer. The corruption is in the JSString header, not the character data.

5. **The overflow happens at runtime, not compile time.** p149g confirmed zero corruption after compilation. The OOB write occurs when the LLInt runs each `op_call`.

6. **Gradient fill strings crash the browser.** `String.fromCharCode` loops create ~1.4M extra rope cells that change the heap layout and crash before the overflow finishes.

7. **All Relapse WebKit bugs are patched on 14.10.** p160 tested the full set. None work.

### Corrected Findings

8. **MetadataTable overflow is DEAD on PS5.** 38M entries × 104B/node = 3.7GB AST. PS5 WebContent process OOM-kills at ~1.5GB. The overflow mathematically cannot trigger within PS5 memory limits. The function must also be called (IIFE required) for the sweep to run — but the parser OOM kills the process before the function even compiles.

9. **.length=81400 was a false positive.** The probe's literal chunk was 814 characters. 100 chunks × 814 = 81,400 — the correct string length, not corruption. Confirmed with varied chunk sizes (817 chars → 81,700 = also correct). The MarkedSpace sweep never ran because the parser OOM'd first.

### Source Audit Findings

10. **All 2023-2024 WebKit CVEs target JIT tiers unavailable on PS5.** Comprehensive audit of 39 CVEs from WSA-2026-0003/0004 found all require DFG, FTL, B3, WebAssembly, WebGL, or user-interaction APIs absent on PS5.

11. **Gigacage DISABLED on FreeBSD.** ArrayBuffer backing stores live in the same FastMalloc heap as JSC objects. No address-space isolation. `GigacageConfig.h` requires Darwin or Linux.

12. **JSC Config freeze DISABLED on PS5.** `disableFreezingForTesting()` at VM.cpp:397 means runtime config values remain writable post-init. `startOfStructureHeap` is mutable — any arbitrary write primitive can redirect all StructureID lookups for instant type confusion.

13. **All PLATFORM(PLAYSTATION) guards are logging-only.** 11 guards across WK-1400 (SourceBuffer.cpp, ContentSecurityPolicy.cpp, VM.cpp, JSLock.cpp, etc.). All are `PS_LOG` debug prints or skip non-safety functions like `monitorBufferingRate()`. No safety checks are weakened.

14. **Canvas/OffscreenCanvas contexts use IsoHeap.** `WTF_MAKE_ISO_ALLOCATED` isolates these objects from general FastMalloc/JSC heap. Cross-type confusion via MetadataTable sweep or other linear overwrites cannot reach them.

15. **All InternalReadableStream operations route through JS builtins.** Every C++ bridge function uses `jsDynamicCast` with null checks. The JS builtin wall means type confusion via private-name inversion cannot reach C++ code paths that access internal fields directly.

### Additional Findings

16. **Conservative GC blocks butterfly UAF strategies.** All 9 bypass angles exhausted. The conservative scanner pins butterfly cells, preventing reclaim for type confusion.

17. **CSSFontFace UAF (CVE-2026-43715) is DoS-only.** The free and use are synchronous — no grooming window. All spray strategies fail under every timing combination. CSSFontFace is the sole occupant of the 192-byte size class.

18. **Canvas getContext UAF (CVE-2026-43720) is DEAD.** IsoHeap wall prevents cross-type replacement. Community-confirmed: AB, string, and Blob carriers all fail.

19. **Unchecked jsCast in JSC runtime is safe.** Every unchecked `jsCast<>` is preceded by a C++ type check (`@isRegExpObject`, `@isMap`, `isTypedView()`, etc.). Private-name inversion cannot bypass these because they check cell type, not property presence.

## Secondary Path: CVE-2023-42890

NetworkProcess use after free in `NetworkLoad::willPerformHTTPRedirection()`. Fixed in Safari 17.2, present on PS5 14.10 (Safari 17.0).

When the server sends an HTTP 302 redirect to an `ftp://` URL:

1. `willPerformHTTPRedirection()` checks `ftpEnabled()` and finds FTP disabled
2. `didCompleteWithError()` notifies the client
3. Client calls `cleanup()` which sets `m_networkLoad = nullptr`, destroying the NetworkLoad object
4. Execution returns to `willPerformHTTPRedirection` where `completionHandler` runs on freed memory

Confirmed on device: the redirect triggers, `TypeError: Load failed` returned to JavaScript. NetworkProcess survives because the freed memory is not dereferenced on the curl backend (PS5 uses the curl networking path, confirmed by `#if PLATFORM(PLAYSTATION)` in `NetworkDataTaskCurl.cpp`).

The completionHandler lambda captures `Ref{*this}` of NetworkDataTask (not the freed NetworkLoad), and the default constructed ResourceRequest is null, so the lambda returns immediately. No crash without heap grooming to replace the freed slot.

NetworkLoad object is ~1024 or 2048 bytes in bmalloc. `m_redirectCompletionHandler` contains a vtable pointer through `CallableWrapperBase`. Controlling that offset gives arbitrary code execution in the NetworkProcess (separate sandbox from WebProcess).

## Progress

| Stage | Status |
|-------|--------|
| Bug identification (Bug 317632) | Done (but DEAD on PS5 — OOM) |
| Source audit (WK-1400) | Done — 15+ subsystems, 0 exploitable from browser |
| Device fingerprinting | Done (V399, V520, V521) |
| CVE triage (2023-2026) | Done — all dead (JIT/WASM/WebGL requirements) |
| PLATFORM(PLAYSTATION) audit | Done — logging only, no safety gaps |
| WebKit entry bug | **NOT FOUND** — all leads exhausted |
| Kernel exploit | BLOCKED — no browser code execution |
| Privilege escalation | Not started |

## How to Use

1. Clone the repo
2. Set up a DNS redirect pointing a domain to your host machine
3. Run `python3 tools/host.py` on the host
4. Open the URL on the PS5 browser
5. Watch the beacon log for results

## Models Used

This research was built with multiple LLMs working together.

| Model | Role |
|-------|------|
| Claude Opus 4.6 | Primary workhorse. Probes, source analysis, struct layouts, heap modeling, coordination |
| GPT-6.1-Sol | Codex dispatches, verification passes, structure recommendations |
| GPT-6.1-Astra | Flagship analysis (sometimes unavailable) |
| DeepSeek v4.1-Flash | Scene sweep, PUP carving, gap analysis, gadget hunting |
| DeepSeek v4-Pro | Deep analysis tasks |
| GLM 5.3 Flash | Router analysis, verification, cross audit |
| Kimi K3 | Escape sequence analysis, exploit page construction |
| Qwen 3.8 | Architecture ladder synthesis, verification |
| Mimo | Analysis support |

## Contact

X: [@Arn0Stride7](https://x.com/Arn0Stride7)

## License

MIT

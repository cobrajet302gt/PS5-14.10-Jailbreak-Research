# 14.10 coalition battery — one-shot bench fingerprint (Tuesday protocol draft)

Run order and the three-tuple report. All probes are single-page, self-beaconing, no external deps beyond a beacon logger (sync-XHR GET /beacon/<tag> is enough).

1. **Engine era markers** — `../era-fingerprint/` P586-style feature probes (async-iterator, asyncDispose/Temporal/try/Float16 absent/present) + JIT presence (tier timing). Expected for 14.10 retail: Jan–early-Feb 2024 fork signature.
2. **44308 firing** — `../era-fingerprint/P593_44308.html`. Expected on retail 14.10: `P594-C-...ISVALS` fires every document (54/54 on our bench; ambient-payload, see evidence/). A bench that DOESN'T fire has a different WebKit build.
3. **Oracle separation** — `P588_TC.html` (interleaved cold/warm tick-count, n>=20). Expected: non-overlapping distributions, ~10% separation. Calibrates the bench's timer lane.
4. **Encoder plant-detect** — `P590_ENCODER.html`. Expected: argmin = planted slot ~99%.
5. **Pool triple** (needs a leak source — WALK/canvas addrof on your bench): log 30+ leaked 16 KiB-buffer addresses with timestamps, then report:
   - residue histogram mod 0x1000 (expect ONE dominant value per era; ours: 0xbf0 / 0xf10 / 0xec0 eras, 17/17 monoculture)
   - consecutive-delta family (expect exact multiples of 0x4000; ours 509/509)
   - same-address stickiness % (ours ~60%)
   Laws verified on our bench against safari-7616 tree arithmetic (see ../../evidence/p44308-fork-verify-20261121.txt era discussion): residue = reuse-equilibrium state, NOT a build fingerprint — compare the TRIPLE, never residue alone. Fresh-bump residue 0x000 has never been observed in 1280 catches (reuse lattice, not fresh conveyor).

Cross-bench agreement test: two benches in the same era should match residue AND stride family AND stickiness band. Divergence in any one localizes the difference (config vs state vs build).

6. **Joint addrof (p597)** — merged 44308 x unicode-range-oracle page (venue #305 protocol; cobrajet bench serves `p597_joint.html` + `lib44308.js`, auto-adopting `oracle_walki.js`). Steps: ASLR-class classification boot FIRST (VP slot RVA + 3x16KiB deltas — ASLR state is a per-unit variable, 0/21 vs 4/4 across benches), then PRE-sweep → fire → POST-sweep → `P597-Delta` beacon. Hard rules: oracle-only reads (`face.style` = post-UAF cache on BOTH retail units), never read text directly (XO crash), text/ELF checks only via two-point unicode-range (full-coverage scans OOM ~38 MB).
7. **Canvas depth-differential** (post hex #295 source answer, 2026-11-22): victim = 768B CanvasRenderingContext2D object incl. inline-capacity-1 `m_stateStack`. Arms: depth-0 (zero `save()` before the outer-bitmaprenderer/inner-2d swap → State inline) vs depth-N (N=3 saves → State out-of-line). Readout: stale-inner-wrapper `lineWidth`/`strokeStyle` sensitivity — sibling OBJECT bytes (depth-0) vs sibling STATE BUFFER (depth-N). Falsification: identical geometry across arms ⇒ inline-capacity-1 not driving aliasing. If resolved, report implied in-chunk `m_stateStack` offset (cross-checks item 6 oracle datum). See cobrajet skill ref `canvas-uaf-source-mechanism-2026-11-22.md`.


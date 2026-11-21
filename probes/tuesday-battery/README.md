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

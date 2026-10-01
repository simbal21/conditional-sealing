# @cealis/v3-configurator

## Status (at retirement, June 2026)

**partial.** Honest work-in-progress.

## Known defect at retirement: the package barrel exports a no-op validator

The root README's status row flags this; here is the exact defect, left as shipped because this repository is a point-in-time record.

- **Where:** `src/index.ts` (line 27) exports `classifySurface` from `./validate/boundary/types.js` — the Phase A *placeholder* that returns the same fixed classification for every surface, i.e. it validates nothing.
- **The real implementation exists:** the working cascade (Tests 1, 1.5, 2, 3) is in `src/validate/boundary/cascade.ts`, correctly re-exported by `src/validate/boundary/index.ts`. The behavioral tests import `classifySurface` from that boundary barrel, not the package barrel — which is why the suite is 440/440 green while the public barrel ships a validator that never rejects.
- **If you fork:** import from `./validate/boundary/index.js` (or repoint the package barrel's `classifySurface` export from `types.js` to the boundary barrel) to get the real validator.

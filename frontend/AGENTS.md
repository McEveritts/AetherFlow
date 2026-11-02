<!-- BEGIN:nextjs-agent-rules -->

## This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` (resolved from this file's directory; in monorepos the `next` package may not be visible from the repo root) before writing any code. Heed deprecation notices.

This block is written and re-added by `next dev` — verify at `node_modules/next/dist/server/lib/generate-agent-files.js`. Removing it from a diff only re-creates the uncommitted change; committing it with your work keeps the tree clean.

<!-- END:nextjs-agent-rules -->

## AetherFlow frontend guardrails

- Keep the managed Next.js block above intact; add project guidance outside its markers. Resolve installed Next.js guides through the monorepo's `../node_modules/next/dist/docs/` when needed.
- Never run `node`, `npm`, or `npx` on the Windows workstation. Run frontend tools over SSH on the Linux development host. Use a runtime satisfying `package.json` engines (currently Node >=22.19.0); Node 24 is used for the current frontend validation environment.
- Preserve pre-existing tracked and untracked changes. Do not reset, clean, stage, commit, or deploy unrelated work. A stale Windows checkout is not a substitute for the current authoritative checkout.
- Release validation includes test-file TypeScript. Do not exclude tests or enable `ignoreBuildErrors` to bypass a failed build. Jest passing alone does not establish type correctness.
- Keep secret scanning enabled. Synthetic fixtures require narrow, reviewed exemptions; do not ignore whole test directories or all TypeScript/Rust tests to silence a finding.
- Preserve unsaved form input across background SWR/store refreshes. Follow authoritative server values after successful saves without discarding newer edits made while a request was pending. Add regression tests for these transitions.
- Preserve static-export compatibility and working local/fallback app icons. Do not introduce a runtime image optimizer or replace icon behavior solely to silence a non-blocking image warning.
- Constrain overflow at the component boundary with `min-w-0`, `max-w-full`, and scoped scrolling; never mask layout problems with blanket viewport overflow clipping.

## Validation

Run these commands from `frontend/` on Linux with a supported Node runtime and installed monorepo dependencies:

```sh
../node_modules/.bin/tsc --noEmit --incremental false
npm run lint
npm run test:ci
NEXT_STATIC_EXPORT=1 npm run build
```

Run focused tests first, then the full checks. Prefer an isolated validation copy when a build would overwrite another process's `.next` or export output. These commands validate source; they do not authorize a commit, push, deployment, or service restart.

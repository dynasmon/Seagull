# Elastic UI (EUI) Compatibility Spike — Findings & Decision

Branch: `spike/elastic-eui` · Date: 2026-05-29 · Stack: React 18.3.1, Vite 5.4.21, TypeScript 5.5.4, Tailwind 3.4, npm 10.

## Decision: GO (conditional)

Proceed with the full migration to real `@elastic/eui` through controlled phases. Technical compatibility is proven across install, strict typecheck, production build, dev server, lint and tests, with **no regressions** to the existing app. The cost is bundle size and chunk count — expected for EUI, acceptable for an internal SOC console, and manageable with the mitigations below.

**One gate remains before Phase 1 work begins:** a short interactive **visual coexistence sweep** in a real browser (this environment has no browser binary, and the running `seagull-portal` container serves the pre-EUI image, so pixel-level rendering could not be verified headlessly). Steps are in "Open item" below. If that sweep shows no global-style breakage (expected, per the analysis), the GO is unconditional.

## What was validated

| Check | Baseline (pre-EUI) | With EUI | Verdict |
|---|---|---|---|
| Dependency install | — | clean, **no peer conflicts**, `react@18.3.1` deduped (single instance) | PASS |
| Production build (`tsc -b && vite build`) | ✓ 5.40s | ✓ 14.54s | PASS |
| TypeScript (strict) | ✓ | ✓ | PASS |
| Dev server (`vite`) | ✓ | ✓ ready 141ms, EUI deps optimized, modules transform 200, no errors | PASS |
| Lint (`eslint .`) | 0 errors, 12 warnings | **0 errors, 12 warnings (identical)** | PASS |
| Tests (`vitest run`) | 80 pass / 3 fail / 16 files fail | **identical — no new failures** | PASS (no regression) |
| Visual rendering (EUI + Tailwind, dark/light) | — | not verifiable headlessly | OPEN |

Note on the test baseline: the suite is already partially red **before EUI** — 15 `network_topology` test files fail at *collection* (they import the sigma/graphology/webgl graph and there is no jsdom/DOM environment configured for vitest), plus 3 assertion failures in `overview/live_realtime.test.ts`. EUI changes none of this. (Worth fixing separately by adding a jsdom test environment.)

## Installed dependency family (minimum)

`@elastic/eui@116.2.0`, `@elastic/eui-theme-borealis@8.0.0` (pulls `@elastic/eui-theme-common@10.0.0`), `@emotion/react@11.14.0`, `@emotion/css@11.13.5`, `moment@2.30.1`, `@elastic/datemath@5.0.3`. `@elastic/charts` intentionally **not** installed (deferred; also needs `moment-timezone`). Install added 173 packages and reported 9 moderate transitive audit advisories (not force-fixed).

## Bundle impact (measured)

| Metric | Baseline | With EUI | Delta |
|---|---|---|---|
| Total `dist` | 2.1 MB | 7.3 MB | ×3.5 |
| Total JS (raw) | 1.75 MB | 5.68 MB | +3.93 MB |
| Total JS (gzip) | 487 KB | 1.35 MB | **+860 KB gzip** |
| **Entry chunk (eager, every load)** | 221 KB / **70 KB gz** | 486 KB / **154 KB gz** | **+84 KB gz eager** |
| Built CSS | 86.3 KB | **86.3 KB (unchanged)** | 0 |
| JS chunks | 89 | 631 | +542 (58 are `logo_*`) |
| `/eui-lab` lazy chunk | — | 2.92 MB / 635 KB gz | isolated/lazy |

Reading the numbers:
- **EUI ships zero static CSS.** The built CSS is byte-for-byte identical; all EUI styling is runtime Emotion CSS-in-JS injected into `<head>`. So there is no CSS-file conflict — only JS weight and runtime injection ordering.
- **Eager cost is ~+84 KB gzip** (EuiProvider + Borealis theme + EUI core, always loaded because the provider is at the root). This is the number that matters for initial load.
- The 2.92 MB `/eui-lab` chunk **overstates** per-page cost: Rollup put every EUI component used by that single lazy route into one chunk. App-wide, EUI belongs in a shared vendor chunk loaded once and cached (see mitigations). The honest "total EUI surface" is the +860 KB gzip total-JS delta.
- **Chunk explosion** comes from `EuiIcon` lazy-importing each icon/logo as its own chunk (58 `logo_*` + many icon chunks). Functionally fine; operationally noisy without grouping.
- recharts (`LineChart` ~340 KB) and the topology page (~340 KB) chunks are **unchanged** — EUI did not bloat or interfere with them.

## Tailwind / EUI coexistence

Strategy implemented: a `<meta name="emotion-insertion-point">` at the top of `index.html` `<head>`, and `EuiProvider` configured with `@emotion/cache` (`default`/`global`/`utility`) pointing at that insertion point (`src/app/eui/EuiRoot.tsx`). EUI styles therefore inject **before** Vite's app stylesheet, so Tailwind utilities win equal-specificity ties and the existing Tailwind pages are protected from EUI's global reset.

Specificity analysis (why this is expected to be safe): Tailwind Preflight resets are element-level (low specificity); EUI component styles are class-level (`.euiButton`, higher specificity) and win regardless of source order. The residual risk is bare elements inside EUI components where EUI's element-level global styles and Tailwind Preflight collide at equal specificity — there, source order decides and Tailwind wins, which is the exact case to confirm visually.

Available levers if the visual sweep finds issues:
- `globalStyles={false}` on `EuiProvider` — drop EUI's reset, rely on Tailwind Preflight.
- Disable Tailwind Preflight (`corePlugins.preflight=false`) — rely on EUI's reset (larger blast radius on the existing app).
- Flip the insertion order so EUI wins ties (if EUI components look under-styled).

Theme: `EuiProvider colorMode` is synced to the existing `useTheme()` state (single source of truth; `html.dark` continues to drive both). No second theme toggle introduced.

## Open item — interactive visual sweep (do before Phase 1)

This environment has no browser; run locally:
1. `cd frontend && SEAGULL_API_PROXY_TARGET=http://localhost:8000 npm run dev`, open `http://localhost:5173`. (Host dev: the backend is published on `:8000`; the default proxy target `seagull-backend:8000` only resolves inside docker. The override is backwards-compatible — it falls back to the docker name when unset.)
2. Log in, visit `/eui-lab` and exercise each tab (Shell, Flyout, Tables & grid, Search & forms, Primitives) in **dark and light**.
3. Sweep existing pages for global-style breakage: `/overview` (recharts), `/network-topology` (sigma canvas), `/events`, `/alerts`, `/inventory`, and any drawer.
4. Confirm: existing pages look unchanged; EUI components render correctly; no layout/contrast regressions on theme toggle.

## Per-primitive wrapper-vs-replace (for Phase 3)

The shared primitives are imported via stable module paths by 136 files, so converting the module internals to EUI migrates consumers without call-site churn. Recommended approach per primitive:

- **Thin wrapper (keep current API):** `Button`→`EuiButton`/`EuiButtonEmpty`; `Badge`→`EuiBadge`; `SeverityPill`→`EuiBadge` (severity color map); `StatusPill`→`EuiHealth`; `Card`/`Panel`→`EuiPanel`; `Tabs`→`EuiTabs`; `Drawer`→`EuiFlyout` (clean contract match: focus-trap/Esc/mask/sizing native); `MetricCard`→`EuiPanel`+`EuiStat`; `EmptyState`→`EuiEmptyPrompt` (49 usages — high value); `Loading`→`EuiLoadingSpinner`/`EuiSkeleton`; `InlineAlert`/`StatusBanner`→`EuiCallOut`; form fields→`EuiFieldText`/`EuiTextArea`/`EuiSelect`/`EuiCheckbox`/`EuiFormRow`.
- **Adapter (recompose):** `PageHeader`→`EuiPageHeader`/`EuiPageTemplate.Header`; `DataView` toolbar→`EuiSearchBar`+`EuiFilterGroup`; `Table`→`EuiBasicTable` for simple tables, `EuiDataGrid` for dense hunt/events grids (largest single component — keep route-split).
- **Delete, don't migrate:** `IconButton` and `QueryState` have **0 usages** (dead code).

recharts and sigma/graphology/@xyflow stay as-is (no EUI equivalent in scope; built cleanly alongside EUI).

## Required Phase-1 mitigations (bundle)

1. `build.rollupOptions.output.manualChunks` to hoist `@elastic/eui` + `@emotion` + `@elastic/eui-theme-*` into one shared vendor chunk (download once, cache across routes).
2. Reduce icon chunk sprawl: group `@elastic/eui` icon assets via manualChunks and/or preload the common icon set; avoid `logo_*` icons we don't need.
3. Keep `EuiDataGrid` route-split to hunt/events pages.
4. Re-measure eager bundle after manualChunks; target keeping the always-loaded delta near the ~84 KB gz observed.

## If we had aborted — removal steps

The spike is isolated and reversible: delete `src/features/_eui_lab/` and `src/app/eui/`, remove the `/eui-lab` route from `src/app/routes.tsx`, unwrap `EuiRoot` in `src/app/providers.tsx`, remove the `emotion-insertion-point` meta from `index.html`, and `npm uninstall` the six packages. No existing page or shared primitive was modified.

## Recommended next phases (on confirmed GO)

1. Foundation: finalize provider/cache/theme; add manualChunks vendor split + icon grouping; establish shared EUI adapters (no raw EUI in feature pages).
2. Shell/Sidebar/TopBar → Kibana-like (`EuiHeader`/`EuiPageTemplate`/`EuiSideNav`); mature SOC IA; demote DDoS from primary nav to a lens; backward-compatible route redirects.
3. Migrate shared primitives to EUI via wrappers (above), then remove the dead `IconButton`/`QueryState`.
4. Overview as the reference EUI SOC dashboard.
5. Feature areas incrementally (Alerts → Events/Hunt → Entities/Inventory → Network/Topology → Exposure/Vulns → Investigations → Response → Governance → Settings), removing legacy per phase.

# EUI Migration — Live Status & Resume Handoff

**This is the single source of truth for resuming the EUI migration.** Read this first, then `frontend/docs/eui-spike.md` for the original spike rationale.

Branch: `spike/elastic-eui` · Goal: migrate the Seagull frontend to **real `@elastic/eui`** (Borealis theme), faithfully Kibana-like. **The human commits/pushes — never run `git commit`/`push`.** Nothing is auto-committed by the assistant.

Last updated: 2026-05-30 (default table density → EUI `compressed`; `ResponseActionDrawer` → EUI done; `DraftNumberInput` → `EuiFieldNumber` done; ALL 8 feature areas done).

---

## TL;DR — where we stopped

Phases **1, 2, 3, 4 are DONE**, and **all 8 Phase 5 feature areas are DONE** (1 Alerts · 2 Events · 3 Entities/Inventory · 4 Network/Topology · 5 Exposure & Vulnerabilities · 6 Investigations & Cases · 7 Governance & Platform · 8 Settings), plus the shared **`DataView` primitives** (cross-cutting, ~21 pages), the shared **`DraftNumberInput`** cross-cutting batch, and the **`ResponseActionDrawer`** (Response & Automation). **The per-feature migration is complete — every feature page now renders on the shared EUI adapters; what remains is cross-cutting cleanup + final visual QA.** All work passed the verification baseline at every batch (build 0, lint 0-err/12-warn, tests at baseline, eager entry ~114.6 KB gz).

**Remaining (not feature areas):**
1. Optionally finish the `DataView` **layout shells** on EUI (`DataViewToolbar`→`EuiPanel`, `DataTableSkeleton`→`EuiSkeleton*`) — kept as-is so far.
2. Bundle re-measure + EUI icon tree-shaking (`appendIconComponentCache`); reconsider the `code_block` highlighter lazy chunk.
3. The full **dark + light browser QA SWEEP** across every page (no browser in this env) — see the per-area checklists below.

---

## Verification protocol (run after EVERY batch — must match baseline, no NEW failures)

From `frontend/`:
- **Build:** `npm run build` → must exit 0 (`tsc -b` strict + vite).
- **Lint:** `npm run lint` → **0 errors, 12 warnings** (pre-existing; don't add new ones).
- **Tests:** `npx vitest run` → exits 1 at baseline. Baseline = **3 failed / 81 passed; 16 failed files**. The only allowed failures: 15 `tests/features/network_topology/*` files fail at *collection* (no jsdom env; they import sigma/webgl) + 3 assertion fails in `tests/features/overview/live_realtime.test.ts`. Anything beyond these is a regression.
- **Bundle:** eager entry chunk (`dist/assets/index-*.js`) ≈ **114 KB gz** — keep it there (EUI/charts/tables/codeblock must stay route-split, not eager).
- **No browser here**; the running `seagull-portal` container serves a pre-EUI image. After visible changes, tell the human to verify:
  `cd frontend && SEAGULL_API_PROXY_TARGET=http://localhost:8000 npm run dev` → http://localhost:5173 (backend on :8000, OTP/2FA login).

## Hard rules (do not violate)
- Migrate a primitive by reimplementing the EXISTING `src/shared/components/<X>.tsx` internals on EUI while keeping its EXACT public prop API. No parallel/duplicate components. ~136 files import these via stable paths and must keep working unchanged.
- For props EUI can't honor: keep them in the prop TYPE (API compat) but don't destructure them (avoids `noUnusedLocals`). Don't silently drop user-facing behavior.
- **NO code comments. NO commented-out code.** English only if truly unavoidable.
- Preserve ALL behavior/routes/URL-state/realtime/filters/drawers/tables/pagination/charts/topology. Don't mock data, change backend contracts, or fake security capabilities.
- Feature-sliced; no global `src/services`; don't rename any `api.ts`; group drawer props as controllers. Sidebar is "always dark." Never name a Tailwind `boxShadow` key after a color.
- Reuse `src/shared/lib/` utils (severity, status, date, ipClassification, format, filters, http). Avoid app-level horizontal scroll.
- Each phase ends clean: remove dead/legacy only after the replacement is wired, all usages migrated, and build/lint/tests pass.

---

## DONE

### Foundation
- `src/app/eui/EuiRoot.tsx` — EuiProvider + `EuiThemeBorealis`, Emotion caches via `<meta name="emotion-insertion-point">` (top of `<head>` in `index.html`) so **Tailwind wins specificity ties**. `colorMode` synced to app `useTheme()`. Mounted in `src/app/providers.tsx`.
- `vite.config.ts` — `SEAGULL_API_PROXY_TARGET` env override for the `/api` proxy; `manualChunks` grouping EUI icons.

### Phase 2 — shell
- `src/layout/Sidebar.tsx` → `EuiSideNav`, always-dark via nested `<EuiThemeProvider colorMode="dark">`. EuiSideNav has no icon-rail, so the **custom compact icon-rail (`CompactNav`) was kept** for collapsed mode; expanded mode uses EuiSideNav. Active state from `useLocation`; client-side nav with cmd/ctrl-click fallthrough; mobile drawer preserved.
- `src/layout/TopBar.tsx` → `EuiHeader` (router breadcrumbs, search field, theme toggle, user, sign-out, mobile + collapse toggles).
- `src/layout/navigation.ts` — 9-group SOC IA; DDoS/SSH/Protocol demoted to Events lenses (present only in breadcrumb metadata, not nav groups). Test: `tests/app/navigation_meta.test.ts` asserts the group order + that DDoS/SSH/Protocol are NOT primary nav items.

### Phase 3 — all shared primitives on EUI (API-preserving adapters)
- **Phase 1 set** (already done before this work): `EmptyState`→EuiEmptyPrompt, `Loading`→EuiLoadingSpinner, `InlineAlert`/`StatusBanner`→EuiCallOut, `Badge`/`SeverityPill`→EuiBadge, `StatusPill`→EuiHealth, `Card`/`Panel`→EuiPanel, `Tabs`→EuiTabs, `MetricCard`→EuiPanel+EuiStat. Severity→EUI color map in `src/shared/lib/severity.ts` (`severityEuiColor`).
- `Button` → EuiButton/EuiButtonEmpty; `size="icon"` renders a square EuiButton/EuiButtonEmpty with the node as children (NOT EuiButtonIcon — avoids forcing a ReactNode through `iconType`; `size="icon"` has 0 consumers anyway).
- `Panel` → EuiPanel (paddingSize none + custom header/body/footer markup preserved).
- `PageHeader` → EuiPageHeader (router-aware breadcrumbs + tabs).
- `Drawer` → **EuiFlyout** + EuiFlyoutHeader/Body/Footer (242→95 lines). Dropped the hand-rolled focus-trap/Esc/scroll-lock/drawer-stack/portal — EUI does all natively, including **nested-flyout stacking** (`PinToWorkspaceDrawer` stacks over 6 parent drawers: EventDrawer, InventoryDrawer, AttackChainDrawer, NetworkTopologyDetailDrawer, ResponseActionDrawer, ProtocolIndicatorDrawer). Kept custom header (eyebrow `headerLabel` + custom close via `hideCloseButton`); `widthClassName` applied as class + `maxWidth={false}` (pixel-identical widths); `closeOnOverlayClick`→`outsideClickCloses`. `initialFocusRef` kept in type, unused (0 consumers).
- `Table` → **EuiBasicTable** (~22 consumers). EuiBasicTable is **controlled — it does NOT reorder items**; consumers pre-sort (matches the old behavior). Columns always provide `render` so EUI `field` is just a sort-id (`width` number→`px` string). Sort via `sorting`+`onChange`; row click/highlight/`rowClassName` via `rowProps` (index via a row→index Map); `compact`→`compressed`; footer rendered below; checkbox selection = a custom controlled leading column (0 consumers use it). Signature changed to `Table<T extends object>` (EUI constraint; non-breaking). Sticky header + `scrollX` (old `w-max`) preserved via scoped CSS in `styles.css`: `.seagullTable-stickyHeader .euiTableHeaderCell` and `.seagullTable-scrollX .euiTable`.
- Form fields (all `compressed`): `TextInput`→EuiFieldText, `TextArea`→EuiTextArea, `SelectInput`→EuiSelect (**converts `<option>` children → `options[]`**; `value` narrowed off multi-select), `CheckboxField`→EuiCheckbox (generated `id`; `onChange` fallback noop), `ToggleSwitch`→EuiSwitch (`onChange` adapted from `EuiSwitchEvent`→input event so `e.target.checked` still works).
- `JsonBlock` → EuiCodeBlock (native copy `isCopyable`, `overflowHeight`, `whiteSpace`; kept the Wrap toggle). NOTE: pulls a syntax highlighter into a **~180 KB-gz lazy `code_block` chunk** (bundle debt to watch; not eager).
- `AsyncState` — retry button → EUI `Button` (already composed migrated EmptyState/Loading).

### Phase 4 — Overview reference dashboard (`src/features/overview/page.tsx`)
Rebuilt as the canonical EUI SOC dashboard; **only relayout — all wired behavior preserved** (live snapshot, storm status, range controls via `useOverviewLiteWindow`, every chart `SimpleTimeSeries`, all tables, the attack-chain fetch, telemetry-quality breakdown):
- Header → `PageHeader` (+ status `HeaderBadge`s); dropped the "Command center" filler tile.
- **One compact `EuiStat` KPI strip** (Events · Active agents · Open alerts · Attack chains[link] · Storm phase · Ingest EPS) — replaced the duplicate `DataStatsStrip` + the 14-card "Ingestion & health" wall.
- **One grouped "Pipeline health" panel** — 8 compact `EuiStat`s (EPS in/out, Workers, Backlog+msgs, Drop %, Sample, Drain, Last event) + storm reason line + the Telemetry-quality grid.
- Quick-pivots slimmed 8→4 (Alerts, Events, Attack Chains, Investigations).
- **DDoS de-emphasized**: "DoS/DDoS posture" section now `defaultOpen={false}` at the bottom; its 5 metrics rebuilt as a compact `EuiStat` summary panel; charts/alerts/range-controls preserved.

### Phase 5 — Area 1: Alerts & Triage (`src/features/alerts/`)
Behavior/routes/URL-state/realtime/filters/bulk-actions/drawers all preserved; only the rendering moved to EUI. Public prop APIs of the area components were kept identical (no orchestrator/hook changes).
- `AlertsTable` → reimplemented on the shared **EUI `Table`** adapter (`EuiBasicTable`): columns (Alert/Network/Description/Actions), **checkbox selection** (select-all + per-row, now with EUI indeterminate state), row-click→drawer, selected-row highlight, `density`→`compressed`, sticky header. Dropped the raw `<table>` + raw `accent-primary` checkboxes. Sits inside the queue `Panel` via the blessed border-neutralizer `className="!shadow-none !border-0 !bg-transparent !rounded-none"`; the panel still owns scroll + sticky pagination footer + the infinite-scroll IntersectionObserver.
- `AlertsRulesList` → rule cards are now clickable **`EuiPanel`** (`color="primary"` for the selected row) instead of raw `<button>`; inner SeverityPill/StatusPill/Edit unchanged.
- `AlertRuleDrawer` → raw `<input type=checkbox>` toggles (Enabled, Schedule-enabled, Effective-Show) → **`ToggleSwitch`** (EuiSwitch); the day picker → **`EuiButtonGroup type="multi"` compressed**; save/validation error `<div>`s → **`InlineAlert`** (EuiCallOut); governance-history raw `<table>` → shared **`Table`**; effective-rule `<pre>` → **`JsonBlock`** (EuiCodeBlock, copyable). Form fields were already migrated adapters. Kept the tiny inline "all/none" text buttons + `FieldLabel` helper (micro-affordances, no clean EUI map).
- Zero raw `<table>` / `ui-input` / `ui-select` / `type=checkbox` remain anywhere under `src/features/alerts/`.

### Shared `DataView` primitives → EUI (`src/shared/components/DataView.tsx`)
Cross-cutting (used by ~21 files). Internals reimplemented on EUI; **every public prop API kept identical** so all consumers work unchanged.
- `DataStatsStrip` → grid of `EuiPanel`+**`EuiStat`** (`titleSize="s"`, `titleColor` from `tone`), matching the Overview KPI strip. NOTE: value now renders **above** the label (EuiStat default / Kibana convention) — previously label was on top. This flips on ~12 pages; intended.
- `DebouncedSearchInput` → **`EuiFieldSearch`** (`compressed`, `isClearable`); debounce draft/commit logic preserved.
- `DataLookbackSelect` → **`EuiSelect`** (`compressed`).
- `DataQueryStateBanner` → **`EuiCallOut`** (`size="s"`) for warning/danger/success; **neutral** (the common case) → subtle `EuiPanel color="subdued"` to avoid making 18 pages noisy. `right` slot + `role=status`/`aria-live` preserved.
- `DataPaginationFooter` → page-size `<select>`→`EuiSelect`, Retry/Load-more `<button>`→shared `Button`. Outer `ui-toolbar-shell` layout shell kept.
- **Kept as-is (layout/composition shells, same rationale the doc used for `Toolbar`):** `DataViewToolbar`, `DataViewFilterBar`, `DataFilterGroup`, `DataTableSkeleton` (a skeleton; could→`EuiSkeleton*` later), `DataEmptyState` (already composes the migrated `EmptyState`).

### Cross-cutting — `DraftNumberInput` → `EuiFieldNumber`
Focused batch over the shared anti-jump number-input wrapper plus all **8 call sites across 6 files**. Public API kept intact: `value`, `onCommit`, `min`, `max`, `fallback`, `className`, and the existing `disabled`/`placeholder`/`title` props still work.
- `src/shared/components/DraftNumberInput.tsx` internals now render **`EuiFieldNumber`** (`compressed`, `controlOnly`) while preserving the draft string, digit filtering, blur/Enter commit, Escape revert, fallback, and min/max clamp semantics.
- Consumer styling reconciled in the same pass: removed `.ui-input` from `EventsFilters`, `InventoryScopePanel`, and `vulnerabilities/page.tsx`; removed bespoke border/background/focus styling from `vulnerabilities/scans.tsx` and `TopologyFilterRail`; made the `AgentEventsWorkbench` full-width clean classes explicit.
- Legacy removed: no raw `ui-input` call sites remain in feature/shared components. Remaining `ui-select` hits are isolated to UEBA views and are unrelated to this number-input batch.
- Verification after the batch: `npm run build` exit 0; `npm run lint` 0 errors / 12 warnings; `npx vitest run` at baseline (16 failed files, 3 failed assertions, 81 passed); eager entry `dist/assets/index-*.js` **114.62 KB gzip**. `DraftNumberInput` now produces a lazy EUI field chunk (~24.5 KB raw / 6.0 KB gzip), not eager.

### Cross-cutting — `ResponseActionDrawer` (Response & Automation) → EUI
The Response-action operator console (`agents/components/ResponseActionDrawer.tsx`) — the last deferred feature surface. Migrated **rendering only**; every wired behavior preserved (create/investigate modes, execution/result tabs, action-instance selection, live-status + result polling, cancel, copy/download/pin, history selection, expiry presets, payload draft, validation gating). No controller/hook/API change; no faked capability.
- **14 standalone button sites + the history list → shared `Button`** (the doc's "15 buttons"): the 3 expiry presets (+15m/+1h/Clear) → `variant="ghost"`; "Queue response action" submit → `variant="primary"`; the rest (Show/Hide advanced, Close ×2, Refresh status, Cancel action, Open result viewer, Copy JSON, Download result, Pin to workspace, Open/Hide details) → `variant="secondary"` (`size="sm"`). EUI now owns the disabled styling the old `cx` opacity/cursor classes did by hand; every disabled condition is unchanged.
- **History card-list → clickable `EuiPanel`** (`color={active ? "primary" : "plain"}`, `hasBorder`, `aria-pressed`) — the `AgentsTable`/`AlertsRulesList`/internal-agents idiom.
- **Block + section status `<div>`s → `InlineAlert`** (EuiCallOut): the top create error/success (danger/success) and the live/result/history data-fetch errors (danger) — 5 callouts.
- **Intentionally KEPT:** the 4 top `InvestigationActionButton`s (already on the kit); the 3 inline field-validation hints (expiration invalid/in-past, payload error) as field micro-copy (tightly bound to their input, sibling to the existing `text-muted-foreground` hints — same rationale as the Alerts "all/none" / FieldLabel affordances); `FieldLabel`; the summary/info display tiles; the two footer container `<div>`s (layout shells, `Toolbar` rationale). Removed the now-unused `cx` import.
- Verification: build exit 0; lint 0-err/12-warn; tests at baseline (16 failed files, 3 failed assertions, 81 passed); eager entry `dist/assets/index-*.js` **111.31 KB gzip** (under baseline — the drawer stays route-split, nothing leaked eager). Net −91 lines (57 ins / 148 del).

### Cross-cutting — default table density → EUI `compressed` (Kibana-dense rows)
Make the dense Elastic/Kibana table look the app default. The shared `Table` adapter's `compact` prop (which maps to `EuiBasicTable` `compressed`) now **defaults to `true`**, so every table that doesn't manage its own density renders compressed (~12px font + tight cell padding) instead of EUI "comfortable".
- Per-page density-toggle defaults flipped comfortable→compact: **Inventory**, **Vulnerabilities** findings + scans, **Audit** (added `defaultCompact: true` to its `useDataTablePreferences`), and the **Alerts queue** (its `constants.ts` `DEFAULTS.density` + the two parse fallbacks in `alertQuery.ts` / `useAlertsQueryState.ts`, which now default unset density to compact unless explicitly `"comfortable"`). **Agents** fleet and **Exposure** assets were already `defaultCompact: true`.
- **Events stream keeps `defaultCompact: false` on purpose** — its `compact` toggle also adds the details column (rule/user/pps/entropy), a separate UX, so flipping it would change default columns.
- Density toggles still work; persisted explicit prefs are respected (a saved "comfortable" is kept — so an existing localStorage value may need a one-time toggle/clear to pick up the new default). Storage keys intentionally NOT bumped (avoids wiping saved page-size/sort/filters).
- Verification: build 0, lint 0-err/12-warn, tests at baseline, eager entry 111.29 KB gz.

### Phase 5 — Area 2: Events & Hunt (`src/features/events/`)
The 4 lenses (stream/ssh/network/ddos) already consumed the now-EUI `DataView` + shared `Table`/`Panel`/form adapters; this pass migrated the views' own remaining raw bits. All behavior (realtime, filters, scope draft/apply, drawers, pagination, deep-links) preserved.
- `DdosEventsTable` → shared **`Table`** (`EuiBasicTable`): row-click + selected-row highlight + sticky header preserved; kept the `h-full overflow-y-auto` scroll wrapper (the table's scroll ancestor) and the border-neutralizer className so it sits flush inside its `Panel`.
- `EventExplorer` (type facets) and the stream **`TopList`** (top src/dst pivots) → **`EuiFacetGroup`/`EuiFacetButton`** (Kibana-native facet lists with quantity badges + `isSelected`). `EventExplorer` dropped its redundant nested card-shell + custom collapse/Chevron header — the parent `Panel` already provides the titled scroll container; `title` kept in its prop type for API compat (undestructured).
- Auto-refresh / "show samples" toggles → **`ToggleSwitch`** (EuiSwitch): the duplicated local `SmallToggle` in stream + ssh, and the network scope-panel auto-refresh checkbox. Dropped raw `accent-primary` `<input type=checkbox>`.
- `ProtocolIndicatorDrawer` sample-table action buttons ("Full view", "Pin") → shared **`Button`** (removed the local `btnCls`/`cx`).
- `EventDetailsPanel` "Extra raw" `ui-card-shell` → **`Panel`**.
- **Intentionally KEPT (documented):** `EventsLinkButton` (a react-router `<Link>` styled `ui-btn` — EUI buttons can't do client-side routing cleanly; same rationale as `DetectionWorkflowRail`); one tiny "Hide/Show" text `<button>` in the network health-hints panel + `topKinds` display rows in `DdosDeepDive` (micro-affordances / non-interactive display, like the Alerts "all/none" links); `FieldLabel` helpers.
- The formerly deferred `DraftNumberInput` in `EventsFilters` is now complete in the cross-cutting `DraftNumberInput` batch.

### Phase 5 — Area 3: Entities / Inventory (`src/features/agents/`, `src/features/inventory/`)
This area was already largely on EUI (Inventory's panels use the shared `Table`/`Panel`; drawers use the migrated investigation kit). This pass cleared the residual raw bits. All behavior preserved.
- `InventoryDrawerHistoryTab` raw `<table>` → shared **`Table`** (precompute the per-row `changed` flag since it depends on the next row; `focusedSnapshotId`→`selectedRowKey`; Focus/Pin actions kept as shared `Button`s).
- `InventoryDrawerSnapshotTab` domain-evidence `<pre>` blocks (processes/network/services/identity) → **`JsonBlock`** (`showControls={false}`).
- Inline **agent-id link buttons** that open the agent drawer → **`EuiLink`** (Kibana-native inline link; removed the custom `text-primary underline` + focus-ring classes, and the now-unused `cx`). 5 sites: `InventoryWarningsPanel` ×2, `InventoryFleetHealthTable`, `InventoryChangesPanel` ×2.
- `AgentsTable` (a *card list*, not a table) → clickable **`EuiPanel`** cards (`color="primary"` when selected, `aria-pressed` preserved) — same pattern as `AlertsRulesList`.
- `AgentEventsWorkbench` "Event pivots" type list → **`EuiFacetGroup`/`EuiFacetButton`** (same as the Events `EventExplorer`).
- **Intentionally KEPT/DEFERRED (documented):**
  - `InventorySection` — collapsible-section layout primitive (custom uppercase eyebrow + hairline divider + localStorage open-state). EuiAccordion would restyle *every* inventory section; kept as a layout primitive (same rationale as `Toolbar`). Its `<button>` is a disclosure toggle, not a control.
  - `InventoryBarGaugeList` — clickable bar-gauge **viz** row (custom progress bar + disabled-when-not-clickable); no clean EUI primitive; kept.
  - `AgentConfigPanel` "Format" — one tiny uppercase text button (micro-affordance, like Alerts "all/none").
  - `ResponseActionDrawer` (`agents/components/`) — **DONE** as its own cross-cutting batch (Response & Automation); see the cross-cutting DONE section above. Was deferred out of Inventory because the workflow is sensitive and the buttons are varied; migrated rendering-only with all behavior preserved.

### Phase 5 — Area 4: Network / Topology (`src/features/network_topology/`)
This area was **already largely on EUI** (filter rail uses shared `Button`/`CheckboxField`/`SelectInput`/`TextInput`/`ToggleSwitch`; panels use shared `Panel`/`Badge`/`SeverityPill`; the detail drawer uses the migrated investigation kit; page uses `DataQueryStateBanner`). No raw `<table>`/`ui-input`/`ui-select`/`<pre>`/`type=checkbox` existed anywhere. This pass cleared the residual standard-UI raw bits and removed dead code; **all behavior preserved** (realtime invalidation, filter draft/apply, focus/search/match-nav, detail drawer, active-discovery action, recalculate).
- **Deleted dead `TopologyTopBar.tsx`** (295 lines, 0 usages — superseded by the floating `TopologyCanvasControls` overlay). Removed the now-empty `components/chrome/` dir.
- `page.tsx` — the admin **Recalculate** raw `<button>` → shared **`Button`** (ghost, sm). Kept the "Operational Details" footer disclosure `<button>` (section-collapse layout primitive, same rationale as `InventorySection`/`FilterSection`).
- `NetworkTopologyDiscoveryPanel` — the raw `lastError` danger `<div>` and `warnings` warning `<div>` → **`InlineAlert`** (EuiCallOut, `tone="danger"`/`"warning"`), same pattern as the Alerts validation errors. Kept the `<label>`+eyebrow field affordance (FieldLabel-style) and the display info tiles.
- `NetworkTopologyServicesPanel` — the **By Host / By Category** 2-button segmented toggle → **`EuiButtonGroup`** (`type="single"` compressed); the raw `<input type="search">` immediate filter → **`EuiFieldSearch`** (`compressed`, `isClearable`, immediate onChange — NO debounce, preserving the exact behavior). **Kept** `ServiceRow`/`FlowBar`/`HostGroupCard`/`CategoryGroupCard` (service-inventory **domain viz** with flow bars + per-card "Show more/less" disclosure, same rationale as `InventoryBarGaugeList`) and the compact inline `SummaryStrip` (a thin one-line stat strip — kept compact rather than ballooning into `EuiStat` cards).
- `TopologyFilterRail` — the **Location / Connection** segmented view-mode toggle → **`EuiButtonGroup`** (`type="single"` compressed `isFullWidth`). Form fields were already shared adapters. Kept `FilterSection` (disclosure layout primitive). The Confidence-min `DraftNumberInput` is now complete in the cross-cutting `DraftNumberInput` batch.
- `NetworkTopologyInsightsPanel` / `NetworkTopologyEvidencePanel` — already cleanly composed on shared `Panel`/`Badge`/`SeverityPill`/`TopologyIpScopeBadge`; display cards are domain display (no change). The Evidence "Open source" `<a href>` is an external pivot link (kept, micro-affordance).
- **Intentionally KEPT — `@xyflow` graph-canvas chrome** (tightly coupled to ReactFlow via `useReactFlow`/`useStore`, positioned as xyflow `Panel`s, deliberately glassmorphic over the WebGL canvas; EUI form controls would look out of place floating over the graph — the canonical "keep sigma/graphology/@xyflow"):
  - `TopologyCanvasControls` (zoom/fit/minimap/fullscreen/refresh/reset `IconButton`s + the canvas search box + the "Show" view-mode toggle that appears when the rail is closed/fullscreen),
  - `TopologyContextMenu` (cursor-positioned right-click menu), `TopologyLegend` (interactive edge-type legend filter), `TopologyStatusStrip` (floating status pills + the "N isolated" reveal button), `TopologyTooltip`, and the inline `TopologyCanvas` multi-select toolbar + halo-escape toast.

### Phase 5 — Area 5: Exposure & Vulnerabilities (`src/features/exposure/`, `src/features/vulnerabilities/`)
Both areas were already substantially on the shared adapters; this pass cleared the residual raw bits — most notably converting the **three raw `<table>` surfaces in Vulnerabilities** to the shared `Table`. All behavior preserved (cursor pagination, realtime scan-lifecycle, filter draft/apply, density, drawers, manual scan, recalculate).

**Exposure** — already on `Card`/`PageHeader`/`Button`/`DataView`, with the asset & finding lists on the shared `Table` and the drawers on the shared `Drawer`.
- `ExposureFiltersBar` — the 3 "Signals" raw `<input type=checkbox accent-primary>` → **`CheckboxField`**.
- `ExposureGraphCanvas` — the "Filter matches" raw checkbox → **`CheckboxField`**. KEPT the custom `<canvas>` 2D attack-graph renderer + its search-result button list (domain viz; the canvas control bar already used shared `TextInput`/`Button`).
- `page.tsx` — the `ui-tab-shell`/`ui-tab-item` raw tab buttons → shared **`Tabs`** (EuiTabs).

**Vulnerabilities** — already on `Card`/`PageHeader`/`Button`/`Badge`/`SelectInput`/`Drawer`/investigation kit.
- **All three raw `<table>` → shared `Table`** (EuiBasicTable): the findings table (`page.tsx`), the recent-scans table (`ActiveScanPanel`), and the scan-inventory table (`scans.tsx`). Each keeps per-column `render`, row-click→drawer, selected-row highlight (`selectedRowKey`), `compact` density, and the live-scan row tint via `rowClassName`. View buttons were already shared `Button`.
- `scans.tsx` filters — raw `<input>`×2 → **`TextInput`**, raw `<select>` → **`SelectInput`**; the local `Toggle` density control → **`ToggleSwitch`** (removed the bespoke component); Refresh/Reset/Apply/Load-more buttons → shared **`Button`**.
- `page.tsx` — the **Priority Queue** and **Most exposed assets** clickable `<button>` card-lists → clickable **`EuiPanel`** (`hasBorder`, `onClick`; same pattern as `AgentsTable`/`AlertsRulesList`). The density toggle was already a shared `Button`.
- **Intentionally KEPT/DEFERRED:** the quick-pivot **asset/package chips** (tiny inline filter chips with `×count` — micro-affordances, like the Alerts "all/none" links / DDoS pivots); the Exposure graph search-result buttons (domain viz). The vulnerability `DraftNumberInput` page-size/min inputs are now complete in the cross-cutting `DraftNumberInput` batch.

### Phase 5 — Area 6: Investigations & Cases (`src/features/investigations/`, `src/features/attack_chain/`)
Both areas were already on the shared adapters (`PageHeader`/`Panel`/`Button`/`DataView`/`StatusPill`/`SeverityPill`/`Badge`/`Drawer` + the investigation kit). The only residual raw primitive in each was a single `<table>` in `page.tsx`; both converted to the shared **`Table`** (EuiBasicTable). All behavior preserved (filters, realtime, cursor pagination via `DataPaginationFooter`, drawers, deep-links).
- `investigations/page.tsx` — the **Workspaces** table → `Table`: columns (Workspace / Assignment / Activity / Action), row-click→workspace drawer, selected-row highlight (`selectedRowKey`). The per-row **Open** button was already a shared `Button`.
- `attack_chain/page.tsx` — the **Cases** table → `Table`: columns (Risk / Stage-Agent / Suspect-Seen / Actions), row-click→case drawer, selected-row highlight, `compact` density. The per-row **View** + **Investigate** buttons were already shared `Button`s.
- Removed the now-unused `cx` import from both. Row-level Enter/Space activation now lives on the per-row action button (the shared `Table` is click-only — consistent with every other migrated table).
- Nothing deferred; `PinToWorkspaceDrawer`/`AttackChainDrawer` already use the shared `Drawer` (EuiFlyout) with native nested-flyout stacking.

### Phase 5 — Area 7: Governance & Platform (`src/features/audit/`, `src/features/internal/`)
Neither area had a raw `<table>` left (`AuditEventsTable` already used the shared `Table`); this pass cleared the residual raw form controls, buttons, JSON dumps, and one clickable card-list. All behavior preserved (audit query/filters/pagination/sort, realtime internal refresh, agent inspection).
**Audit:**
- `AuditFiltersBar` — 9 raw `<input className="ui-input">` → **`TextInput`** (incl. the two `datetime-local`s), 2 raw `<select className="ui-select">` → **`SelectInput`**, Apply (submit) / Clear → shared **`Button`**. Kept the `<form>` `ui-card-shell` wrapper (submit semantics + layout shell).
- `AuditEventsTable` — the Comfortable/Compact density buttons → **`ToggleSwitch`**; Previous/Next + the per-row **Open** → shared **`Button`** (the table body was already the shared `Table`).
- `views/timeline.tsx` — density buttons → **`ToggleSwitch`**, Previous/Next → **`Button`**. KEPT the dense clickable timeline event rows (a domain list with a `group`-hover dot affordance; lightweight `<button>` rows, like `EventsLinkButton`).
- `views/changes.tsx` — the Governance-Scope filter chips (All / Rules / Allowlists / Users / Settings) → **`EuiButtonGroup`** (`type="single"`; the empty "all" key mapped to a `__all__` sentinel).
**Internal:**
- `InternalRefreshToolbar` — Refresh → shared **`Button`** (kept the `ui-toolbar-shell`).
- `views/agents.tsx` — the agent-picker cards → clickable **`EuiPanel`** (`color="primary"` when active, `aria-pressed`; the `AgentsTable` idiom); the 3 raw `<pre>` JSON dumps (Heartbeat/Modules, Metadata, Config) → **`JsonBlock`** (`maxHeight="320px"`, now copyable + wrap toggle).

### Phase 5 — Area 8: Settings (`src/features/settings/`)
Already fully on the shared adapters (`PageHeader`/`Card`/`Button`/`TextInput`/`InlineAlert`/`Loading`/`Table`/`Badge`, including the login-history `Table` and the password-change form). This pass:
- `page.tsx` — the `loginError` raw `<div className="text-danger">` → **`InlineAlert`** (`tone="danger"`), matching the `runtimeError` callout already used in the same view. Kept the `PasswordRule` dot-list (domain display) and the `<label>`+eyebrow field affordances.
- **Deleted the empty, unused `components/ApiEndpointForm.tsx`** (0 bytes, 0 imports) + removed the now-empty `components/` dir.

### Deleted dead code (0 usages, confirmed by grep)
`src/shared/components/IconButton.tsx`, `QueryState.tsx`, `FormField.tsx`, `ThemeToggle.tsx`; `src/features/overview/components/StatLinkTile.tsx`; the whole `src/features/_eui_lab/` + its `/eui-lab` route in `src/app/routes.tsx`; `src/features/network_topology/components/chrome/TopologyTopBar.tsx` (+ the emptied `chrome/` dir); `src/features/settings/components/ApiEndpointForm.tsx` (empty 0-byte file + emptied `components/` dir).

### Intentionally KEPT legacy (with reasons)
- `IpAddressPill` — domain pill already composing the migrated `Badge` (EuiBadge); no EUI primitive maps.
- `Toolbar` — thin `ui-toolbar-shell` layout shell; `EuiFlexGroup` would be lateral.
- `DetectionWorkflowRail` — domain `NavLink` rail; no clean EUI equivalent.

---

## TODO — Phase 5: feature areas (incremental)

Migrate each feature area's orchestrator + components/hooks/lib/drawer to reuse the shared adapters; remove legacy after validating; verify (build/lint/tests vs baseline) and pause for human visual review after EACH area.

**Order:**
1. ~~**Alerts & Triage** (`src/features/alerts/`)~~ — **DONE 2026-05-30** (see DONE section above). Also migrated the shared `DataView` primitives.
2. ~~**Events & Hunt** (`src/features/events/`)~~ — **DONE 2026-05-30** (see DONE section above). The deferred `DraftNumberInput` is now complete in the cross-cutting batch.
3. ~~**Entities / Inventory** (`src/features/agents/`, `src/features/inventory/`)~~ — **DONE 2026-05-30** (see DONE section above). The deferred `ResponseActionDrawer` (Response & Automation) and `DraftNumberInput` are now both complete in their cross-cutting batches.
4. ~~**Network / Topology** (`src/features/network_topology/`)~~ — **DONE 2026-05-30** (see DONE section above). Was already largely on adapters; cleared residual standard-UI raw bits + deleted dead `TopologyTopBar`. `@xyflow` canvas chrome intentionally kept. The deferred `TopologyFilterRail` `DraftNumberInput` is now complete. Tests still fail at collection (no jsdom) — that's baseline, unchanged.
5. ~~**Exposure & Vulnerabilities** (`src/features/exposure/`, `src/features/vulnerabilities/`)~~ — **DONE 2026-05-30** (see DONE section above). Exposure: checkboxes→`CheckboxField`, tabs→`Tabs`. Vulnerabilities: 3 raw `<table>`→shared `Table`, scans filters/buttons→adapters, card-lists→`EuiPanel`. The deferred `DraftNumberInput` page-size/min inputs are now complete.
6. ~~**Investigations & Cases** (`src/features/investigations/`, `src/features/attack_chain/`)~~ — **DONE 2026-05-30** (see DONE section above). One raw `<table>` per page → shared `Table`; everything else already on adapters. Nothing deferred.
7. ~~**Governance & Platform** (`src/features/audit/`, `src/features/internal/`)~~ — **DONE 2026-05-30** (see DONE section above). Audit filter inputs/selects/buttons → adapters, density → `ToggleSwitch`, governance chips → `EuiButtonGroup`; Internal agent cards → `EuiPanel` + `<pre>` → `JsonBlock`. Nothing deferred.
8. ~~**Settings** (`src/features/settings/`)~~ — **DONE 2026-05-30** (last feature area). Was already fully migrated; only a `loginError`→`InlineAlert` consistency fix + deleted the empty dead `ApiEndpointForm.tsx`.

**✅ All 8 Phase 5 feature areas are complete.** Remaining work is cross-cutting only — see the "Remaining (not feature areas)" list in the TL;DR.
- Response & Automation: only when a real backing capability exists — don't fake it.

**Per-area definition of done:** new impl fully wired; existing behavior preserved; no duplicate old/new layers; no unused imports/exports/files; no comments; build+lint+tests at baseline; area cleaner than before. Report: what migrated, legacy removed, reused, intentionally-kept + why, risks/debt, next.

### Also in Phase 5 / cleanup
- `DraftNumberInput` → `EuiFieldNumber` is **DONE** across Inventory scope, Vulnerabilities, Agents workbench, Events filters, Topology filter rail, and scans.
- Watch for remaining raw `<select className="ui-select">` in UEBA views. No raw `ui-input` call sites remain in feature/shared components.
- `DataView` components: **migrated** the ones with clean EUI maps (`DataStatsStrip`, `DataQueryStateBanner`, `DebouncedSearchInput`, `DataLookbackSelect`, `DataPaginationFooter`); **kept** the layout/composition shells (`DataViewToolbar`, `DataViewFilterBar`, `DataFilterGroup`, `DataTableSkeleton`, `DataEmptyState`). If a later pass wants full EUI: `DataViewToolbar`→`EuiPanel`, `DataTableSkeleton`→`EuiSkeletonText`/`EuiSkeletonTitle`.
- Re-measure bundle; consider EUI icon tree-shaking (`appendIconComponentCache`) once icon usage is known. Reconsider the `code_block` (EuiCodeBlock highlighter) lazy chunk.
- Final: verify dark AND light both look like a serious SOC console; no horizontal scroll; all routes/drawers/filters/tables behave as before.

### Open visual-verification items (human, in browser)
- Nested drawers (Pin-to-workspace stacking over a parent: Esc/backdrop closes only the top one).
- Table behaviors: wide `scrollX` tables (Events network/SSH) scroll not cram; sticky header on long tables; sortable columns; row click + selected-row highlight.
- Form-field density (`compressed`) across Alerts rule editor, Investigations, Agents config, Topology filter rail.
- The full redesigned `/overview` (KPI strip, Pipeline health, collapsed DDoS) in dark + light.
- **Alerts area (this batch):** `/alerts/queue` — EUI table selection (select-all indeterminate, per-row checkbox doesn't open the drawer, row-click does), sticky header while scrolling the queue, density toggle, pagination footer + infinite-scroll. `/alerts/rules` — selectable EuiPanel cards; rule drawer: EuiSwitch toggles, the `EuiButtonGroup` day picker, InlineAlert validation errors, the governance-history EUI table, the JsonBlock effective rule.
- **DataView SWEEP (cross-cutting — check several data pages, dark + light):** the new `EuiStat` stat strips (value-above-label now), the `EuiFieldSearch` search boxes (clearable), the neutral `EuiPanel` status banner vs the warning/danger `EuiCallOut`, and the `EuiSelect`/`Button` pagination footer. Pages: Overview, Events (all lenses), Exposure, UEBA, Investigations, Audit, Correlations, Internal/Agents, Network topology.
- **DraftNumberInput cross-cutting (this batch):** dark + light check all eight EUI number fields: `/events` filter Limit; `/inventory` Scope Window; `/agents` Recent alerts/events Window + Limit; `/vulnerabilities` Posture window + filter Page; `/vulnerabilities/scans` Page size; `/network` filter rail Confidence Min. Confirm typing does not jump while focused, blur/Enter commits and clamps, Escape reverts, disabled state still reads correctly, compact widths align with adjacent EUI fields, and no page gains horizontal scroll.
- **`ResponseActionDrawer` (this batch):** `/agents` (admin) → open a Response action. Confirm the shared `Button`s (ghost +15m/+1h/Clear expiry presets; primary "Queue response action"; secondary Refresh status / Cancel action / Open result viewer / Copy JSON / Download result / Pin to workspace / Show-advanced / Close) all fire and show disabled states correctly; the create error/success and the live/result/history fetch errors render as `InlineAlert` callouts; the History list is clickable `EuiPanel` cards (active = primary tint, `aria-pressed`, select drives the execution/result panels); the inline expiration/payload validation hints still read as field micro-copy; and the `PinToWorkspaceDrawer` still stacks over the response drawer (nested flyout). Dark + light.
- **Events area (this batch):** `/events` stream — the `EuiFacetButton` Explorer + Top src/dst facet lists (selected state, quantity badges, click-to-search), the `EuiSwitch` toggles. `/events/ssh` + `/events/network` — auto-refresh `EuiSwitch`; network Protocol-Intel drawer sample table "Full view"/"Pin" `EuiButton`s; the `EuiFacet`/scope panels. `/events` (DDoS lens) — the `DdosEventsTable` (now EuiBasicTable) scrolls within its 420px panel with a sticky header + row select. Confirm `EventsLinkButton` pivots still navigate client-side.
- **Entities/Inventory area (this batch):** `/agents` — the `EuiPanel` agent card list (selected = primary tint, keyboard/aria-pressed), the `EuiFacetButton` "Event pivots" in the events workbench. `/inventory` — the agent-id `EuiLink`s in the fleet/changes/warnings tables open the drawer; inventory drawer History tab (now EuiBasicTable, Focus/Pin + selected row) and Snapshot tab (domain-evidence `JsonBlock`s). Confirm `InventorySection` collapse/expand still persists per-section.
- **Network/Topology area (this batch):** `/network` — the filter rail **Location/Connection** `EuiButtonGroup` (applies immediately, full-width) and the Services panel **By Host/By Category** `EuiButtonGroup` + `EuiFieldSearch` immediate filter (clearable); the Discovery panel `InlineAlert` error/warning callouts; the admin **Recalculate** shared `Button` in the footer. CRITICAL — confirm the untouched `@xyflow` canvas chrome still works: graph renders/drags/fits, node/edge click → detail drawer, zoom/minimap/fullscreen/refresh/reset-layout controls, canvas search + match-nav (‹/›), right-click `TopologyContextMenu` (View details / Focus group / Copy IP), interactive `TopologyLegend` edge filter, `TopologyStatusStrip` pills + "N isolated" reveal, tooltips, multi-select toolbar, halo-escape toast. Dark + light.
- **Exposure & Vulnerabilities area (this batch):** `/exposure` — the `CheckboxField` Signals filters + graph "Filter matches" checkbox; the `Tabs` (Asset Posture / Attack Paths / Graph / Findings); confirm the custom `<canvas>` attack graph still renders/pans/zooms and node-click opens the asset drawer. `/vulnerabilities` — the findings **EuiBasicTable** (row-click→drawer, selected-row highlight, density toggle, Load more), the **Priority Queue** / **Most exposed assets** `EuiPanel` cards (click → drawer or filter), the asset/package quick-pivot chips. `/vulnerabilities/scans` — the scan-inventory **EuiBasicTable** (live-scan row tint, View), the `TextInput`/`SelectInput` filters, the `ToggleSwitch` density, and the now-EUI page-size number field. Dark + light. **Watch:** multi-line table rows now use EUI default vertical alignment (was `align-top` on the row) — confirm rows still read cleanly.
- **Investigations & Cases area (this batch):** `/investigations` — the Workspaces **EuiBasicTable** (row-click → workspace drawer, selected-row highlight, the per-row Open button) + the nested `PinToWorkspaceDrawer` stacking over a workspace drawer. The attack-chain cases page — the Cases **EuiBasicTable** (row-click → `AttackChainDrawer`, selected-row highlight, density, the View + Investigate buttons; Investigate pivots into an investigations workspace). Same `align-top`→EUI-default vertical-alignment watch as above for the multi-line rows. Dark + light.
- **Governance & Platform area (this batch):** `/audit` — the `TextInput`/`SelectInput` filter bar (incl. the datetime-local From/To), the `ToggleSwitch` density + Prev/Next `Button`s on both the events table and timeline, the `EuiButtonGroup` Governance-Scope filter on the Changes view, and the (kept) clickable timeline event rows. `/internal` agents view — the agent-picker `EuiPanel` cards (active = primary tint, `aria-pressed`), the `InternalRefreshToolbar` `Button`, and the 3 `JsonBlock` JSON dumps (Heartbeat/Modules, Metadata, Config — now with copy + wrap). Dark + light.

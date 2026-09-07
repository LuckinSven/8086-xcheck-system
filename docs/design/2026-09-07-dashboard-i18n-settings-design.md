# XCheck Dashboard, Visual Settings, and Internationalization Design

## Goal

Add a real home dashboard with three selectable operating modes, improve the small typography visible throughout the current interface, centralize all appearance choices in System Settings, and make English the default language while retaining full Simplified Chinese support.

The result must remain suitable for an internal LAN deployment and for future publication in a Git repository. It must not duplicate task or intelligence data, weaken the existing 200,000-row safeguards, or expose credentials through dashboard or settings responses.

## Confirmed product decisions

- The root route becomes the home dashboard. New Query moves to `/new`.
- The dashboard supports three modes: Overview, Threat Landscape, and Operations.
- Only System Settings changes the active dashboard mode. The home page has no mode picker.
- Theme selection also moves from the top bar into System Settings.
- The home page uses a colored ambient background, translucent floating panels, and restrained motion effects.
- Motion intensity is configurable as Off, Subtle, Medium, or Strong. Medium is the default.
- English and Simplified Chinese are supported. English is the default.
- Language is a system-wide setting shared by LAN users, consistent with the current no-authentication deployment.
- User-facing UI text, statuses, validation messages, integration-test messages, and export headings are localized.
- External intelligence values, filenames, and user-provided data remain unchanged to preserve evidence fidelity.
- The English `README.md` is the primary repository entry point. `README.zh-CN.md` provides the Chinese version.

## Architecture choice

Use frontend message catalogs for presentation and stable backend error/status codes for transport and persistence. This keeps API contracts language-neutral and avoids maintaining translated prose throughout service code.

Rejected alternatives:

1. Returning fully translated sentences from the backend would bind API behavior to the current display language and make stored errors difficult to reinterpret after a language change.
2. Translating only Vue templates would leave exports, background-task errors, and integration probes inconsistent.

The selected design adds structured error identifiers at backend boundaries, translates them in the frontend, and lets export services select localized column names from the current system language.

## Navigation and application bootstrap

Routes become:

- `/`: dashboard
- `/new`: new query
- `/history`: task history
- `/threatbook-history`: ThreatBook history
- `/tasks/:id`: task details
- `/tasks/:id/threatbook`: ThreatBook workspace
- `/tasks/:id/ips/:ipId`: IP diagnostics
- `/settings`: system settings

The main navigation order is Home, New Query, Query History, ThreatBook History, and System Settings. The top bar retains product context and service health but no longer contains the theme picker.

At application startup, English renders as the safe default while `/api/settings` loads. The returned global language, theme, dashboard mode, and motion intensity are then applied to the document root. A failed settings request keeps the English defaults and shows a non-blocking localized warning rather than preventing navigation.

## System settings

Extend the existing settings payload with four validated enum fields:

- `ui_language`: `en-US` or `zh-CN`; default `en-US`
- `theme_id`: one of the six existing theme identifiers; default `threatbook-red`
- `homepage_mode`: `overview`, `threat-landscape`, or `operations`; default `overview`
- `motion_intensity`: `off`, `subtle`, `medium`, or `strong`; default `medium`

System Settings gains an **Appearance & Language** panel above integration configuration. Language choices use their native names, `English` and `简体中文`, so users can recover from an accidental language change. The homepage choices include short localized descriptions. Theme swatches remain visible inside Settings. Motion choices explain their performance and accessibility impact.

Saving settings is atomic at the request level. The response contains the effective safe settings and never returns the ThreatBook API key. The current browser applies visual settings immediately after a successful save; other open browsers use the new values on their next reload.

Existing databases need no destructive migration. Missing keys receive the defaults above and are persisted through the existing `settings` table. Unknown or obsolete values fall back to defaults and are reported through a safe warning.

## Typography and visual system

Replace isolated small font declarations with shared type tokens:

- base body text: 15px
- navigation, controls, buttons, and table body: 14px
- table headers, badges, timestamps, and secondary labels: at least 12px
- page descriptions: 14px
- comfortable line height between 1.45 and 1.6 depending on content

The ThreatBook history table specifically increases its body, source, status, tags, regions, timestamps, and pagination text. Its existing server pagination and horizontal overflow behavior remain unchanged.

Each theme gains semantic ambient and glass tokens rather than dashboard components hard-coding red or blue values. The default ThreatBook theme uses low-saturation red and blue light fields, translucent surfaces, soft borders, background blur, and modest shadows. Other themes derive the same effects from their own palette.

Dashboard motion consists of CSS-only ambient light drift, occasional panel highlight sweep, subtle chart breathing, map-point pulses, and hover elevation. Motion must not move essential controls or data. The four intensity values adjust duration, distance, opacity, and the number of active effects through document-level data attributes and CSS custom properties. `prefers-reduced-motion: reduce` always disables non-essential animation regardless of the stored setting.

Other application pages use the improved background and light glass treatment but do not receive the dashboard's richer continuous effects.

## Dashboard modes

All modes reuse existing task, step, usage, batch, and intelligence tables. No dashboard snapshot table or duplicated intelligence history is introduced.

### Overview

Designed as the normal daily landing page:

- queried IPs today
- malicious IPs today and malicious rate
- running tasks and aggregate completion
- nodes requiring investigation
- seven-day query and malicious-hit trend
- most recent high-risk discoveries with links to diagnostics
- shortcuts to New Query and the relevant history page when data is empty

### Threat Landscape

Designed for visual situational awareness:

- malicious sources in the last 24 hours
- country-level map aggregation
- top countries and regions
- top threat labels
- severity distribution
- malicious discovery trend

The map uses a bundled, versioned geographic asset and aggregated country counts. It does not send IP addresses to an external map provider. ThreatBook-supplied labels and geographic names are displayed as evidence values and are not machine-translated.

### Operations

Designed for task and integration health:

- running, queued, waiting, paused, partial, and failed task counts
- queue backlog and current aggregate progress
- failed nodes with direct investigation links
- current daily ThreatBook usage and remaining local budget
- worker and database status
- whitelist and ThreatBook configuration state
- last explicit connection/authentication test status, time, and latency
- active tasks with progress and direct links

The dashboard never probes external services during refresh. Existing Settings test actions persist a safe summary of the last result. No API key, response body, or sensitive request value enters dashboard data.

## Dashboard API and refresh behavior

Add `GET /api/dashboard?mode=<mode>`. The server validates `mode` against the same enum used by settings and returns a common envelope:

- `mode`
- `generated_at`
- `summary`
- mode-specific bounded sections
- per-section availability metadata

Only data for the requested mode is calculated and returned. Trends use date buckets, rankings return bounded Top N collections, and recent discoveries return a small fixed page. Aggregation is performed in SQL; the service must not load all ThreatBook results or task IPs into Python.

The frontend refreshes every 15 seconds. It pauses polling while the document is hidden, prevents overlapping requests, and ignores stale responses after route changes. A refresh failure preserves the last successful values and marks only the affected section stale.

Dashboard links reuse existing detail and diagnostics routes. Counts must have the same task-status semantics as history APIs rather than introducing a second interpretation of completed or failed work.

## Internationalization boundaries

Use `vue-i18n` with message catalogs under `frontend/src/locales/`:

- `en-US.ts`
- `zh-CN.ts`

Locale keys are semantic and organized by common navigation, settings, tasks, whitelist, ThreatBook, dashboard, errors, and exports. Vue templates contain no user-facing hard-coded Chinese or English prose other than proper product names and external evidence values.

Backend APIs return stable values for statuses and result categories. User-facing API failures use a structured body containing an error `code`, optional safe `params`, and an English `fallback`. The frontend translates known codes and uses the English fallback for forward compatibility.

New background-task failures store a structured error code and safe parameters alongside an English fallback. Existing historical `error_summary` values remain readable without destructive conversion. If no structured code exists, the legacy text is displayed as stored.

Exports read the current global language at request time and localize workbook sheet names, headings, status labels, whitelist conclusions, and generated explanatory text. Raw IPs, request IDs, filenames, ThreatBook labels, geographic values, and evidence fields remain exact.

Input parsing accepts both established and English column aliases independently of display language. At minimum, access logs recognize `访问源 IP`, `Source IP`, and `source_ip`; attack logs retain `srcAddress` and recognize `Source Address` and `source_address`. This preserves old workflows while making an English installation usable immediately.

## Repository publication

- Rewrite `README.md` in English and link prominently to `README.zh-CN.md`.
- Add the Chinese translation as `README.zh-CN.md`, with reciprocal language links.
- Keep commands, environment variable names, route names, and configuration keys in English in both documents.
- Do not commit local design-preview or scratch artifacts.
- Existing internal historical design notes do not require translation, but new public-facing documentation defaults to English.

## Error handling and degraded states

- A failed dashboard section shows a localized inline error and retry action while other sections remain usable.
- Empty states distinguish no data from a failed query.
- Invalid setting enums return a structured validation error and do not partially save settings.
- Failure to apply a visual preference falls back to English, the default ThreatBook red theme, Overview, and reduced motion without affecting task processing.
- Last integration-test summaries store only success/failure, timestamp, latency, stable error code, and safe message parameters.
- Map asset failure falls back to ranked countries instead of leaving a blank panel.
- Missing locale keys produce an English fallback in production and fail the locale-consistency test in development.

## Performance and security

- Dashboard aggregates use indexed task dates/statuses and indexed ThreatBook result attributes.
- Ranking and recent-item sections have fixed limits, and all trends use database-side grouping.
- Polling stops when the page is hidden or unmounted.
- No dashboard response includes raw ThreatBook JSON, API keys, uploaded file contents, or unrestricted diagnostic bodies.
- Translucency and blur degrade to opaque semantic surfaces when unsupported.
- Motion uses transforms and opacity only where practical to avoid expensive layout animation.

## Testing and acceptance

Backend tests cover:

- defaults and persistence for the four new settings
- enum validation and atomic setting updates
- mode-specific dashboard aggregates and empty states
- bounded SQL result shapes for large fixtures
- status-count and daily-budget semantics
- persistence and sanitization of integration-test summaries
- structured errors and English fallbacks
- localized English and Chinese exports
- bilingual input-column aliases

Frontend tests cover:

- English-first application bootstrap and Simplified Chinese switching
- navigation and every page using message keys
- System Settings controlling language, theme, homepage mode, and motion
- removal of the top-bar theme selector
- three dashboard layouts and their mode-specific content
- polling pause, stale-response protection, partial errors, and empty states
- type scale minimums, theme contrast, glass fallbacks, and reduced-motion behavior
- missing-key equality between English and Chinese catalogs

Final verification requires Ruff, Pytest, Vitest, Vue type checking, the production build, Docker health, loopback health, and LAN access on port 8086. Existing persisted data must survive the deployment unchanged.

## Acceptance outcome

On a fresh or upgraded installation, `http://<server>:8086/` opens an English Overview dashboard with the approved ambient glass and medium motion treatment. An administrator can change the language, theme, home mode, and motion strength only in System Settings. All existing task workflows remain available, the ThreatBook history text is more readable, English and Chinese exports are consistent, and no dashboard view attempts to load a full high-volume result set.

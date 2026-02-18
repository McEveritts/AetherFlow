# Dependency Audit & Update Plan

The following libraries are vendored in `dashboard/lib` and appear to be outdated.

## Frontend Libraries (Vendored)

| Library | Current Path | Recommended Action |
| :--- | :--- | :--- |
| jQuery | `lib/jquery` | Update to latest v3.x (check for breaking changes). |
| Bootstrap | `lib/bootstrap` | Currently appears to be v3. Upgrade to v5 is recommended for modern features, but requires significant refactoring of HTML classes. |
| Font Awesome | `lib/font-awesome` | Upgrade to v6 for more icons and better SVG support. |
| DataTables | `lib/datatables` | Update to latest version. |
| Flot | `lib/flot` | Legacy charting library. **Strongly Recommended**: Replace with Chart.js or ApexCharts for modern, responsive visualization. |
| jQuery UI | `lib/jquery-ui` | Largely obsolete. Replace specific widgets (e.g., sortable, draggable) with modern lightweight libraries or native HTML5 API. |
| Modernizr | `lib/modernizr` | Update to latest. |

## Backend Dependencies (Composer)

Current `composer.json` mainly handles dev tooling.
Consider introducing:
- `vlucas/phpdotenv`: For better configuration management via `.env` files.
- `monolog/monolog`: For structured logging (replacing `error_log` calls).
- `filp/whoops`: For better development error pages.

## Action Plan

1.  **Identify Versions**: Check header comments in each library file to determine current version.
2.  **Test Updates**: Create a test branch. Replace `jquery` first and test dashboard interactivity.
3.  **Migrate Charts**: Replace Flot with Chart.js for better responsiveness and aesthetics (aligns with P16 modernization).
4.  **Bootstrap Migration**: This is the largest task. Moving from BS3 to BS5 requires rewriting all grid classes and components. Evaluate if visual refresh (P2) can coincide with this.

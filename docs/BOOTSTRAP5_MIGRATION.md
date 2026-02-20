# AetherFlow UI Modernization Roadmap (Bootstrap 5)

This document outlines the phased migration strategy to modernize the AetherFlow Dashboard from Bootstrap 3.x to Bootstrap 5.x.

## Phase 1: CSS & Component Refactoring
Bootstrap 5 introduces major structural changes. We need to replace legacy BS3 components with their BS5 equivalents across all Dashboard `.php` templates and `dashboard/skins/aetherflow.css`.

### Key Component Replacements
1. **Panels to Cards:**
   - Find: `<div class="panel panel-default">` -> `<div class="card">`
   - Find: `<div class="panel-heading">` -> `<div class="card-header">`
   - Find: `<div class="panel-body">` -> `<div class="card-body">`
2. **Grid System (Layouts):**
   - BS5 drops the `-xs` infix. `col-xs-*` must be updated to `col-*`.
   - Update `pull-right` / `pull-left` to `float-end` / `float-start`.
3. **Typography & Utilities:**
   - Verify `text-center`, `text-right` (now `text-end`).
   - Remove obsolete custom `.btn` CSS in `aetherflow.css` and rely on BS5 utility classes.

### Iconography (Glyphicons)
- Bootstrap 3 included Glyphicons, which are completely removed in Bootstrap 4/5. 
- **Action:** Replace all `<i class="glyphicon glyphicon-*"></i>` elements with Bootstrap Icons (e.g., `<i class="bi bi-*"></i>`) or incorporate FontAwesome 6 as a core dependency in `package.json`.

## Phase 2: JavaScript Dependency Migration
Legacy jQuery plugins may not be fully compatible with BS5 or standard ES6 architecture.

### Lobipanel & jQuery Custom Logic
- Review `dashboard/js/lobipanel.js`. As part of previous security remediation, `eval()` was safely replaced with `JSON.parse()`.
- Evaluate replacing Lobipanel with vanilla JS drag-and-drop combined with BS5 Cards. This drastically reduces the dependency payload.
- Convert custom tooltips / popovers to use the native BS5 implementation (which utilizes Popper.js).

## Phase 3: Validation and Responsive Testing
1. **Mobile Menu:** Validate the mobile `.navbar` toggle functions appropriately with BS5's updated collapse mechanics.
2. **Widget Layout:** Verify widget columns render smoothly down to 320px viewing widths.

## Next Steps
- Implement BS5 dependencies in `package.json`.
- Execute a global Search & Replace for `.panel` to `.card` conversions.
- Manually run integration tests on routing and UI rendering.

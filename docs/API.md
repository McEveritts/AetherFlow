# AetherFlow Dashboard API Documentation

## Internal Functions (`inc/config.php`, `inc/localize.php`)

### `T($key)`
Translates a string based on the current user's language preference.
- **Parameters**: `$key` (string) - The translation key defined in `lang/lang_XX.php`.
- **Returns**: `string` - The translated string or the key if not found.

### `isWidgetVisible($widgetName)`
Checks if a widget should be displayed for the current user.
- **Parameters**: `$widgetName` (string) - Unique identifier for the widget (e.g., 'bandwidth_data').
- **Returns**: `bool` - `true` if visible, `false` otherwise.
- **Logic**: Checks `user_widgets` table first, falls back to `widgets` table default.

## API Endpoints (`api/`)

### `POST /api/save_widget_pref.php`
Updates the authenticated user's widget visibility preferences.
- **Authentication**: Required (Session).
- **Parameters**: 
  - `widgets[]` (array of strings) - List of enabled widget names.
- **Response**: Redirects to Referer/Profile with success flag.

### `GET /api/get_log.php`
Retrieves usage logs for a specific service using `journalctl`.
- **Authentication**: Required (Session).
- **Parameters**:
  - `service` (string) - Name of the service (e.g., 'rtorrent', 'plex').
- **Response**: JSON object.
  - `logs` (array of strings) - Last 50 lines of the service journal.
  - `error` (string, optional) - Error message if failed.

### `POST /api/gemini.php` (Integration)
Interface for AI Assistant queries.
- **Parameters**: JSON body `{ "prompt": "..." }`.
- **Response**: JSON object `{ "reply": "...", "error": "..." }`.

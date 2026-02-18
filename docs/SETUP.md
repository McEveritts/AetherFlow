# Setup Instructions

## Prerequisites
- PHP 7.4+ or 8.x
- SQLite3 (enabled in `php.ini` via `extension=pdo_sqlite`)
- ImageMagick (for favicons)

## Initialization

1.  **Database**:
    Run the initialization script to embrace the new SQLite backend:
    ```bash
    php dashboard/db/init_db.php
    ```
    Or simply access the dashboard; `inc/config.php` attempts to auto-initialize on first load if the DB file is missing.

2.  **Dependencies**:
    Install PHP dependencies (for development/linting):
    ```bash
    cd dashboard
    composer install
    ```

3.  **Favicons**:
    Generate favicons from a source image:
    ```bash
    ./scripts/favicon.sh path/to/logo.png dashboard/img/favicons
    ```

## Configuration

- Edit `dashboard/inc/config.php` to adjust database paths or default settings.
- Widgets can be toggled via the Profile page.

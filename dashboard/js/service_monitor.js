// Service Monitor - Dynamic Polling for AetherFlow
// Replaces legacy card.app_status.ajax.js

const POLLING_INTERVAL = 3000; // 3 seconds

function updateServiceStatus() {
    $.ajax({
        url: 'api/services_status.php',
        dataType: 'json',
        cache: false,
        success: function (data) {
            // data is { "rtorrent": { "running": true, "enabled": true }, ... }

            for (const [service, status] of Object.entries(data)) {
                // 1. Update Running Status Badge (#appstat_SERVICE)
                const badgeId = '#appstat_' + service;
                const badgeEl = $(badgeId);

                if (badgeEl.length) {
                    let html = '';
                    if (status.running) {
                        html = '<span class="badge badge-service-running-dot"></span><span class="badge badge-service-running-pulse"></span>';
                    } else {
                        html = '<span class="badge badge-service-disabled-dot"></span><span class="badge badge-service-disabled-pulse"></span>';
                    }
                    if (badgeEl.html() !== html) {
                        badgeEl.html(html);
                    }
                }

                // 2. Update Toggle Switch (if present)
                // We construct the selector based on the onclick URL or distinct ID if available?
                // The toggle HTML I generated: <input type="checkbox" ... onchange="location.href='?id=77...service=NAME'">
                // It's hard to select by onchange attribute safely.
                // But the toggle reflects 'enabled' state.
                // Let's try to select by context if possible, or add IDs to toggles in Phase 6c?
                // For now, let's skip auto-updating the toggle state to avoid interrupting user interaction
                // (e.g. if they are about to click it and it flips).
                // Focus on the Badge update which is the primary "Monitor" goal.
            }
        },
        complete: function () {
            setTimeout(updateServiceStatus, POLLING_INTERVAL);
        }
    });
}

$(document).ready(function () {
    updateServiceStatus();
});

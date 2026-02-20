$(document).ready(function () {
    const NOTIF_API = 'api/notifications.php';
    let isDropdownOpen = false;

    // Notification Intelligence (Phase 26)
    var notificationCount = 0;
    var lastNotificationTime = 0;
    var QUIET_MODE_THRESHOLD = 5; // Max notifications per minute
    var QUIET_MODE_WINDOW = 60000; // 1 minute

    function showNotification(title, text, type) {
        var now = new Date().getTime();

        // Reset counter if outside window
        if (now - lastNotificationTime > QUIET_MODE_WINDOW) {
            notificationCount = 0;
        }

        notificationCount++;
        lastNotificationTime = now;

        if (notificationCount > QUIET_MODE_THRESHOLD) {
            console.log("Quiet Mode active: suppressing notification");
            // Optionally update a "bundled" notification
            return;
        }

        $.gritter.add({
            title: title,
            text: text,
            class_name: 'with-icon ' + type, // success, info, warning, danger
            sticky: false
        });
    }

    function fetchNotifications() {
        $.ajax({
            url: NOTIF_API,
            method: 'GET',
            dataType: 'json',
            success: function (data) {
                updateNotificationBadge(data.count);
                if (isDropdownOpen) {
                    renderNotificationList(data.notifications);
                }
            },
            error: function (err) {
                console.error('Failed to fetch notifications', err);
            }
        });
    }

    function updateNotificationBadge(count) {
        const badge = $('#notif-count');
        if (count > 0) {
            badge.text(count).show();
        } else {
            badge.hide();
        }
    }

    function renderNotificationList(notifications) {
        const list = $('#notif-list');
        list.empty();

        if (!notifications || notifications.length === 0) {
            list.append('<div class="text-center" style="padding: 10px; color: #777;">No new notifications</div>');
            return;
        }

        notifications.forEach(function (notif) {
            let iconClass = 'fa-info-circle text-info';
            if (notif.type === 'success') iconClass = 'fa-check-circle text-success';
            if (notif.type === 'warning') iconClass = 'fa-exclamation-triangle text-warning';
            if (notif.type === 'error') iconClass = 'fa-times-circle text-danger';

            const item = $(`
                <a href="${notif.link || '#'}" class="list-group-item notif-item" data-id="${notif.id}" style="border-radius: 0; border-left: 0; border-right: 0;">
                    <div class="media">
                        <div class="media-left">
                            <i class="fa ${iconClass} fa-fw"></i>
                        </div>
                        <div class="media-body">
                            <p style="margin: 0; font-size: 13px; color: #fff;">${notif.message}</p>
                            <small class="text-muted" style="font-size: 10px;">${timeSince(new Date(notif.created_at))}</small>
                        </div>
                    </div>
                </a>
            `);

            item.click(function (e) {
                if (!notif.link) e.preventDefault();
                markAsRead(notif.id);
            });

            list.append(item);
        });
    }

    function markAsRead(id) {
        $.ajax({
            url: NOTIF_API,
            method: 'POST',
            data: {
                action: 'mark_read',
                id: id,
                _csrf_token: $('meta[name="csrf-token"]').attr('content')
            },
            success: function () {
                fetchNotifications();
            }
        });
    }

    function markAllAsRead() {
        $.ajax({
            url: NOTIF_API,
            method: 'POST',
            data: {
                action: 'mark_all_read',
                _csrf_token: $('meta[name="csrf-token"]').attr('content')
            },
            success: function () {
                fetchNotifications();
            }
        });
    }

    // Toggle logic
    $('#notification-li').on('shown.bs.dropdown', function () {
        isDropdownOpen = true;
        fetchNotifications(); // Fetch immediately on open
    });

    $('#notification-li').on('hidden.bs.dropdown', function () {
        isDropdownOpen = false;
    });

    $('#mark-all-read').click(function (e) {
        e.preventDefault();
        e.stopPropagation();
        markAllAsRead();
    });

    // Helper: Time Ago
    function timeSince(date) {
        var seconds = Math.floor((new Date() - date) / 1000);
        var interval = seconds / 31536000;
        if (interval > 1) return Math.floor(interval) + " years ago";
        interval = seconds / 2592000;
        if (interval > 1) return Math.floor(interval) + " months ago";
        interval = seconds / 86400;
        if (interval > 1) return Math.floor(interval) + " days ago";
        interval = seconds / 3600;
        if (interval > 1) return Math.floor(interval) + " hours ago";
        interval = seconds / 60;
        if (interval > 1) return Math.floor(interval) + " minutes ago";
        return Math.floor(seconds) + " seconds ago";
    }

    // Initial Poll
    fetchNotifications();
    // Poll every 60s
    setInterval(fetchNotifications, 60000);
});

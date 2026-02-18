/**
 * AetherFlow CSRF & Security Layer
 *
 * Intercepts legacy GET links for admin actions (install, remove, system,
 * plugins, themes, languages, service control) and converts them to POST
 * requests with CSRF tokens.
 *
 * This avoids rewriting hundreds of HTML links while providing CSRF
 * protection at the client layer. The server-side also validates.
 *
 * @package AetherFlow
 * @author McEveritts <armyworkbs@gmail.com>
 */
(function ($) {
    'use strict';

    // Read CSRF token from meta tag (set in panel.header.php)
    var csrfToken = $('meta[name="csrf-token"]').attr('content') || '';

    // Setup CSRF token for all jQuery AJAX requests
    $.ajaxSetup({
        headers: {
            'X-CSRF-TOKEN': csrfToken
        }
    });

    /**
     * Intercept clicks on legacy admin action links and convert to POST.
     */
    $(document).on('click', 'a[href]', function (e) {
        var href = $(this).attr('href');
        if (!href) return;

        var match;

        // Package install: ?installpackage-{name}=true
        match = href.match(/\?installpackage-([^=]+)=true/);
        if (match) {
            e.preventDefault();
            submitPostAction('install_package', match[1]);
            return;
        }

        // Package remove: ?removepackage-{name}=true
        match = href.match(/\?removepackage-([^=]+)=true/);
        if (match) {
            e.preventDefault();
            submitPostAction('remove_package', match[1]);
            return;
        }

        // Plugin install: ?installplugin-{name}=true
        match = href.match(/\?installplugin-([^=]+)=true/);
        if (match) {
            e.preventDefault();
            submitPostAction('install_plugin', match[1]);
            return;
        }

        // Plugin remove: ?removeplugin-{name}=true
        match = href.match(/\?removeplugin-([^=]+)=true/);
        if (match) {
            e.preventDefault();
            submitPostAction('remove_plugin', match[1]);
            return;
        }

        // Theme select: ?themeSelect-{name}=true
        match = href.match(/\?themeSelect-([^=]+)=true/);
        if (match) {
            e.preventDefault();
            submitPostAction('theme_select', match[1]);
            return;
        }

        // Language select: ?langSelect-{name}=true
        match = href.match(/\?langSelect-([^=]+)=true/);
        if (match) {
            e.preventDefault();
            submitPostAction('lang_select', match[1]);
            return;
        }

        // Service control: ?id=66&serviceenable=X, ?id=77&servicedisable=X, ?id=88&servicestart=X
        match = href.match(/\?id=66&serviceenable=([^&]+)/);
        if (match) {
            e.preventDefault();
            submitServiceAction(66, 'serviceenable', match[1]);
            return;
        }
        match = href.match(/\?id=77&servicedisable=([^&]+)/);
        if (match) {
            e.preventDefault();
            submitServiceAction(77, 'servicedisable', match[1]);
            return;
        }
        match = href.match(/\?id=88&servicestart=([^&]+)/);
        if (match) {
            e.preventDefault();
            submitServiceAction(88, 'servicestart', match[1]);
            return;
        }

        // System actions: clean_mem, clean_log
        var systemActions = ['clean_mem', 'clean_log'];
        for (var i = 0; i < systemActions.length; i++) {
            if (href.indexOf('?' + systemActions[i] + '=true') !== -1 ||
                href.indexOf('?' + systemActions[i]) !== -1) {
                e.preventDefault();
                submitPostAction(systemActions[i], 'true');
                return;
            }
        }
    });

    /**
     * Submit a POST form dynamically with CSRF token.
     *
     * @param {string} action - The action name (e.g., 'install_package')
     * @param {string} value  - The action value (e.g., 'plex')
     */
    function submitPostAction(action, value) {
        var $form = $('<form>', {
            method: 'POST',
            action: window.location.pathname
        });

        $form.append($('<input>', { type: 'hidden', name: '_csrf_token', value: csrfToken }));
        $form.append($('<input>', { type: 'hidden', name: action, value: value }));

        $form.appendTo('body').submit();
    }

    /**
     * Submit a service control POST with id + service name.
     */
    function submitServiceAction(id, actionName, serviceName) {
        var $form = $('<form>', {
            method: 'POST',
            action: window.location.pathname
        });

        $form.append($('<input>', { type: 'hidden', name: '_csrf_token', value: csrfToken }));
        $form.append($('<input>', { type: 'hidden', name: 'id', value: id }));
        $form.append($('<input>', { type: 'hidden', name: actionName, value: serviceName }));

        $form.appendTo('body').submit();
    }

})(jQuery);

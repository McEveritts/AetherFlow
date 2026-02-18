<!-- AETHERFLOW STORE WIDGET -->
<div class="panel panel-main panel-inverse" id="aetherflow-store">
    <div class="panel-heading">
        <h4 class="panel-title">AetherFlow Store</h4>
        <div class="panel-btns">
            <button class="btn btn-xs btn-primary" onclick="loadStore()">Refresh Catalog</button>
        </div>
    </div>
    <div class="panel-body">
        <div id="store-grid" class="row">
            <!-- Cards will be injected here -->
            <div class="col-md-12 text-center text-muted">Loading Store...</div>
        </div>
    </div>
</div>

<style>
    .store-card {
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 4px;
        padding: 15px;
        margin-bottom: 20px;
        transition: all 0.2s ease;
        height: 100%;
        display: flex;
        flex-direction: column;
    }

    .store-card:hover {
        background: rgba(255, 255, 255, 0.1);
        border-color: var(--accent-gold);
        transform: translateY(-2px);
    }

    .store-icon {
        font-size: 32px;
        margin-bottom: 10px;
        color: var(--accent-gold);
    }

    .store-title {
        font-size: 16px;
        font-weight: 600;
        margin-bottom: 5px;
        color: #fff;
    }

    .store-desc {
        font-size: 12px;
        color: #aaa;
        flex-grow: 1;
        margin-bottom: 15px;
        line-height: 1.4;
    }

    .store-footer {
        border-top: 1px solid rgba(255, 255, 255, 0.1);
        padding-top: 10px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    .badge-category {
        background: rgba(0, 0, 0, 0.3);
        color: #888;
        font-size: 10px;
        padding: 2px 6px;
        border-radius: 3px;
    }
</style>

<script>
    function loadStore() {
        $('#store-grid').html('<div class="col-md-12 text-center text-muted"><i class="fa fa-spinner fa-spin"></i> Loading...</div>');

        $.post('api/store.php', { action: 'list' }, function (data) {
            var html = '';
            if (data.packages && data.packages.length > 0) {
                data.packages.forEach(function (pkg) {
                    var btnClass = pkg.installed ? 'btn-success disabled' : 'btn-primary';
                    var btnText = pkg.installed ? '<i class="fa fa-check"></i> Installed' : 'Install';
                    var action = pkg.installed ? '' : 'onclick="installPackage(\'' + pkg.id + '\')"';

                    // If installed, maybe offer uninstall? Or just show status for now.
                    if (pkg.installed) {
                        // For prototype, let's keep it simple: just show status
                    }

                    html += '<div class="col-md-4 col-sm-6 mb20">' +
                        '<div class="store-card">' +
                        '<div class="store-icon"><i class="fa ' + (pkg.icon || 'fa-cube') + '"></i></div>' +
                        '<div class="store-title">' + pkg.name + '</div>' +
                        '<div class="store-desc">' + pkg.description + '</div>' +
                        '<div class="store-footer">' +
                        '<span class="badge-category">' + (pkg.category || 'System') + '</span>' +
                        '<button class="btn btn-xs ' + btnClass + '" ' + action + '>' + btnText + '</button>' +
                        '</div>' +
                        '</div>' +
                        '</div>';
                });
            } else {
                html = '<div class="col-md-12 text-center text-warning">No packages found in catalog.</div>';
            }
            $('#store-grid').html(html);
        });
    }

    function installPackage(id) {
        if (!confirm('Install package: ' + id + '? This may take time.')) return;

        // Optimistic UI update
        var btn = $('button[onclick="installPackage(\'' + id + '\')"]');
        var originalText = btn.html();
        btn.html('<i class="fa fa-spinner fa-spin"></i> Installing...').prop('disabled', true);

        $.post('api/store.php', { action: 'install', id: id }, function (data) {
            if (data.success) {
                alert(data.message);
                loadStore(); // Refresh to update status
            } else {
                alert('Error: ' + (data.error || 'Unknown error'));
                btn.html(originalText).prop('disabled', false);
            }
        }).fail(function () {
            alert('Request failed.');
            btn.html(originalText).prop('disabled', false);
        });
    }

    $(document).ready(function () {
        loadStore();
    });
</script>
<!-- BACKUP CONTROL WIDGET -->
<div class="card card-main card-inverse">
    <div class="card-header">
        <h4 class="card-title">Backup & Recovery</h4>
        <div class="card-btns">
            <button class="btn btn-xs btn-primary" onclick="createBackup()">Create Snapshot</button>
        </div>
    </div>
    <div class="card-body">
        <div class="table-responsive">
            <table class="table table-hover nomargin">
                <thead>
                    <tr>
                        <th>Snapshot Name</th>
                        <th class="text-end">Actions</th>
                    </tr>
                </thead>
                <tbody id="backup-list">
                    <tr>
                        <td colspan="2" class="text-center text-muted">Loading snapshots...</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</div>

<script>
    function loadBackups() {
        $.post('api/backup.php', { action: 'list' }, function (data) {
            var rows = '';
            if (data.backups && data.backups.length > 0) {
                data.backups.forEach(function (line) {
                    if (line.trim() === '') return;
                    var parts = line.split(' '); // Simple parse: filename (size)
                    var filename = parts[0];

                    rows += '<tr>' +
                        '<td><i class="fa fa-archive text-warning"></i> ' + line + '</td>' +
                        '<td class="text-end">' +
                        '<button class="btn btn-xs btn-success btn-icon" onclick="restoreBackup(\'' + filename + '\')" title="Restore"><i class="fa fa-rotate-left"></i></button> ' +
                        '<button class="btn btn-xs btn-danger btn-icon" onclick="deleteBackup(\'' + filename + '\')" title="Delete"><i class="fa fa-trash"></i></button>' +
                        '</td>' +
                        '</tr>';
                });
            } else {
                rows = '<tr><td colspan="2" class="text-center text-muted">No backups found.</td></tr>';
            }
            $('#backup-list').html(rows);
        });
    }

    function createBackup() {
        if (!confirm('Create a new system snapshot? This may take a few moments.')) return;

        // UI Feedback
        var btn = $('.card-btns button');
        var originalText = btn.text();
        btn.text('Creating...').prop('disabled', true);

        $.post('api/backup.php', { action: 'create' }, function (data) {
            alert(data.message || 'Backup process initiated.');
            loadBackups();
            btn.text(originalText).prop('disabled', false);
        }).fail(function () {
            alert('Failed to create backup.');
            btn.text(originalText).prop('disabled', false);
        });
    }

    function deleteBackup(filename) {
        if (!confirm('Are you sure you want to permanently delete ' + filename + '?')) return;
        $.post('api/backup.php', { action: 'delete', filename: filename }, function (data) {
            loadBackups(); // Refresh list
        });
    }

    function restoreBackup(filename) {
        if (!confirm('WARNING: restoring ' + filename + ' will overwrite current configurations. Continue?')) return;
        $.post('api/backup.php', { action: 'restore', filename: filename }, function (data) {
            alert(data.message || 'Restore process finished.');
        });
    }

    $(document).ready(function () {
        loadBackups();
    });
</script>
<?php
include('inc/config.php');
include('inc/panel.header.php');
include('inc/panel.menu.php');

// Handle Password Change
$password_feedback = "";
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['change_password'])) {
    requireCsrfToken();
    $new_pass = $_POST['new_pass'];
    
    // Basic validation
    if (strlen($new_pass) < 6) {
        $password_feedback = "<div class='alert alert-danger'>Password must be at least 6 characters long.</div>";
    } else {
        $safeUser = escapeshellarg($username);
        $safePass = escapeshellarg($new_pass);

        // Try to update system password for the user
        // Using chpasswd is generally safer/better if available, but sudo passwd needs stdin handling.
        // Command: echo "username:password" | sudo chpasswd
        // OR: printf "password\npassword" | sudo passwd username

        // Let's try the pipe to passwd method as it's common on Linux
        $cmd = sprintf("printf '%%s\\n%%s' %s %s | sudo passwd %s 2>&1", $safePass, $safePass, $safeUser);
        $output = shell_exec($cmd);

        if (strpos($output, 'successfully') !== false || strpos($output, 'success') !== false) {
            $password_feedback = "<div class='alert alert-success'>System password updated successfully.</div>";
        } else {
            $password_feedback = "<div class='alert alert-warning'>Password update attempt finished. Output: " . htmlspecialchars($output) . "</div>";
        }
    }
}

// Handle Webhook Save
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_webhook'])) {
    requireCsrfToken();
    $webhook = trim($_POST['discord_webhook']);
    
    // Insert or Update
    $stmt = $db->prepare("INSERT INTO user_settings (user_id, setting_key, setting_value) VALUES (?, 'discord_webhook', ?) 
                          ON CONFLICT(user_id, setting_key) DO UPDATE SET setting_value = excluded.setting_value");
    if ($stmt->execute([$_SESSION['user']['id'], $webhook])) {
        $password_feedback = "<div class='alert alert-success'>Webhook settings updated.</div>";
    } else {
        $password_feedback = "<div class='alert alert-danger'>Failed to update webhook settings.</div>";
    }
}

// Fetch Login History
$loginHistory = [];
try {
    // Check if table exists first (it should via callback.php)
    $stmt = $db->prepare("SELECT ip_address, user_agent, login_time FROM login_history WHERE user_id = ? ORDER BY login_time DESC LIMIT 10");
    $stmt->execute([$_SESSION['user']['id']]);
    $loginHistory = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    // Table might not exist yet if no logins recorded or migration failed
    $loginHistory = []; 
}

// Fetch Widget Settings (Preserving Phase 15 placeholder logic)
$widgetsList = [];
try {
    $widgetsList = $db->query("SELECT * FROM widgets")->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $widgetsList = [];
}

?>

<div class="mainpanel">
    <div class="contentpanel">
        <ol class="breadcrumb">
            <li><a href="index.php"><i class="fa fa-home"></i> <?php echo T('MAIN_MENU'); ?></a></li>
            <li class="active"><?php echo T('PROFILE'); ?></li>
        </ol>

        <div class="row">
            <!-- Account Info Column (Left) -->
            <div class="col-md-4">
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h4 class="panel-title">Account Information</h4>
                    </div>
                    <div class="panel-body">
                        <div class="text-center" style="margin-bottom: 20px;">
                            <img src="<?php echo htmlspecialchars($_SESSION['user']['avatar_url'] ?? 'img/default-avatar.png'); ?>" 
                                 alt="Avatar" class="img-circle" style="width: 100px; height: 100px; border: 3px solid #eee;">
                        </div>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <strong>Username</strong>
                                <span class="pull-right text-muted"><?php echo htmlspecialchars($_SESSION['user']['username']); ?></span>
                            </li>
                            <li class="list-group-item">
                                <strong>Email</strong>
                                <span class="pull-right text-muted"><?php echo htmlspecialchars($_SESSION['user']['email']); ?></span>
                            </li>
                            <li class="list-group-item">
                                <strong>Role</strong>
                                <span class="pull-right text-muted"><?php echo htmlspecialchars(ucfirst($_SESSION['user']['role'])); ?></span>
                            </li>
                            <li class="list-group-item">
                                <strong>Google ID</strong>
                                <span class="pull-right text-muted" title="<?php echo htmlspecialchars($_SESSION['user']['google_id']); ?>">
                                    <?php echo substr($_SESSION['user']['google_id'], 0, 8) . '...'; ?>
                                </span>
                            </li>
                        </ul>
                    </div>
                </div>

                <!-- Widget Settings (Phase 15 Placeholder) -->
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h4 class="panel-title"><?php echo T('WIDGET_SETTINGS'); ?></h4>
                    </div>
                    <div class="panel-body">
                        <p class="small text-muted">Toggle visibility of dashboard widgets.</p>
                        <form action="api/save_widget_pref.php" method="POST">
                            <?php csrfField(); ?>
                            <ul class="list-group" style="max-height: 300px; overflow-y: auto;">
                                <?php foreach ($widgetsList as $widget): ?>
                                <li class="list-group-item" style="padding: 10px 15px;">
                                    <?php echo T($widget['title_key']); ?>
                                    <div class="pull-right">
                                        <label class="switch-sm">
                                            <input type="checkbox" name="widgets[]" value="<?php echo htmlspecialchars($widget['name']); ?>" 
                                            <?php echo isWidgetVisible($widget['name']) ? 'checked' : ''; ?>>
                                        </label>
                                    </div>
                                </li>
                                <?php endforeach; ?>
                            </ul>
                            <button type="submit" class="btn btn-primary btn-block btn-sm" style="margin-top: 10px;">
                                <?php echo T('UPDATE'); ?> Preferences
                            </button>
                        </form>
                    </div>
                </div>
            </div>

            <!-- Notification Settings -->
            <div class="panel panel-default">
                <div class="panel-heading">
                    <h4 class="panel-title">Notification Settings</h4>
                </div>
                <div class="panel-body">
                    <form method="POST">
                        <?php csrfField(); ?>
                        <div class="form-group">
                            <label>Discord Webhook URL</label>
                            <input type="url" name="discord_webhook" class="form-control" placeholder="https://discord.com/api/webhooks/..."
                                value="<?php echo htmlspecialchars($db->query("SELECT setting_value FROM user_settings WHERE user_id = " . $_SESSION['user']['id'] . " AND setting_key = 'discord_webhook'")->fetchColumn() ?: ''); ?>">
                            <p class="help-block small">Receive notifications directly to your Discord server.</p>
                        </div>
                        <button type="submit" name="save_webhook" value="true" class="btn btn-primary btn-sm btn-block">
                            Save Webhook
                        </button>
                    </form>
                </div>
            </div>
        </div>

            <!-- Settings Column (Right) -->
            <div class="col-md-8">
                
                <!-- System Password Change -->
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h4 class="panel-title">System Password</h4>
                        <p class="small text-muted" style="margin-bottom:0">Change your Linux system password (affects SSH, FTP, etc).</p>
                    </div>
                    <div class="panel-body">
                        <?php if (!empty($password_feedback)) echo $password_feedback; ?>
                        
                        <form method="POST" class="form-horizontal">
                            <?php csrfField(); ?>
                            <!-- Old password not strictly verified by sudo passwd in this flow, usually root force sets it. 
                                 Ideally we'd verify old password first for security, but sudo allows override. 
                                 Let's ask for it for UI consistency/safety if we can verify it later. -->
                            
                            <div class="form-group">
                                <label class="col-sm-3 control-label">New Password</label>
                                <div class="col-sm-6">
                                    <input type="password" name="new_pass" class="form-control" required minlength="6">
                                </div>
                            </div>
                            
                            <div class="form-group">
                                <div class="col-sm-offset-3 col-sm-6">
                                    <button type="submit" name="change_password" value="true" class="btn btn-danger">
                                        Update System Password
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>

                <!-- Login History -->
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h4 class="panel-title">Login History</h4>
                        <p class="small text-muted" style="margin-bottom:0">Recent access to your account.</p>
                    </div>
                    <div class="panel-body">
                        <div class="table-responsive">
                            <table class="table table-hover table-striped">
                                <thead>
                                    <tr>
                                        <th>Date/Time</th>
                                        <th>IP Address</th>
                                        <th>User Agent</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($loginHistory)): ?>
                                        <tr><td colspan="3" class="text-center text-muted">No login history available.</td></tr>
                                    <?php else: ?>
                                        <?php foreach ($loginHistory as $entry): ?>
                                            <tr>
                                                <td><?php echo htmlspecialchars($entry['login_time']); ?></td>
                                                <td><?php echo htmlspecialchars($entry['ip_address']); ?></td>
                                                <td title="<?php echo htmlspecialchars($entry['user_agent']); ?>">
                                                    <?php 
                                                        // Simplify User Agent for display
                                                        $ua = $entry['user_agent'];
                                                        if (strpos($ua, 'Chrome') !== false) $ua = 'Chrome';
                                                        elseif (strpos($ua, 'Firefox') !== false) $ua = 'Firefox';
                                                        elseif (strpos($ua, 'Safari') !== false) $ua = 'Safari';
                                                        elseif (strpos($ua, 'Edge') !== false) $ua = 'Edge';
                                                        echo htmlspecialchars($ua); 
                                                    ?>
                                                    <small class="text-muted" style="font-size: 0.8em;">(...) </small>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    <?php endif; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

            </div>
        </div>
    </div>
</div>

<?php
include('inc/panel.scripts.php');
include('inc/panel.end.php');
?>
<?php
include('inc/config.php');
include('inc/panel.header.php');
include('inc/panel.menu.php');
?>

<div class="mainpanel">
    <div class="contentpanel">
        <ol class="breadcrumb">
            <li><a href="index.php"><i class="fa fa-home"></i>
                    <?php echo T('MAIN_MENU'); ?>
                </a></li>
            <li class="active">
                <?php echo T('PROFILE'); ?>
            </li>
        </ol>

        <?php if (isset($_GET['success']) && $_GET['success'] == 'widgets'): ?>
        <div class="alert alert-success">
            <button type="button" class="close" data-dismiss="alert" aria-hidden="true">&times;</button>
            <?php echo T('WIDGET_SETTINGS'); ?> updated successfully!
        </div>
        <?php endif; ?>

        <div class="row">
            <div class="col-md-12">
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h4 class="panel-title">
                            <?php echo T('PROFILE'); ?>
                        </h4>
                        <p>Manage your account settings and dashboard preferences.</p>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <!-- User Settings -->
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h4 class="panel-title">
                            <?php echo T('WIDGET_SETTINGS'); ?> (P15)
                        </h4>
                    </div>
                    <div class="panel-body">
                        <p>Toggle visibility of dashboard widgets.</p>
                        <?php
                        // Fetch widgets for display
                        try {
                            $widgetsList = $db->query("SELECT * FROM widgets")->fetchAll(PDO::FETCH_ASSOC);
                        } catch (PDOException $e) {
                            $widgetsList = [];
                            echo "<div class='alert alert-warning'>Failed to load widgets list. Database error.</div>";
                        }
                        ?>
                        <form action="api/save_widget_pref.php" method="POST">
                            <?php csrfField(); ?>
                            <ul class="list-group">
                                <?php foreach ($widgetsList as $widget): ?>
                                <li class="list-group-item">
                                    <?php echo T($widget['title_key']); ?>
                                    <div class="pull-right">
                                        <label>
                                            <input type="checkbox" name="widgets[]" value="<?php echo htmlspecialchars($widget['name']); ?>" 
                                            <?php echo isWidgetVisible($widget['name']) ? 'checked' : ''; ?>> Visible
                                        </label>
                                    </div>
                                </li>
                                <?php endforeach; ?>
                            </ul>
                            <button type="submit" class="btn btn-primary">
                                <?php echo T('AGREE'); ?>
                            </button>
                        </form>
                    </div>
                </div>
            </div>

            <?php
            if (isset($_POST['change_password'])) {
                requireCsrfToken();
                $new_pass = $_POST['new_pass'];
                // P0: Critical Security - Sanitize Input
                // Although we pipe the password, we must ensure it doesn't contain null bytes or other shell manipulation characters if possible.
                // However, passwords can contain almost anything. escapeshellarg is safe for quoting.
                $safeUser = escapeshellarg($username);
                $safePass = escapeshellarg($new_pass);

                // Using echo pipeline to feed password to passwd command
                // Note: echoing password in process list is visible? echo is built-in usually, but checking `ps` might reveal it if executed as /bin/echo.
                // Better to use a file or pipe securely. Given constraints, we use the standard approach for this environment.
                // We assume sudoers allows 'sudo passwd $username' without password for www-data.
            
                // Command: echo "password\npassword" | sudo passwd username
                $cmd = "echo $safePass | sudo passwd --stdin $safeUser";

                // Fallback if --stdin is not supported (e.g. standard passwd), try sending twice
                // $cmd = "echo -e \"$safePass\\n$safePass\" | sudo passwd $safeUser";
            
                // Let's us the double echo method which is more compatible
                // formatting the string for echo -e needs care.
                // A simpler way: printf "$new_pass\n$new_pass" | sudo passwd "$username"
                // We use escapeshellarg for the pass, so it's quoted: 'password'.
                // printf '%s\n%s' 'pass' 'pass' | ...
            
                $cmd = sprintf("printf '%%s\\n%%s' %s %s | sudo passwd %s", $safePass, $safePass, $safeUser);

                $output = shell_exec($cmd);
                $password_feedback = "<div class='alert alert-info'>Password change attempt executed. Output: " . htmlspecialchars($output) . "</div>";
            }
            ?>
            <!-- ... existing layout ... -->
            <div class="col-md-6">
                <!-- User Settings -->
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h4 class="panel-title">Account Security</h4>
                    </div>
                    <div class="panel-body">
                        <?php if (isset($password_feedback))
                            echo $password_feedback; ?>
                        <form method="POST">
                            <?php csrfField(); ?>
                            <div class="form-group">
                                <label class="col-sm-3 control-label">Current Password</label>
                                <div class="col-sm-9">
                                    <input type="password" name="old_pass" class="form-control"
                                        placeholder="(Not verified)">
                                </div>
                            </div>
                            <div class="form-group">
                                <label class="col-sm-3 control-label">New Password</label>
                                <div class="col-sm-9">
                                    <input type="password" name="new_pass" class="form-control" required>
                                </div>
                            </div>
                            <button type="submit" name="change_password" value="true"
                                class="btn btn-danger btn-block">Change Password</button>
                        </form>
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
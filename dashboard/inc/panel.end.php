<?php include($_SERVER['DOCUMENT_ROOT'] . '/widgets/gemini_assistant.php'); ?>
</body>

</html>
<?php
// Timing: calculate page generation time
$time_end = microtime_float();
$gentime = substr(($time_end - $time_start), 0, 5);
// Note: session_destroy() was removed — it was destroying auth sessions on every page load
?>
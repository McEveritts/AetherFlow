<?php
// AetherFlow Predictive Analytics (Phase 29)
header('Content-Type: application/json');
include_once '../inc/config.php';

// Mocking vnStat history data for simulation
// In production: parse `vnstat --json`
$history = [
    ['day' => 1, 'rx' => 500],
    ['day' => 2, 'rx' => 550],
    ['day' => 3, 'rx' => 600],
    ['day' => 4, 'rx' => 580],
    ['day' => 5, 'rx' => 620],
    ['day' => 6, 'rx' => 700],
    ['day' => 7, 'rx' => 750]
];

// Simple Linear Regression
$n = count($history);
$sumX = 0;
$sumY = 0;
$sumXY = 0;
$sumXX = 0;

foreach ($history as $point) {
    $sumX += $point['day'];
    $sumY += $point['rx'];
    $sumXY += ($point['day'] * $point['rx']);
    $sumXX += ($point['day'] * $point['day']);
}

$slope = ($n * $sumXY - $sumX * $sumY) / ($n * $sumXX - $sumX * $sumX);
$intercept = ($sumY - $slope * $sumX) / $n;

// Forecast next 3 days
$forecast = [];
for ($i = 1; $i <= 3; $i++) {
    $nextDay = $n + $i;
    $predictedRx = $slope * $nextDay + $intercept;
    $forecast[] = ['day' => $nextDay, 'predicted_rx' => round($predictedRx, 2)];
}

echo json_encode([
    'trend' => ($slope > 0) ? 'Increasing' : 'Decreasing',
    'slope' => round($slope, 2),
    'forecast' => $forecast
]);
?>
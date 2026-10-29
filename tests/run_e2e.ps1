# PowerShell wrapper for AetherFlow v3.1.7 E2E Test Suite
Param(
    [int]$Tier = 0,
    [string]$Feature = "",
    [string]$Mode = "contract",
    [string]$Url = "http://localhost:8080",
    [string]$Socket = "/run/aetherflow/runner.sock",
    [switch]$VerboseOutput,
    [switch]$FailFast,
    [string]$JsonOut = "",
    [string]$ReportOut = ""
)

$argsList = @("tests/run_e2e.py")

if ($Tier -gt 0) {
    $argsList += "--tier"
    $argsList += "$Tier"
}
if ($Feature) {
    $argsList += "--feature"
    $argsList += "$Feature"
}
if ($Mode) {
    $argsList += "--mode"
    $argsList += "$Mode"
}
if ($Url) {
    $argsList += "--url"
    $argsList += "$Url"
}
if ($Socket) {
    $argsList += "--socket"
    $argsList += "$Socket"
}
if ($VerboseOutput) {
    $argsList += "--verbose"
}
if ($FailFast) {
    $argsList += "--fail-fast"
}
if ($JsonOut) {
    $argsList += "--json-out"
    $argsList += "$JsonOut"
}
if ($ReportOut) {
    $argsList += "--report-out"
    $argsList += "$ReportOut"
}

python @argsList
exit $LASTEXITCODE

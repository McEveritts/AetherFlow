<?php

// Valid values for other parameters you can pass to the script.
// Input parameters will always be limited to one of the values listed here.
// If a parameter is not provided or invalid it will revert to the default,
// the first parameter in the list.

if (isset($_SERVER['PHP_SELF'])) {
    $script = $_SERVER['PHP_SELF'];
} elseif (isset($_SERVER['SCRIPT_NAME'])) {
    $script = $_SERVER['SCRIPT_NAME'];
} else {
    die('can\'t determine script name!');
}

$page_list = array('s', 'h', 'd', 'm');

$page_title['s'] = T('summary');
$page_title['h'] = T('hours');
$page_title['d'] = T('days');
$page_title['m'] = T('months');


//
// functions
//
function validate_input()
{
    global $page, $page_list;
    global $iface, $iface_list;
    //
    // get interface data
    //
    $page = isset($_GET['page']) ? $_GET['page'] : '';
    $iface = isset($_GET['if']) ? $_GET['if'] : '';

    if (!in_array($page, $page_list)) {
        $page = $page_list[0];
    }

    if (!in_array($iface, $iface_list)) {
        $iface = $iface_list[0];
    }
}


function get_vnstat_data($use_label = true)
{
    global $iface, $vnstat_bin, $data_dir;
    global $hour, $day, $month, $top, $summary;

    $day = array();
    $hour = array();
    $month = array();
    $top = array();
    $summary = array('totalrx' => 0, 'totalrxk' => 0, 'totaltx' => 0, 'totaltxk' => 0); // Initialize defaults

    // Attempt JSON (vnStat 2.x)
    $json_output = null;
    if (isset($vnstat_bin) && $vnstat_bin != '') {
        $json_output = shell_exec("$vnstat_bin --json -i $iface 2>/dev/null");
    }

    $json = json_decode($json_output ?? '', true);

    if ($json && isset($json['interfaces'])) {
        // Find interface
        $ifaceData = null;
        foreach ($json['interfaces'] as $int) {
            if ($int['name'] == $iface) {
                $ifaceData = $int;
                break;
            }
        }
        if (!$ifaceData && count($json['interfaces']) > 0)
            $ifaceData = $json['interfaces'][0];

        if ($ifaceData) {
            $traffic = $ifaceData['traffic'] ?? $ifaceData;

            // Helper to parse Traffic List
            $parse_list = function ($list, $type) use ($use_label) {
                $result = [];
                foreach ($list as $entry) {
                    $rx = $entry['rx'];
                    $tx = $entry['tx'];

                    // Timestamp construction
                    $date = $entry['date'];
                    $time = isset($entry['time']) ? $entry['time'] : ['hour' => 0, 'minute' => 0];
                    $ts = mktime($time['hour'], $time['minute'], 0, $date['month'], $date['day'], $date['year']);

                    $item = [
                        'time' => $ts,
                        'rx' => $rx / 1024, // Bytes to KB
                        'tx' => $tx / 1024,
                        'act' => 1
                    ];

                    if ($use_label) {
                        if ($type == 'h') {
                            // Hour label
                            $item['label'] = strftime(T('datefmt_hours'), $ts) . ' - ' . strftime(T('datefmt_hours'), $ts + 3600);
                        } elseif ($type == 'd') {
                            $item['label'] = strftime(T('datefmt_days'), $ts);
                        } elseif ($type == 'm') {
                            $item['label'] = strftime(T('datefmt_months'), $ts);
                        } elseif ($type == 't') {
                            $item['label'] = strftime(T('datefmt_top'), $ts);
                        }
                    } else {
                        $item['label'] = '';
                    }
                    $result[] = $item;
                }
                return $result;
            };

            if (isset($traffic['hour']))
                $hour = $parse_list($traffic['hour'], 'h');
            if (isset($traffic['day']))
                $day = $parse_list($traffic['day'], 'd');
            if (isset($traffic['month']))
                $month = $parse_list($traffic['month'], 'm');
            if (isset($traffic['top']))
                $top = $parse_list($traffic['top'], 't');

            // Summary
            // vnStat JSON total is simplified.
            if (isset($traffic['total'])) {
                $summary['totalrx'] = floor($traffic['total']['rx'] / 1024 / 1024); // MB
                $summary['totalrxk'] = ($traffic['total']['rx'] / 1024) % 1024; // Remainder KB
                $summary['totaltx'] = floor($traffic['total']['tx'] / 1024 / 1024);
                $summary['totaltxk'] = ($traffic['total']['tx'] / 1024) % 1024;
            }

            rsort($day);
            rsort($month);
            rsort($hour);
            return;
        }
    }

    // FALLBACK: Old dumpdb parsing
    $vnstat_data = array();
    if (!isset($vnstat_bin) || $vnstat_bin == '') {
        if (file_exists("$data_dir/vnstat_dump_$iface")) {
            $vnstat_data = file("$data_dir/vnstat_dump_$iface");
        }
    } else {
        $fd = popen("$vnstat_bin --dumpdb -i $iface", "r");
        if (is_resource($fd)) {
            $buffer = '';
            while (!feof($fd)) {
                $buffer .= fgets($fd);
            }
            $vnstat_data = explode("\n", $buffer);
            pclose($fd);
        }
    }

    if (isset($vnstat_data[0]) && strpos($vnstat_data[0], 'Error') !== false) {
        return;
    }

    foreach ($vnstat_data as $line) {
        $d = explode(';', trim($line));
        if (count($d) < 3)
            continue;

        if ($d[0] == 'd') {
            $day[$d[1]]['time'] = $d[2];
            $day[$d[1]]['rx'] = $d[3] * 1024 + $d[5];
            $day[$d[1]]['tx'] = $d[4] * 1024 + $d[6];
            $day[$d[1]]['act'] = $d[7];
            if ($d[2] != 0 && $use_label) {
                $day[$d[1]]['label'] = strftime(T('datefmt_days'), $d[2]);
                $day[$d[1]]['img_label'] = strftime(T('datefmt_days_img'), $d[2]);
            } elseif ($use_label) {
                $day[$d[1]]['label'] = '';
                $day[$d[1]]['img_label'] = '';
            }
        } else if ($d[0] == 'm') {
            $month[$d[1]]['time'] = $d[2];
            $month[$d[1]]['rx'] = $d[3] * 1024 + $d[5];
            $month[$d[1]]['tx'] = $d[4] * 1024 + $d[6];
            $month[$d[1]]['act'] = $d[7];
            if ($d[2] != 0 && $use_label) {
                $month[$d[1]]['label'] = strftime(T('datefmt_months'), $d[2]);
                $month[$d[1]]['img_label'] = strftime(T('datefmt_months_img'), $d[2]);
            } else if ($use_label) {
                $month[$d[1]]['label'] = '';
                $month[$d[1]]['img_label'] = '';
            }
        } else if ($d[0] == 'h') {
            $hour[$d[1]]['time'] = $d[2];
            $hour[$d[1]]['rx'] = $d[3];
            $hour[$d[1]]['tx'] = $d[4];
            $hour[$d[1]]['act'] = 1;
            if ($d[2] != 0 && $use_label) {
                $st = $d[2] - ($d[2] % 3600);
                $et = $st + 3600;
                $hour[$d[1]]['label'] = strftime(T('datefmt_hours'), $st) . ' - ' . strftime(T('datefmt_hours'), $et);
                $hour[$d[1]]['img_label'] = strftime(T('datefmt_hours_img'), $d[2]);
            } else if ($use_label) {
                $hour[$d[1]]['label'] = '';
                $hour[$d[1]]['img_label'] = '';
            }
        } else if ($d[0] == 't') {
            $top[$d[1]]['time'] = $d[2];
            $top[$d[1]]['rx'] = $d[3] * 1024 + $d[5];
            $top[$d[1]]['tx'] = $d[4] * 1024 + $d[6];
            $top[$d[1]]['act'] = $d[7];
            if ($use_label) {
                $top[$d[1]]['label'] = strftime(T('datefmt_top'), $d[2]);
                $top[$d[1]]['img_label'] = '';
            }
        } else {
            $summary[$d[0]] = isset($d[1]) ? $d[1] : '';
        }
    }

    rsort($day);
    rsort($month);
    rsort($hour);
}
?>
<?php
// HTTP Security Headers
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
?>
<html lang="en">

<head>
  <?php echo csrfMeta(); ?>
  <!-- META -->
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
  <meta name="description" content="<?php echo $panel['description'] ?>">
  <meta name="author" content="<?php echo $panel['author'] ?>">
  <title><?php echo $panel['title'] ?></title>
  <meta name="robots" content="<?php echo $panel['robots'] ?>">
  <meta name="theme-color" content="#ffffff">
  <!-- FAVICON ASSETTS -->
  <link rel="apple-touch-icon" sizes="180x180" href="img/favicon/apple-touch-icon.png">
  <link rel="icon" type="image/png" href="img/favicon/favicon-32x32.png" sizes="32x32">
  <link rel="icon" type="image/png" href="img/favicon//favicon-16x16.png" sizes="16x16">
  <link rel="manifest" href="img/favicon/manifest.json">
  <link rel="mask-icon" href="img/favicon/safari-pinned-tab.svg" color="#5bbad5">
  <!-- CSS STYLESHEETS AND ASSETTS -->
  <script>
    // Phase 28: Command Bar Listener
    document.addEventListener('keydown', function (e) {
      if (e.ctrlKey && e.key === 'k') {
        var cmd = prompt("AetherFlow Command Center:");
        if (cmd) {
          $.post('api/command.php', { command: cmd }, function (res) {
            alert(res.message);
          });
        }
      }
    });
  </script>
  <link rel="manifest" href="manifest.json">
  <meta name="theme-color" content="#00BFA5">
  <script>
    if ('serviceWorker' in navigator) {
      window.addEventListener('load', () => {
        navigator.serviceWorker.register('sw.js')
          .then((reg) => console.log('SW registered:', reg))
          .catch((err) => console.log('SW failed:', err));
      });
    }
  </script>
  <link rel="shortcut icon" href="/img/favicon.ico" type="image/ico">
  <link rel="stylesheet" href="lib/jquery-ui/jquery-ui.css">
  <link rel="stylesheet" href="lib/Hover/hover.css">
  <link rel="stylesheet" href="lib/jquery-toggles/toggles-full.css">
  <link rel="stylesheet" href="lib/jquery.gritter/jquery.gritter.css">
  <link rel="stylesheet" href="lib/animate.css/animate.css">
  <!-- Font Awesome 6 (CDN) -->
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.7.2/css/all.min.css"
    integrity="sha512-Evv84Mr4kqVGRNSgIGL/F/aIDqQb7xQ2vcrdIwxfjThSH8CSR7PBEakCr51Ck+w+/U6swU2Im1vVX0SVk9ABhg=="
    crossorigin="anonymous" referrerpolicy="no-referrer" />
  <!-- Font Awesome 4 compatibility shim -->
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.7.2/css/v4-shims.min.css"
    crossorigin="anonymous" referrerpolicy="no-referrer" />
  <link rel="stylesheet" href="lib/ionicons/css/ionicons.css">
  <link rel="stylesheet" href="lib/select2/select2.css">
  <!-- Google Font: Roboto -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="skins/aetherflow.css">
  <link rel="stylesheet" href="<?php echo $theme_css; ?>">
  <link rel="stylesheet" href="skins/lobipanel.css" />
  <link rel="stylesheet" href="css/vision_pro_toggles.css">
  <!-- JAVASCRIPT -->
  <script src="lib/jquery/jquery.js"></script>
  <script src="lib/chartjs/chart.umd.js"></script>

  <!--///// BANDWIDTH CHART (Chart.js) /////-->
  <script type="text/javascript">
    $(document).ready(function () {
      var bwCanvas = document.getElementById('mainbw');
      if (!bwCanvas) return;
      var bwCtx = bwCanvas.getContext('2d');
      var bwChart = new Chart(bwCtx, {
        type: 'line',
        data: {
          labels: [],
          datasets: [{
            label: 'Upload',
            data: [],
            borderColor: '#F4B400',
            backgroundColor: 'rgba(244, 180, 0, 0.15)',
            borderWidth: 1.5,
            fill: true,
            tension: 0.4,
            pointRadius: 0
          }, {
            label: 'Download',
            data: [],
            borderColor: '#D4AF37',
            backgroundColor: 'rgba(212, 175, 55, 0.15)',
            borderWidth: 1.5,
            fill: true,
            tension: 0.4,
            pointRadius: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: { duration: 300 },
          plugins: {
            legend: {
              display: true,
              position: 'top',
              labels: { color: '#acacac', font: { family: 'Roboto, sans-serif', size: 11 } }
            }
          },
          scales: {
            x: {
              display: true,
              ticks: { color: '#999', font: { family: 'Roboto, sans-serif', size: 9 }, maxTicksLimit: 6 },
              grid: { color: 'rgba(255,255,255,0.05)' }
            },
            y: {
              display: true,
              beginAtZero: true,
              ticks: {
                color: '#999',
                font: { family: 'Roboto, sans-serif', size: 9 },
                callback: function (val) { return val.toFixed(1) + ' MB/s'; }
              },
              grid: { color: 'rgba(255,255,255,0.05)' }
            }
          }
        }
      });
      // Fetch bandwidth data and update chart
      function fetchBwData() {
        $.ajax({
          url: 'widgets/data.php',
          method: 'GET',
          dataType: 'json',
          success: function (series) {
            if (series && series.length >= 2) {
              // Flot format: [{label, data:[[x,y],...]}, ...]
              var uploadData = series[0] && series[0].data ? series[0].data : [];
              var downloadData = series[1] && series[1].data ? series[1].data : [];
              var labels = uploadData.map(function (pt) {
                var d = new Date(pt[0]);
                return ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2) + ':' + ('0' + d.getSeconds()).slice(-2);
              });
              bwChart.data.labels = labels;
              bwChart.data.datasets[0].data = uploadData.map(function (pt) { return pt[1]; });
              bwChart.data.datasets[1].data = downloadData.map(function (pt) { return pt[1]; });
              bwChart.update('none');
            }
            setTimeout(fetchBwData, 3000);
          },
          error: function () { setTimeout(fetchBwData, 5000); }
        });
      }
      fetchBwData();
    });
  </script>

  <!--///// CPU CHART (Chart.js) /////-->
  <script type="text/javascript">
    var cpuData = [];
    var cpuLabels = [];
    var cpuTotalPoints = 100;
    var cpuUpdateInterval = 1000;
    var cpuChart;

    function initCpuData() {
      var now = new Date();
      for (var i = cpuTotalPoints; i > 0; i--) {
        var t = new Date(now.getTime() - i * cpuUpdateInterval);
        cpuLabels.push(('0' + t.getHours()).slice(-2) + ':' + ('0' + t.getMinutes()).slice(-2) + ':' + ('0' + t.getSeconds()).slice(-2));
        cpuData.push(0);
      }
    }

    function getCpuData() {
      $.ajax({
        url: 'widgets/cpu.php',
        dataType: 'json',
        cache: false,
        success: function (_data) {
          cpuData.shift();
          cpuLabels.shift();
          var now = new Date();
          cpuLabels.push(('0' + now.getHours()).slice(-2) + ':' + ('0' + now.getMinutes()).slice(-2) + ':' + ('0' + now.getSeconds()).slice(-2));
          cpuData.push(_data.cpu);
          cpuChart.data.labels = cpuLabels;
          cpuChart.data.datasets[0].data = cpuData;
          cpuChart.data.datasets[0].label = 'CPU: ' + _data.cpu + '%';
          cpuChart.update('none');
          setTimeout(getCpuData, cpuUpdateInterval);
        },
        error: function () { setTimeout(getCpuData, cpuUpdateInterval * 3); }
      });
    }

    $(document).ready(function () {
      var cpuCanvas = document.getElementById('flot-placeholder1');
      if (!cpuCanvas) return;
      initCpuData();
      var cpuCtx = cpuCanvas.getContext('2d');
      cpuChart = new Chart(cpuCtx, {
        type: 'line',
        data: {
          labels: cpuLabels,
          datasets: [{
            label: 'CPU: 0%',
            data: cpuData,
            borderColor: '#F4B400',
            backgroundColor: 'rgba(244, 180, 0, 0.15)',
            borderWidth: 1.5,
            fill: true,
            tension: 0.3,
            pointRadius: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: { duration: 200 },
          plugins: {
            legend: {
              display: true,
              position: 'top',
              labels: { color: '#acacac', font: { family: 'Roboto, sans-serif', size: 11 } }
            }
          },
          scales: {
            x: {
              display: true,
              ticks: { color: '#999', font: { family: 'Roboto, sans-serif', size: 9 }, maxTicksLimit: 6 },
              grid: { color: 'rgba(255,255,255,0.05)' }
            },
            y: {
              display: true,
              min: 0,
              max: 100,
              ticks: {
                color: '#999',
                font: { family: 'Roboto, sans-serif', size: 9 },
                stepSize: 10,
                callback: function (val) { return val + '%'; }
              },
              grid: { color: 'rgba(255,255,255,0.05)' }
            }
          }
        }
      });
      setTimeout(getCpuData, cpuUpdateInterval);
    });
  </script>

  <!-- <script type="text/javascript" src="inc/panel.app_status.ajax.js"></script> -->
  <script type="text/javascript" src="js/service_monitor.js"></script>

  <script type="text/javascript">
    $(document).ready(function () { getJSONData(); });
    var OutSpeed2 = <?php echo floor($NetOutSpeed[2]) ?>;
    var OutSpeed3 = <?php echo floor($NetOutSpeed[3]) ?>;
    var OutSpeed4 = <?php echo floor($NetOutSpeed[4]) ?>;
    var OutSpeed5 = <?php echo floor($NetOutSpeed[5]) ?>;
    var InputSpeed2 = <?php echo floor($NetInputSpeed[2]) ?>;
    var InputSpeed3 = <?php echo floor($NetInputSpeed[3]) ?>;
    var InputSpeed4 = <?php echo floor($NetInputSpeed[4]) ?>;
    var InputSpeed5 = <?php echo floor($NetInputSpeed[5]) ?>;
    function getJSONData() {
      setTimeout("getJSONData()", 1000);
      $.getJSON('?act=rt&callback=?', displayData);
    }
    function ForDight(Dight, How) {
      if (Dight < 0) {
        var Last = 0 + "B/s";
      } else if (Dight < 1024) {
        var Last = Math.round(Dight * Math.pow(10, How)) / Math.pow(10, How) + "B/s";
      } else if (Dight < 1048576) {
        Dight = Dight / 1024;
        var Last = Math.round(Dight * Math.pow(10, How)) / Math.pow(10, How) + "KB/s";
      } else {
        Dight = Dight / 1048576;
        var Last = Math.round(Dight * Math.pow(10, How)) / Math.pow(10, How) + "MB/s";
      }
      return Last;
    }
    function displayData(dataJSON) {
      $("#NetOut2").html(dataJSON.NetOut2);
      $("#NetOut3").html(dataJSON.NetOut3);
      $("#NetOut4").html(dataJSON.NetOut4);
      $("#NetOut5").html(dataJSON.NetOut5);
      $("#NetOut6").html(dataJSON.NetOut6);
      $("#NetOut7").html(dataJSON.NetOut7);
      $("#NetOut8").html(dataJSON.NetOut8);
      $("#NetOut9").html(dataJSON.NetOut9);
      $("#NetOut10").html(dataJSON.NetOut10);
      $("#NetInput2").html(dataJSON.NetInput2);
      $("#NetInput3").html(dataJSON.NetInput3);
      $("#NetInput4").html(dataJSON.NetInput4);
      $("#NetInput5").html(dataJSON.NetInput5);
      $("#NetInput6").html(dataJSON.NetInput6);
      $("#NetInput7").html(dataJSON.NetInput7);
      $("#NetInput8").html(dataJSON.NetInput8);
      $("#NetInput9").html(dataJSON.NetInput9);
      $("#NetInput10").html(dataJSON.NetInput10);
      $("#NetOutSpeed2").html(ForDight((dataJSON.NetOutSpeed2 - OutSpeed2), 3)); OutSpeed2 = dataJSON.NetOutSpeed2;
      $("#NetOutSpeed3").html(ForDight((dataJSON.NetOutSpeed3 - OutSpeed3), 3)); OutSpeed3 = dataJSON.NetOutSpeed3;
      $("#NetOutSpeed4").html(ForDight((dataJSON.NetOutSpeed4 - OutSpeed4), 3)); OutSpeed4 = dataJSON.NetOutSpeed4;
      $("#NetOutSpeed5").html(ForDight((dataJSON.NetOutSpeed5 - OutSpeed5), 3)); OutSpeed5 = dataJSON.NetOutSpeed5;
      $("#NetInputSpeed2").html(ForDight((dataJSON.NetInputSpeed2 - InputSpeed2), 3)); InputSpeed2 = dataJSON.NetInputSpeed2;
      $("#NetInputSpeed3").html(ForDight((dataJSON.NetInputSpeed3 - InputSpeed3), 3)); InputSpeed3 = dataJSON.NetInputSpeed3;
      $("#NetInputSpeed4").html(ForDight((dataJSON.NetInputSpeed4 - InputSpeed4), 3)); InputSpeed4 = dataJSON.NetInputSpeed4;
      $("#NetInputSpeed5").html(ForDight((dataJSON.NetInputSpeed5 - InputSpeed5), 3)); InputSpeed5 = dataJSON.NetInputSpeed5;
    }
  </script>

  <!-- Legacy IE shims removed — targeting modern browsers only -->

  <style>
    #sysPre {
      max-height: 600px;
      overflow-y: scroll;
    }

    .legend>table {
      background-color: transparent !important;
      color: #acacac !important;
      font-size: 11px !important;
    }
  </style>

  <style>
    <?php include('custom/custom.css'); ?>
  </style>

</head>
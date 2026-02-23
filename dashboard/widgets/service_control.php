<?php
include('../inc/config.php');
include('../inc/card.header.php');
include('../inc/card.menu.php');
?>

<!--SERVICE CONTROL CENTER-->
<div class="card card-inverse">
  <div class="card-header">
    <h4 class="card-title"><?php echo T('SERVICE_CONTROL_CENTER'); ?></h4>
  </div>
  <div class="card-body" style="padding: 0">
    <div class="table-responsive">
      <table class="table table-hover nomargin" style="font-size:14px">
        <thead>
          <tr>
            <th class="text-center"><?php echo T('SERVICE_STATUS'); ?></th>
            <th class="text-center"><?php echo T('RESTART_SERVICES'); ?></th>
            <!-- Disabled column removed as it is now integrated into Status/Toggle -->
            <!-- <th class="text-center"><?php echo T('ENABLE_DISABLE_SERVICES'); ?></th> -->
            <th class="text-center"><?php echo T('LOGS'); ?></th>
          </tr>
        </thead>
        <tbody>
          <?php if (file_exists("/install/.rtorrent.lock")) { ?>
            <tr>
              <?php
              $rtorrentrc = '/home/' . $username . '/.rtorrent.rc';
              if (file_exists($rtorrentrc)) {
                $rtorrentrc_data = file_get_contents($rtorrentrc);
                $scgiport = search($rtorrentrc_data, 'localhost:', "\n");
              }
              ?>
              <td>
                <div style="display:flex; align-items:center; justify-content:space-between;">
                  <span><span id="appstat_rtorrent"></span> <?php echo T('SERVICE_RTORRENT'); ?></span>
                  <?php echo "$cbodyr"; ?>
                </div>
              </td>
              <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('rtorrent')" 
                  class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
              </td>
              <td class="text-center"><a href="javascript:;" onclick="viewLogs('rtorrent')" class="btn btn-xs btn-info"><i
                    class="fa fa-file-text-o"></i></a></td>
            </tr>
          <?php } ?>

          <?php if (file_exists("/install/.autodlirssi.lock")) { ?>
            <tr>
              <td>
                <div style="display:flex; align-items:center; justify-content:space-between;">
                  <span><span id="appstat_irssi"></span> <?php echo T('SERVICE_IRSSI'); ?> </span>
                  <?php echo "$cbodyi"; ?>
                </div>
              </td>
              <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('irssi')" 
                  class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
              </td>
              <td class="text-center"><a href="javascript:;" onclick="viewLogs('irssi')" class="btn btn-xs btn-info"><i
                    class="fa fa-file-text-o"></i></a></td>
            </tr>
          <?php } ?>

          <?php if (file_exists("/install/.deluge.lock")) { ?>
            <tr>
              <td>
                <div style="display:flex; align-items:center; justify-content:space-between;">
                  <span><span id="appstat_deluged"></span> DelugeD </span>
                  <?php echo "$cbodyd"; ?>
                </div>
              </td>
              <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('deluged')" 
                  class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
              </td>
              <td class="text-center"><a href="javascript:;" onclick="viewLogs('deluged')" class="btn btn-xs btn-info"><i
                    class="fa fa-file-text-o"></i></a></td>
            </tr>
            <tr>
              <td>
                <div style="display:flex; align-items:center; justify-content:space-between;">
                  <span><span id="appstat_delugeweb"></span> Deluge Web </span>
                  <?php echo "$cbodydw"; ?>
                </div>
              </td>
              <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('delugeweb')" 
                  class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
              </td>
              <td class="text-center"><a href="javascript:;" onclick="viewLogs('delugeweb')"
                  class="btn btn-xs btn-info"><i class="fa fa-file-text-o"></i></a></td>
            </tr>
          <?php } ?>

          <?php if (file_exists("/install/.transmission.lock")) { ?>
            <tr>
              <td>
                <div style="display:flex; align-items:center; justify-content:space-between;">
                  <span><span id="appstat_transmission"></span> Transmission </span>
                  <?php echo "$cbodytr"; ?>
                </div>
              </td>
              <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('transmission')" 
                  class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
              </td>
              <td class="text-center"><a href="javascript:;" onclick="viewLogs('transmission')"
                  class="btn btn-xs btn-info"><i class="fa fa-file-text-o"></i></a></td>
            </tr>
          <?php } ?>

          <?php if (file_exists("/install/.qbittorrent.lock")) { ?>
            <tr>
              <td>
                <div style="display:flex; align-items:center; justify-content:space-between;">
                  <span><span id="appstat_qbittorrent"></span> qBittorrent </span>
                  <?php echo "$cbodyqb"; ?>
                </div>
              </td>
              <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('qbittorrent')" 
                  class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
              </td>
              <td class="text-center"><a href="javascript:;" onclick="viewLogs('qbittorrent')"
                  class="btn btn-xs btn-info"><i class="fa fa-file-text-o"></i></a></td>
            </tr>
          <?php } ?>

          <?php if (isAdmin()) { ?>

            <tr>
              <td>
                <div style="display:flex; align-items:center; justify-content:space-between;">
                  <span><span id="appstat_webconsole"></span> Web Console </span>
                  <?php echo "$wcbodyb"; ?>
                </div>
              </td>
              <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('shellinabox')" 
                  class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
              </td>
            </tr>

            <?php if (file_exists("/install/.btsync.lock")) { ?>
              <tr>
                <td>
                  <div style="display:flex; align-items:center; justify-content:space-between;">
                    <span><span id="appstat_btsync"></span> BTSync </span>
                    <?php echo "$cbodyb"; ?>
                  </div>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('btsync')" 
                    class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="viewLogs('btsync')" class="btn btn-xs btn-info"><i
                      class="fa fa-file-text-o"></i></a></td>
              </tr>
            <?php } ?>

            <?php if (file_exists("/install/.couchpotato.lock")) { ?>
              <tr>
                <td>
                  <div style="display:flex; align-items:center; justify-content:space-between;">
                    <span><span id="appstat_couchpotato"></span> CouchPotato </span>
                    <?php echo "$cbodycp"; ?>
                  </div>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('couchpotato')" 
                    class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="viewLogs('couchpotato')"
                    class="btn btn-xs btn-info"><i class="fa fa-file-text-o"></i></a></td>
              </tr>
            <?php } ?>

            <?php if (file_exists("/install/.emby.lock")) { ?>
              <tr>
                <td>
                  <div style="display:flex; align-items:center; justify-content:space-between;">
                    <span><span id="appstat_emby"></span> Emby </span>
                    <?php echo "$cbodye"; ?>
                  </div>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('emby')" 
                    class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="viewLogs('emby')" class="btn btn-xs btn-info"><i
                      class="fa fa-file-text-o"></i></a></td>
              </tr>
            <?php } ?>

            <?php if (file_exists("/install/.headphones.lock")) { ?>
              <tr>
                <td>
                  <div style="display:flex; align-items:center; justify-content:space-between;">
                    <span><span id="appstat_headphones"></span> Headphones </span>
                    <?php echo "$cbodyhp"; ?>
                  </div>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('headphones')" 
                    class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="viewLogs('headphones')"
                    class="btn btn-xs btn-info"><i class="fa fa-file-text-o"></i></a></td>
              </tr>
            <?php } ?>

            <?php if (file_exists("/install/.jackett.lock")) { ?>
              <tr>
                <td>
                  <div style="display:flex; align-items:center; justify-content:space-between;">
                    <span><span id="appstat_jackett"></span> Jackett </span>
                    <?php echo "$cbodyj"; ?>
                  </div>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('jackett')" 
                    class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="viewLogs('jackett')" class="btn btn-xs btn-info"><i
                      class="fa fa-file-text-o"></i></a></td>
              </tr>
            <?php } ?>

            <?php if (file_exists("/install/.lidarr.lock")) { ?>
              <tr>
                <td>
                  <div style="display:flex; align-items:center; justify-content:space-between;">
                    <span><span id="appstat_lidarr"></span> Lidarr </span>
                    <?php echo "$cbodylid"; ?>
                  </div>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('lidarr')" 
                    class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="viewLogs('lidarr')" class="btn btn-xs btn-info"><i
                      class="fa fa-file-text-o"></i></a></td>
              </tr>
            <?php } ?>

            <?php if (file_exists("/install/.medusa.lock")) { ?>
              <tr>
                <td>
                  <div style="display:flex; align-items:center; justify-content:space-between;">
                    <span><span id="appstat_medusa"></span> Medusa </span>
                    <?php echo "$cbodym"; ?>
                  </div>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('medusa')" 
                    class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="viewLogs('medusa')" class="btn btn-xs btn-info"><i
                      class="fa fa-file-text-o"></i></a></td>
              </tr>
            <?php } ?>

            <?php if (file_exists("/install/.nzbget.lock")) { ?>
              <tr>
                <td>
                  <div style="display:flex; align-items:center; justify-content:space-between;">
                    <span><span id="appstat_nzbget"></span> NZBGet </span>
                    <?php echo "$cbodynzg"; ?>
                  </div>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('nzbget')" 
                    class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="viewLogs('nzbget')" class="btn btn-xs btn-info"><i
                      class="fa fa-file-text-o"></i></a></td>
              </tr>
            <?php } ?>

            <?php if (file_exists("/install/.nzbhydra.lock")) { ?>
              <tr>
                <td>
                  <div style="display:flex; align-items:center; justify-content:space-between;">
                    <span><span id="appstat_nzbhydra"></span> NZBHydra </span>
                    <?php echo "$cbodynzb"; ?>
                  </div>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('nzbhydra')" 
                    class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="viewLogs('nzbhydra')" class="btn btn-xs btn-info"><i
                      class="fa fa-file-text-o"></i></a></td>
              </tr>
            <?php } ?>

            <?php if (file_exists("/install/.ombi.lock")) { ?>
              <tr>
                <td>
                  <div style="display:flex; align-items:center; justify-content:space-between;">
                    <span><span id="appstat_ombi"></span> Ombi </span>
                    <?php echo "$cbodypr"; ?>
                  </div>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('ombi')" 
                    class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="viewLogs('ombi')" class="btn btn-xs btn-info"><i
                      class="fa fa-file-text-o"></i></a></td>
              </tr>
            <?php } ?>

            <?php if (file_exists("/install/.plex.lock")) { ?>
              <tr>
                <td>
                  <div style="display:flex; align-items:center; justify-content:space-between;">
                    <span><span id="appstat_plex"></span> Plex </span>
                    <?php echo "$cbodyp"; ?>
                  </div>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('plex')" 
                    class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="viewLogs('plex')" class="btn btn-xs btn-info"><i
                      class="fa fa-file-text-o"></i></a></td>
              </tr>
            <?php } ?>

            <?php if (file_exists("/install/.Tautulli.lock")) { ?>
              <tr>
                <td>
                  <div style="display:flex; align-items:center; justify-content:space-between;">
                    <span><span id="appstat_Tautulli"></span> Tautulli </span>
                    <?php echo "$cbodypp"; ?>
                  </div>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('Tautulli')" 
                    class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="viewLogs('tautulli')" class="btn btn-xs btn-info"><i
                      class="fa fa-file-text-o"></i></a></td>
              </tr>
            <?php } ?>

            <?php if (file_exists("/install/.pyload.lock")) { ?>
              <tr>
                <td>
                  <div style="display:flex; align-items:center; justify-content:space-between;">
                    <span><span id="appstat_pyload"></span> pyLoad </span>
                    <?php echo "$cbodypl"; ?>
                  </div>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('pyload')" 
                    class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="viewLogs('pyload')" class="btn btn-xs btn-info"><i
                      class="fa fa-file-text-o"></i></a></td>
              </tr>
            <?php } ?>

            <?php if (file_exists("/install/.radarr.lock")) { ?>
              <tr>
                <td>
                  <div style="display:flex; align-items:center; justify-content:space-between;">
                    <span><span id="appstat_radarr"></span> Radarr </span>
                    <?php echo "$cbodyrad"; ?>
                  </div>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('radarr')" 
                    class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="viewLogs('radarr')" class="btn btn-xs btn-info"><i
                      class="fa fa-file-text-o"></i></a></td>
              </tr>
            <?php } ?>

            <?php if (file_exists("/install/.sabnzbd.lock")) { ?>
              <tr>
                <td>
                  <div style="display:flex; align-items:center; justify-content:space-between;">
                    <span><span id="appstat_sabnzbd"></span> SABnzbd </span>
                    <?php echo "$cbodysz"; ?>
                  </div>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('sabnzbd')" 
                    class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="viewLogs('sabnzbd')" class="btn btn-xs btn-info"><i
                      class="fa fa-file-text-o"></i></a></td>
              </tr>
            <?php } ?>

            <?php if (file_exists("/install/.sickgear.lock")) { ?>
              <tr>
                <td>
                  <div style="display:flex; align-items:center; justify-content:space-between;">
                    <span><span id="appstat_sickgear"></span> SickGear </span>
                    <?php echo "$cbodysg"; ?>
                  </div>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('sickgear')" 
                    class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="viewLogs('sickgear')" class="btn btn-xs btn-info"><i
                      class="fa fa-file-text-o"></i></a></td>
              </tr>
            <?php } ?>

            <?php if (file_exists("/install/.sickrage.lock")) { ?>
              <tr>
                <td>
                  <div style="display:flex; align-items:center; justify-content:space-between;">
                    <span><span id="appstat_sickrage"></span> SickRage </span>
                    <?php echo "$cbodysr"; ?>
                  </div>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('sickrage')" 
                    class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="viewLogs('sickrage')" class="btn btn-xs btn-info"><i
                      class="fa fa-file-text-o"></i></a></td>
              </tr>
            <?php } ?>

            <?php if (file_exists("/install/.sonarr.lock")) { ?>
              <tr>
                <td>
                  <div style="display:flex; align-items:center; justify-content:space-between;">
                    <span><span id="appstat_sonarr"></span> Sonarr </span>
                    <?php echo "$cbodys"; ?>
                  </div>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('sonarr')" 
                    class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="viewLogs('sonarr')" class="btn btn-xs btn-info"><i
                      class="fa fa-file-text-o"></i></a></td>
              </tr>
            <?php } ?>

            <?php if (file_exists("/install/.subsonic.lock")) { ?>
              <tr>
                <td>
                  <div style="display:flex; align-items:center; justify-content:space-between;">
                    <span><span id="appstat_subsonic"></span> Subsonic </span>
                    <?php echo "$cbodyss"; ?>
                  </div>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('subsonic')" 
                    class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="viewLogs('subsonic')" class="btn btn-xs btn-info"><i
                      class="fa fa-file-text-o"></i></a></td>
              </tr>
            <?php } ?>

            <?php if (file_exists("/install/.syncthing.lock")) { ?>
              <tr>
                <td>
                  <div style="display:flex; align-items:center; justify-content:space-between;">
                    <span><span id="appstat_syncthing"></span> Syncthing </span>
                    <?php echo "$cbodyst"; ?>
                  </div>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('syncthing')" 
                    class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="viewLogs('syncthing')"
                    class="btn btn-xs btn-info"><i class="fa fa-file-text-o"></i></a></td>
              </tr>
            <?php } ?>

            <?php if (file_exists("/install/.sample.lock")) { ?>
              <tr>
                <td>
                  <div style="display:flex; align-items:center; justify-content:space-between;">
                    <span><?php echo "$sampleval"; ?> SAMPLE </span>
                    <?php echo "$samplebody"; ?>
                  </div>
                </td>
                <td class="text-center"><a href="javascript:;" onclick="submitServiceStart('sample')" 
                    class="btn btn-xs btn-default"><i class="fa fa-refresh text-info"></i> <?php echo T('REFRESH'); ?></a>
                </td>
                <td class="text-center"><?php echo "$samplebody"; ?></td>
              </tr>
            <?php } ?>

          <?php } ?>
        </tbody>
      </table>
    </div><!-- table-responsive -->
  </div>
</div><!-- card -->

<!-- Service Log Modal -->
<div class="modal fade" id="serviceLogModal" tabindex="-1" role="dialog" aria-labelledby="serviceLogModalLabel">
  <div class="modal-dialog modal-lg" role="document">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-label="Close"><span
            aria-hidden="true">&times;</span></button>
        <h4 class="modal-title" id="serviceLogModalLabel"><?php echo T('LOGS'); ?>: <span id="logServiceTitle"></span>
        </h4>
      </div>
      <div class="modal-body">
        <pre id="serviceLogContent"
          style="height: 400px; overflow-y: scroll; background: #222; color: #fff; border: none;"></pre>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CLOSE'); ?></button>
      </div>
    </div>
  </div>
</div>

<script>
  function viewLogs(service) {
    $('#logServiceTitle').text(service);
    $('#serviceLogContent').text('<?php echo T("LOADING"); ?>');
    $('#serviceLogModal').modal('show');

    $.ajax({
      url: 'api/get_log.php',
      data: { service: service },
      dataType: 'json',
      success: function (data) {
        if (data.error) {
          $('#serviceLogContent').text('<?php echo T("ERROR"); ?>: ' + data.error);
        } else {
          $('#serviceLogContent').text(data.logs.join('\n'));
          var logDiv = document.getElementById("serviceLogContent");
          logDiv.scrollTop = logDiv.scrollHeight;
        }
      },
      error: function () {
        $('#serviceLogContent').text('<?php echo T("ERROR_FETCHING_LOGS"); ?>');
      }
    });
  }
</script>

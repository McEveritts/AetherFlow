<?php
include('../inc/config.php');
include('../inc/card.header.php');
include('../inc/card.menu.php');
?>


<!--PACKAGE MANAGEMENT CENTER-->
<div class="card card-main card-inverse">
  <div class="card-header">
    <h4 class="card-title"><?php echo T('PACKAGE_MANAGEMENT_CENTER'); ?></h4>
  </div>
  <div class="card-body text-center" style="padding:0;">
    <div class="alert alert-danger">
      <button type="button" class="close" data-bs-dismiss="alert" aria-hidden="true">&times;</button>
      <div align="center"><?php echo T('PMC_NOTICE_TXT'); ?></div>
    </div>
    <div class="table-responsive ps-container">
      <table id="dataTable1" class="table table-bordered table-striped-col" style="font-size: 12px">
        <thead>
          <tr>
            <th><?php echo T('NAME'); ?></th>
            <th><?php echo T('DETAILS'); ?></th>
            <th><?php echo T('AVAILABILITY'); ?></th>
          </tr>
        </thead>

        <tbody>
          <tr>
            <td><?php echo T('PMC_NAME_BTSYNC'); ?></td>
            <td><?php echo T('BTSYNC_DETAILS'); ?></td>
            <?php if (file_exists("/install/.btsync.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#btsyncRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a>
              </td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-btsync=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="btsyncInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_COUCHPOTATO'); ?></td>
            <td><?php echo T('COUCHPOTATO'); ?></td>
            <?php if (file_exists("/install/.couchpotato.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#couchpotatoRemovalConfirm"
                  class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a></td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-couchpotato=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="couchpotatoInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_CSF'); ?></td>
            <td><?php echo T('CSF'); ?></td>
            <?php if (file_exists("/install/.csf.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#csfRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a></td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><button data-bs-toggle="tooltip"
                  title="<?php echo T('BOX_TOOLTIP_CSF'); ?>" data-placement="top"
                  class="btn btn-xs btn-danger disabled tooltips"><?php echo T('BOX'); ?></button></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_DELUGE'); ?></td>
            <td><?php echo T('DELUGE'); ?></td>
            <?php if (file_exists("/install/.deluge.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#delugeRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a>
              </td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-deluge=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="delugeInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_EMBY'); ?></td>
            <td><?php echo T('EMBY'); ?></td>
            <?php if (file_exists("/install/.emby.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#embyRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a></td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-emby=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="embyInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_HEADPHONES'); ?></td>
            <td><?php echo T('HEADPHONES'); ?></td>
            <?php if (file_exists("/install/.headphones.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#headphonesRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a>
              </td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-headphones=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="headphonesInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_JACKETT'); ?></td>
            <td><?php echo T('JACKETT'); ?></td>
            <?php if (file_exists("/install/.jackett.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#jackettRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a>
              </td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-jackett=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="jackettInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_LIDARR'); ?></td>
            <td><?php echo T('LIDARR'); ?></td>
            <?php if (file_exists("/install/.lidarr.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#lidarrRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a>
              </td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-lidarr=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="lidarrInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_MEDUSA'); ?></td>
            <td><?php echo T('MEDUSA'); ?></td>
            <?php if (file_exists("/install/.medusa.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#medusaRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a>
              </td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-medusa=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="medusaInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_NEXTCLOUD'); ?></td>
            <td><?php echo T('NEXTCLOUD'); ?></td>
            <?php if (file_exists("/install/.nextcloud.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#nextcloudRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a>
              </td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><button data-bs-toggle="tooltip"
                  title="<?php echo T('BOX_TOOLTIP_NEXTCLOUD'); ?>" data-placement="top"
                  class="btn btn-xs btn-danger disabled tooltips"><?php echo T('BOX'); ?></button></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_NZBGET'); ?></td>
            <td><?php echo T('NZBGET'); ?></td>
            <?php if (file_exists("/install/.nzbget.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#nzbgetRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a>
              </td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-nzbget=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="nzbgetInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_NZBHYDRA'); ?></td>
            <td><?php echo T('NZBHYDRA'); ?></td>
            <?php if (file_exists("/install/.nzbhydra.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#nzbhydraRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a>
              </td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-nzbhydra=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="nzbhydraInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_OMBI'); ?></td>
            <td><?php echo T('OMBI'); ?></td>
            <?php if (file_exists("/install/.ombi.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#ombiRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a></td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-ombi=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="ombiInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_OPENVPN'); ?></td>
            <td><?php echo T('OVPN'); ?></td>
            <?php if (file_exists("/install/.vpn.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><button data-bs-toggle="tooltip"
                  title="<?php echo T('OVPN_TOOLTIP_U'); ?>" data-placement="top"
                  class="btn btn-xs btn-success disabled tooltips"><?php echo T('CLI'); ?></button></td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><button data-bs-toggle="tooltip"
                  title="<?php echo T('OVPN_TOOLTIP_I'); ?>" data-placement="top"
                  class="btn btn-xs btn-danger disabled tooltips"><?php echo T('CLI'); ?></button></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_PLEX'); ?></td>
            <td><?php echo T('PLEX'); ?></td>
            <?php if (file_exists("/install/.plex.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#plexRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a></td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-plex=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="plexInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_PYLOAD'); ?></td>
            <td><?php echo T('PYLOAD'); ?></td>
            <?php if (file_exists("/install/.pyload.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#pyloadRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a>
              </td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-pyload=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="pyloadInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_QUASSEL'); ?></td>
            <td><?php echo T('QUASSEL'); ?></td>
            <?php if (file_exists("/install/.quassel.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#quasselRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a>
              </td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-quassel=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="quasselInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_QUOTAS'); ?></td>
            <td><?php echo T('QUOTAS'); ?></td>
            <?php if (file_exists("/install/.quota.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#quotaRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a></td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-quota=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="quotaInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_RADARR'); ?></td>
            <td><?php echo T('RADARR'); ?></td>
            <?php if (file_exists("/install/.radarr.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#radarrRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a>
              </td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-radarr=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="radarrInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_RAPIDLEECH'); ?></td>
            <td><?php echo T('RAPIDLEECH'); ?></td>
            <?php if (file_exists("/install/.rapidleech.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#rapidleechRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a>
              </td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-rapidleech=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="rapidleechInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_SABNZBD'); ?></td>
            <td><?php echo T('SABNZBD'); ?></td>
            <?php if (file_exists("/install/.sabnzbd.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#sabnzbdRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a>
              </td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-sabnzbd=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="sabnzbdInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_SICKGEAR'); ?></td>
            <td><?php echo T('SICKGEAR'); ?></td>
            <?php if (file_exists("/install/.sickgear.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#sickgearRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a>
              </td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-sickgear=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="sickgearInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_SICKRAGE'); ?></td>
            <td><?php echo T('SICKRAGE'); ?></td>
            <?php if (file_exists("/install/.sickrage.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#sickrageRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a>
              </td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-sickrage=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="sickrageInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_SONARR'); ?></td>
            <td><?php echo T('SONARR'); ?></td>
            <?php if (file_exists("/install/.sonarr.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#sonarrRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a>
              </td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-sonarr=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="sonarrInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_SUBSONIC'); ?></td>
            <td><?php echo T('SUBSONIC'); ?></td>
            <?php if (file_exists("/install/.subsonic.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#subsonicRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a>
              </td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-subsonic=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="subsonicInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_SYNCTHING'); ?></td>
            <td><?php echo T('SYNCTHING'); ?></td>
            <?php if (file_exists("/install/.syncthing.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#syncthingRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a>
              </td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-syncthing=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="syncthingInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_TAUTULLI'); ?></td>
            <td><?php echo T('TAUTULLI'); ?></td>
            <?php if (file_exists("/install/.Tautulli.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#TautulliRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a>
              </td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-Tautulli=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="TautulliInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_TRANSMISSION'); ?></td>
            <td><?php echo T('TRANSMISSION'); ?></td>
            <?php if (file_exists("/install/.transmission.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#transmissionRemovalConfirm"
                  class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a></td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-transmission=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="transmissionInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_QBITTORRENT'); ?></td>
            <td><?php echo T('QBITTORRENT'); ?></td>
            <?php if (file_exists("/install/.qbittorrent.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#qbittorrentRemovalConfirm"
                  class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a></td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-qbittorrent=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="qbittorrentInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_X2GO'); ?></td>
            <td><?php echo T('X2GO'); ?></td>
            <?php if (file_exists("/install/.x2go.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#x2goRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a></td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><a href="?installpackage-x2go=true"
                  data-bs-toggle="modal" data-bs-target="#sysResponse" id="x2goInstall"
                  class="btn btn-xs btn-default"><?php echo T('INSTALL'); ?></a></td>
            <?php } ?>
          </tr>
          <tr>
            <td><?php echo T('PMC_NAME_ZNC'); ?></td>
            <td><?php echo T('ZNC'); ?></td>
            <?php if (file_exists("/install/.znc.lock")) { ?>
              <td style="vertical-align: middle; text-align: center"><a href="javascript:void()" data-bs-toggle="modal"
                  data-bs-target="#zncRemovalConfirm" class="btn btn-xs btn-success"><?php echo T('INSTALLED'); ?></a></td>
            <?php } else { ?>
              <td style="vertical-align: middle; text-align: center"><button data-bs-toggle="tooltip"
                  title="<?php echo T('BOX_TOOLTIP_ZNC'); ?>" data-placement="top"
                  class="btn btn-xs btn-danger disabled tooltips"><?php echo T('BOX'); ?></button></td>
            <?php } ?>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</div><!-- package center card -->
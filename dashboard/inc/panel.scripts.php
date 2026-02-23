</section>

<!-- BTSYNC UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="btsyncRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="BTSyncRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="BTSyncRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> BTSync?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_BTSYNC_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-btsync=true" id="btsyncRemove" class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- CSF UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="csfRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="CSFRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="CSFRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> Config Server Firewall?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_CSF_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-csf=true" id="csfRemove" class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- COUCHPOTATO UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="couchpotatoRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="CouchPotatoRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="CouchPotatoRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> CouchPotato?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_COUCHPOTATO_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-couchpotato=true" id="couchpotatoRemove"
          class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- DELUGE UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="delugeRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="DelugeRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="DelugeRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> Deluge?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_DELUGE_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-deluge=true" id="delugeRemove" class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- EMBY UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="embyRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="EmbyRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="EmbyRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> Emby-Server?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_EMBY_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-emby=true" id="embyRemove" class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- HEADPHONES UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="headphonesRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="HeadphonesRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="HeadphonesRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> Headphones?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_HEADPHONES_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-headphones=true" id="headphonesRemove"
          class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- Jackett UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="jackettRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="JackettRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="JackettRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> Jackett?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_JACKETT_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-jackett=true" id="jackettRemove" class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- LIDARR UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="lidarrRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="LidarrRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="LidarrRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> Lidarr?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_LIDARR_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-lidarr=true" id="lidarrRemove" class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- MEDUSA UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="medusaRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="MedusaRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="MedusaRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> Medusa?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_MEDUSA_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-medusa=true" id="medusaRemove" class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- NextCloud UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="nextcloudRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="NextCloudRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="NextCloudRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> NextCloud?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_NEXTCLOUD_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-nextcloud=true" id="nextcloudRemove"
          class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- NZBGet UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="nzbgetRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="NZBGetRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="NZBGetRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> NZBGet?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_NZBGET_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-nzbget=true" id="nzbgetRemove" class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- NZBHydra UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="nzbhydraRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="NZBHydraRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="NZBHydraRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> NZBHydra?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_NZBHYDRA_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-nzbhydra=true" id="nzbhydraRemove" class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- OMBI UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="ombiRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="OmbiRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="OmbiRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> Ombi?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_OMBI_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-ombi=true" id="ombiRemove" class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- PLEX UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="plexRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="PlexRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="PlexRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> Plex?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_PLEX_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-plex=true" id="plexRemove" class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- Tautulli UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="TautulliRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="TautulliRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="TautulliRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> Tautulli?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_TAUTULLI_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-Tautulli=true" id="TautulliRemove" class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- PYLOAD UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="pyloadRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="pyLoadRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="pyLoadRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> pyLoad?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_PYLOAD_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-pyload=true" id="pyloadRemove" class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- QUASSEL UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="quasselRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="quasselRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="quasselRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> Quassel?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_QUASSEL_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-quassel=true" id="quasselRemove" class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- QUOTA UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="quotaRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="quotaRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="quotaRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> Quotas?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_QUOTAS_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-quota=true" id="quotaRemove" class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- RADARR UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="radarrRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="RadarrRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="RadarrRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> Radarr?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_RADARR_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-radarr=true" id="radarrRemove" class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- RAPIDLEECH UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="rapidleechRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="RapidleechRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="RapidleechRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> Rapidleech?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_RAPIDLEECH_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-rapidleech=true" id="rapidleechRemove"
          class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- SABNZBD UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="sabnzbdRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="SABnzbdRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="SABnzbdRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> SABnzbd?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_SABNZBD_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-sabnzbd=true" id="sabnzbdRemove" class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- SICKGEAR UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="sickgearRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="SickGearRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="SickGearRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> SickGear?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_SICKGEAR_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-sickgear=true" id="sickgearRemove" class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- SICKRAGE UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="sickrageRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="SickRageRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="SickRageRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> SickRage?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_SICKRAGE_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-sickrage=true" id="sickrageRemove" class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- SONARR UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="sonarrRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="SonarrRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="SonarrRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> Sonarr-NzbDrone?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_SONARR_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-sonarr=true" id="sonarrRemove" class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- SUBSONIC UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="subsonicRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="SubsonicRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="SubsonicRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> Subsonic?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_SUBSONIC_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-subsonic=true" id="subsonicRemove" class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- SYNCTHING UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="syncthingRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="SyncthingRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="SyncthingRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> Syncthing?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_SYNCTHING_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-syncthing=true" id="syncthingRemove"
          class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- TRANSMISSION UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="transmissionRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="TransmissionRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="TransmissionRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> Transmission?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_TRANSMISSION_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-transmission=true" id="transmissionRemove"
          class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- QBITTORRENT UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="qbittorrentRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="qBittorrentRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="qBittorrentRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> qBittorrent?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_QBITTORRENT_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-qbittorrent=true" id="qbittorrentRemove"
          class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- X2GO UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="x2goRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="x2goRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="x2goRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> x2go?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_X2GO_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-x2go=true" id="x2goRemove" class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- ZNC UNINSTALL MODAL -->
<div class="modal bounceIn animated" id="zncRemovalConfirm" tabindex="-1" role="dialog"
  aria-labelledby="ZNCRemovalConfirm" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="ZNCRemovalConfirm"><?php echo T('UNINSTALL_TITLE'); ?> ZNC?</h4>
      </div>
      <div class="modal-body">
        <?php echo T('UNINSTALL_ZNC_TXT'); ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
        <a href="?removepackage-znc=true" id="zncRemove" class="btn btn-primary"><?php echo T('AGREE'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->
<!-- THEME SELECT MODAL -->
<?php $option = array();
$option[] = array('file' => 'defaulted', 'title' => 'Defaulted');
$option[] = array('file' => 'smoked', 'title' => 'Smoked');
$option[] = array('file' => 'glass', 'title' => 'Glass (Gold)');
$option[] = array('file' => 'aetherflow', 'title' => 'AetherFlow'); { ?>
  <?php foreach ($option as $theme) { ?>
    <div class="modal bounceIn animated" id="themeSelect<?php echo $theme['file'] ?>Confirm" tabindex="-1" role="dialog"
      aria-labelledby="ThemeSelect<?php echo $theme['file'] ?>Confirm" aria-hidden="true">
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
            <h4 class="modal-title" id="ThemeSelect<?php echo $theme['file'] ?>Confirm"><?php echo $theme['title'] ?></h4>
          </div>
          <div class="modal-body">
            <?php echo T('THEME_CHANGE_TXT'); ?>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-default" data-bs-dismiss="modal"><?php echo T('CANCEL'); ?></button>
            <a href="?themeSelect-<?php echo $theme['file'] ?>=true" id="themeSelect<?php echo $theme['file'] ?>Go"
              class="btn btn-primary"><?php echo T('AGREE'); ?></a>
          </div>
        </div><!-- modal-content -->
      </div><!-- modal-dialog -->
    </div><!-- modal -->
  <?php } ?>
<?php } ?>
<!-- SYSTEM RESPONSE MODAL -->
<div class="modal bounceIn animated" id="sysResponse" tabindex="-1" role="dialog" aria-labelledby="sysResponse"
  aria-hidden="true">
  <div class="modal-dialog" style="width: 600px">
    <div class="modal-content" style="background:rgba(0, 0, 0, 0.6);border:2px solid rgba(0, 0, 0, 0.2)">
      <div class="modal-header" style="background:rgba(0, 0, 0, 0.4);border:0!important">
        <h4 class="modal-title" style="color:#fff"><?php echo T('SYSTEM_RESPONSE_TITLE'); ?></h4>
      </div>
      <div class="modal-body ps-container" style="background:rgba(0, 0, 0, 0.4); max-height:600px;" id="sysPre">
        <pre style="color: rgb(83, 223, 131) !important;" class="sysout ps-child"><span id="sshoutput"></span></pre>
      </div>
      <div class="modal-footer" style="background:rgba(0, 0, 0, 0.4);border:0!important">
        <a href="?clean_log=true" class="btn btn-xs btn-danger"><?php echo T('CLOSE_REFRESH'); ?></a>
      </div>
    </div><!-- modal-content -->
  </div><!-- modal-dialog -->
</div><!-- modal -->

<!-- VERSION UPDATE CHECK MODAL (Visual placeholder — no API dependency) -->
<div class="modal bounceIn animated" id="versionChecker" tabindex="-1" role="dialog" aria-labelledby="VersionChecker"
  aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-bs-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="VersionChecker">System Updates</h4>
      </div>
      <div class="modal-body">
        <p>The AetherFlow update system is being redesigned.</p>
        <p class="text-muted">A new release-based update mechanism is coming soon. Stay tuned!</p>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-bs-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>


<!--script src="js/script.js"></script-->
<script src="lib/jquery-ui/jquery-ui.js"></script>
<script src="lib/jquery.ui.touch-punch.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"
  crossorigin="anonymous"></script>
<script src="lib/jquery-toggles/toggles.js"></script>
<script src="lib/jquery-knob/jquery.knob.js"></script>
<script src="lib/jquery.gritter/jquery.gritter.js"></script>
<script src="js/aetherflow.js"></script>
<script src="js/notifications.js"></script>
<script src="js/csrf-interceptor.js"></script>
<script src="js/lobipanel.js"></script>
<script>
  $(function () {
    // Phase 23: Drag and Drop Dashboard
    // Initialize sortable on the columns containing panels
    $('.col-md-8, .col-md-4').sortable({
      connectWith: '.col-md-8, .col-md-4',
      handle: '.card-heading',
      placeholder: 'card-placeholder',
      forcePlaceholderSize: true,
      opacity: 0.8,
      stop: function (event, ui) {
        // Future: Save order via API
        // var order = $(this).sortable('toArray');
        console.log('Dashboard layout updated');
      }
    });

    $('.card').lobiPanel({
      reload: {
        icon: 'fa fa-refresh'
      },
      unpin: {
        icon: 'fa fa-arrows'
      },
      minimize: {
        icon: 'fa fa-chevron-up',
        icon2: 'fa fa-chevron-down'
      },
      close: {
        icon: 'fa fa-times-circle'
      },
      expand: {
        icon: 'fa fa-expand',
        icon2: 'fa fa-compress'
      },
      dropdown: {
        icon: 'fa fa-cog'
      },
      close: false,
      save: true,
      sortable: true,
      stateful: true,
      draggable: true,
      reload: false,
      resize: true,
      editTitle: false,
      expand: false
    });
  });
</script>

<script>
  $(function () {
    $('#rutorrent').on('loaded.lobiPanel', function (ev, lobiPanel) {
      var $body = lobiPanel.$el.find('.card-body');
      $body.html('<div>' + $body.html() + '</div>');
    });
  });
</script>

<script src="js/jquery.scrollbar.js"></script>
<script>
  $(function () {
    $('.leftpanel').perfectScrollbar();
    $('.leftpanel').perfectScrollbar({ wheelSpeed: 1, wheelPropagation: true, minScrollbarLength: 20 });
    $('.leftpanel').perfectScrollbar('update');
    //$('.body').perfectScrollbar();
    //$('.body').perfectScrollbar({ wheelSpeed: 1, wheelPropagation: true, swipePropagation: true, minScrollbarLength: 20 });
    //$('.body').perfectScrollbar('update');
    $('.modal-body').perfectScrollbar();
    $('.modal-body').perfectScrollbar({ wheelSpeed: 1, wheelPropagation: true, minScrollbarLength: 20 });
    $('.modal-body').perfectScrollbar('update');
    $('.sysout').perfectScrollbar();
    $('.sysout').perfectScrollbar({ wheelSpeed: 1, wheelPropagation: true, minScrollbarLength: 20 });
    $('.sysout').perfectScrollbar('update');
  });
</script>
<script>
  $(function () {
    // Toggles
    $('.toggle-en').toggles({
      on: true,
      height: 26,
      width: 100,
      text: {
        on: "<?php echo T('ENABLED') ?>"
      }
    });
    $('.toggle-dis').toggles({
      on: false,
      height: 26,
      width: 100,
      text: {
        off: "<?php echo T('DISABLED') ?>"
      }
    });
    $('.toggle-pen').toggles({
      on: true,
      height: 16,
      width: 90,
      text: {
        on: "<?php echo T('INSTALLED') ?>",
        off: "<?php echo T('UNINSTALLING') ?>"
      }
    });
    $('.toggle-pdis').toggles({
      on: false,
      height: 16,
      width: 90,
      text: {
        off: "<?php echo T('UNINSTALLED') ?>",
        on: "<?php echo T('INSTALLING') ?>"
      }
    });
  });
</script>
<script>
  $(document).ready(function () {

    'use strict';

    // BTSyncRemove
    $('#btsyncRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> BTSync',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> Bittorrent Sync <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // csfRemove
    $('#csfRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> CSF',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> Config Server Firewall <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // CouchPotatoRemove
    $('#couchpotatoRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> CouchPotato',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> CouchPotato <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // DelugeRemove
    $('#delugeRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> Deluge',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> Deluge <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // EmbyRemove
    $('#embyRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> Emby-Server',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> Emby-Server <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // HeadphonesRemove
    $('#headphonesRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> Headphones',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> Headphones <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // JackettRemove
    $('#jackettRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> Jackett',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> Jackett <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // LidarrRemove
    $('#lidarrRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> Lidarr',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> Lidarr <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // MedusaRemove
    $('#medusaRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> Medusa',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> Medusa <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // NextCloudRemove
    $('#nextcloudRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> NextCloud',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> NextCloud <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // NZBGetRemove
    $('#nzbgetRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> NZBGet',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> NZBGet <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // NZBHydraRemove
    $('#nzbhydraRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> NZBHydra',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> NZBHydra <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // OmbiRemove
    $('#ombiRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> Ombi',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> Ombi <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // PlexRemove
    $('#plexRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> Plex',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> Plex Media Server <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // TautulliRemove
    $('#TautulliRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> Tautulli',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> Tautulli <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // pyLoadRemove
    $('#pyloadRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> pyLoad',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> pyLoad <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // RadarrRemove
    $('#radarrRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> Radarr',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> Radarr <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // RapidleechRemove
    $('#rapidleechRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> Rapidleech',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> Rapidleech <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // SABnzbdRemove
    $('#sabnzbdRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> SABnzbd',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> SABnzbd <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // SickGearRemove
    $('#sickgearRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> SickGear',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> SickGear <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // SickRageRemove
    $('#sickrageRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> SickRage',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> SickRage <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // SonarrRemove
    $('#sonarrRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> Sonarr',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> Sonarr-NzbDrone <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // SubsonicRemove
    $('#subsonicRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> Subsonic',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> Subsonic <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // SyncthingRemove
    $('#synctingRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> Syncthing',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> Sycthing <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // TransmissionRemove
    $('#transmissionRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> Transmission',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> Transmission <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // qbittorrentRemove
    $('#qbittorrentRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> qBittorrent',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> qBittorrent <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });
    // QuasselRemove
    $('#quasselRemove').click(function () {
      $.gritter.add({
        title: '<?php echo T('UNINSTALLING_TITLE'); ?> Quassel-Core',
        text: '<?php echo T('UNINSTALLING_TXT_1'); ?> Quassel <?php echo T('UNINSTALLING_TXT_2'); ?>',
        class_name: 'with-icon times-circle danger',
        sticky: true
      });
    });

  });
</script>
<script>
  // AetherFlow Form Interceptor Script
  // Replaces legacy GET links with secure POST form submissions for CSRF compatibility
  $(document).ready(function () {
    function createPostForm(actionKey, pkgName) {
      var csrfToken = document.querySelector('meta[name="csrf-token"]');
      if (!csrfToken) {
        alert('CSRF token missing');
        return;
      }
      var $form = $('<form>').attr({ method: 'POST', action: '/' });
      $form.append($('<input>').attr({ type: 'hidden', name: '_csrf_token', value: csrfToken.content }));
      $form.append($('<input>').attr({ type: 'hidden', name: actionKey, value: pkgName }));
      $('body').append($form);
      $form.submit();
    }

    $(document).on('click', 'a[href^="?installpackage-"]', function (e) {
      e.preventDefault();
      var pkg = $(this).attr('href').replace('?installpackage-', '').replace('=true', '');
      createPostForm('install_package', pkg);
    });

    $(document).on('click', 'a[href^="?removepackage-"]', function (e) {
      e.preventDefault();
      var pkg = $(this).attr('href').replace('?removepackage-', '').replace('=true', '');
      createPostForm('remove_package', pkg);
    });
  });
</script>
// QuotaRemove
$('#quotaRemove').click(function () {
$.gritter.add({
title: '<?php echo T('UNINSTALLING_TITLE'); ?> user quotas',
text: '<?php echo T('UNINSTALLING_TXT_1'); ?> Quota <?php echo T('UNINSTALLING_TXT_2'); ?>',
class_name: 'with-icon times-circle danger',
sticky: true
});
});
// x2goRemove
$('#x2goRemove').click(function () {
$.gritter.add({
title: '<?php echo T('UNINSTALLING_TITLE'); ?> x2go',
text: '<?php echo T('UNINSTALLING_TXT_1'); ?> x2go <?php echo T('UNINSTALLING_TXT_2'); ?>',
class_name: 'with-icon times-circle danger',
sticky: true
});
});
// ZNCRemove
$('#zncRemove').click(function () {
$.gritter.add({
title: 'Uninstalling ZNC',
text: '<?php echo T('UNINSTALLING_TXT_1'); ?> ZNC <?php echo T('UNINSTALLING_TXT_2'); ?>',
class_name: 'with-icon times-circle danger',
sticky: true
});
});

});
</script>

<script>
  $(document).ready(function () {
    $('#sysResponse').on('hidden.bs.modal', function () {
      location.reload();
    });
  });
</script>

<script src="lib/datatables/jquery.dataTables.js"></script>
<script src="lib/datatables-plugins/integration/bootstrap/3/dataTables.bootstrap.js"></script>
<script src="lib/select2/select2.js"></script>

<script>
  $(document).ready(function () {

    'use strict';

    $('#dataTable1').DataTable();

    var exRowTable = $('#exRowTable').DataTable({
      responsive: true,
      'fnDrawCallback': function (oSettings) {
        $('#exRowTable_paginate ul').addClass('pagination-active-success');
      },
      'ajax': 'ajax/objects.txt',
      'columns': [{
        'class': 'details-control',
        'orderable': false,
        'data': null,
        'defaultContent': ''
      },
      { 'data': 'name' },
      { 'data': 'details' },
      { 'data': 'availability' }
      ],
      'order': [[1, 'asc']]
    });

    // Add event listener for opening and closing details
    $('#exRowTable tbody').on('click', 'td.details-control', function () {
      var tr = $(this).closest('tr');
      var row = exRowTable.row(tr);

      if (row.child.isShown()) {
        // This row is already open - close it
        row.child.hide();
        tr.removeClass('shown');
      } else {
        // Open this row
        row.child(format(row.data())).show();
        tr.addClass('shown');
      }
    });

    function format(d) {
      // `d` is the original data object for the row
      return '<h4>' + d.name + '<small>' + d.details + '</small></h4>' +
        '<p class="nomargin">Nothing to see here.</p>';
    }

    // Select2
    $('select').select2({ minimumResultsForSearch: Infinity });

  });
</script>

<script>
  $(document).ready(functio n() {
    if($('#bw_tables').length) {
    $('#bw_tables').load('widgets/bw_tables.php?page=s');
  }
  });
</script>
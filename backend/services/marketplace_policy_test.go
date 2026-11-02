package services

import "testing"

func TestSharedApacheUpdatePolicy(t *testing.T) {
	for _, app := range []string{"nextcloud", "rutorrent", "organizr"} {
		if AppControlScope(app) != "shared-vhost" || ShouldPreStopOnUpdate(app) || ShouldRestartAfterUpdate(app) || ShouldApplyCallerSandbox(app) {
			t.Errorf("shared Apache ownership was not preserved for %s", app)
		}
	}
	if AppControlScope("apache2") != "service" || !ShouldPreStopOnUpdate("radarr") {
		t.Fatal("explicit daemon policy was changed")
	}
}

func TestLoopbackLaunchPolicy(t *testing.T) {
	for _, app := range []string{"maintainerr", "af-maintainerr.service", "palate", "af-palate", "kasmvnc", "af-kasmvnc", "mcvnc", "af-mcvnc"} {
		if AppBindScope(app) != "loopback" {
			t.Errorf("loopback scope missing for %s", app)
		}
	}
	if AppBindScope("sonarr") != "network" {
		t.Fatal("network app was marked loopback")
	}
}

package services

import (
	"aetherflow/db"
	"aetherflow/models"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackageLifecycleEnvironmentRequiresExplicitRemovalPurge(t *testing.T) {
	t.Setenv("DELETE_DATA", "true")
	t.Setenv("AF_PACKAGE_ACTION", "remove")
	for _, test := range []struct {
		action string
		purge  bool
		want   string
	}{
		{"remove", false, "false"}, {"remove", true, "true"}, {"install", true, "false"}, {"update", true, "false"},
	} {
		cmd := buildPackageLifecycleCommand("/fixture/installer", false, 18001, test.action, test.purge)
		values := map[string][]string{}
		for _, entry := range cmd.Env {
			key, val, _ := strings.Cut(entry, "=")
			values[key] = append(values[key], val)
		}
		if len(values["DELETE_DATA"]) != 1 || values["DELETE_DATA"][0] != test.want {
			t.Fatalf("%s purge=%v: DELETE_DATA=%v", test.action, test.purge, values["DELETE_DATA"])
		}
		if len(values["AF_PACKAGE_ACTION"]) != 1 || values["AF_PACKAGE_ACTION"][0] != test.action {
			t.Fatalf("wrong action %v", values["AF_PACKAGE_ACTION"])
		}
		if len(values["AF_APP_PORT"]) != 1 || values["AF_APP_PORT"][0] != "18001" {
			t.Fatalf("wrong port %v", values["AF_APP_PORT"])
		}
	}
}

func retentionRunner(t *testing.T, packageHandler http.HandlerFunc, hostsFailure bool) <-chan PackageRunnerRequest {
	t.Helper()
	root, err := os.MkdirTemp(os.Getenv("TMPDIR"), "af-ir-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	socket := filepath.Join(root, "r.sock")
	t.Setenv("AETHERFLOW_RUNNER_SOCK", socket)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan PackageRunnerRequest, 8)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/package", func(writer http.ResponseWriter, request *http.Request) {
		var payload PackageRunnerRequest
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Error(err)
			http.Error(writer, "invalid fixture request", http.StatusBadRequest)
			return
		}
		requests <- payload
		if packageHandler != nil {
			packageHandler(writer, request)
			return
		}
		fmt.Fprintln(writer, "[PROGRESS:95] Fixture package script completed")
	})
	mux.HandleFunc("/v1/hosts", func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(RunnerResponse{Success: !hostsFailure, Error: "fixture hosts teardown failure"})
	})
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(RunnerResponse{Success: true})
	})
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return requests
}

func TestRunPackageActionRemovalPropagatesArchiveAndTeardownFailures(t *testing.T) {
	for _, scenario := range []struct {
		name         string
		trigger      string
		purge        bool
		hostsFailure bool
		wantMessage  string
		wantActive   bool
	}{
		{"archive insert", `CREATE TRIGGER fail_retained BEFORE INSERT ON retained_app_ingress_configs BEGIN SELECT RAISE(ABORT,'fixture retained write failure'); END`, false, false, "fixture retained write failure", true},
		{"active delete", `CREATE TRIGGER fail_active_delete BEFORE DELETE ON app_ingress_configs BEGIN SELECT RAISE(ABORT,'fixture active delete failure'); END`, false, false, "fixture active delete failure", true},
		{"explicit purge", `CREATE TRIGGER fail_retained_purge BEFORE DELETE ON retained_app_ingress_configs BEGIN SELECT RAISE(ABORT,'fixture retained purge failure'); END`, true, false, "fixture retained purge failure", true},
		{"hosts teardown", "", false, true, "fixture hosts teardown failure", false},
		{"update cleanup", `CREATE TRIGGER fail_update_cleanup BEFORE DELETE ON app_updates BEGIN SELECT RAISE(ABORT,'fixture update cleanup failure'); END`, false, false, "fixture update cleanup failure", false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			setupBlueprintTestDB(t)
			clearActiveJobs()
			t.Cleanup(clearActiveJobs)
			requests := retentionRunner(t, nil, scenario.hostsFailure)
			config := models.AppIngressConfig{AppName: "maintainerr", ListenPort: 18421, PublicDomain: "custom.example.test", ExternalAccessEnabled: true}
			if err := db.SetAppIngressConfig(config); err != nil {
				t.Fatal(err)
			}
			if err := db.ArchiveAppIngressConfig(config.AppName, false); err != nil {
				t.Fatal(err)
			}
			if err := db.SetAppIngressConfig(config); err != nil {
				t.Fatal(err)
			}
			if scenario.trigger != "" {
				if _, err := db.DB.Exec(scenario.trigger); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := db.DB.Exec(`INSERT INTO app_updates(package_name,latest_version) VALUES('maintainerr','fixture')`); err != nil {
				t.Fatal(err)
			}
			var events []string
			SetPackageEventBroadcaster(func(app, action, status string, progress int, message string) {
				events = append(events, status+":"+message)
			})
			t.Cleanup(func() { SetPackageEventBroadcaster(nil) })
			RunPackageActionWithOptions("remove", "af-maintainerr.service", "removepackage-maintainerr", "", scenario.purge)
			select {
			case request := <-requests:
				if request.Action != "remove" || request.DeleteData != scenario.purge {
					t.Fatalf("wrong worker dispatch: %+v", request)
				}
			default:
				t.Fatal("actual package worker did not dispatch the fake removal script")
			}
			job := GetPackageJobInfo("af-maintainerr.service")
			if job == nil || job.Status != "failed" || job.Progress != 100 || !strings.Contains(job.LastLine, scenario.wantMessage) {
				t.Fatalf("worker fabricated removal success: %+v", job)
			}
			t.Logf("actual removal worker: status=%s progress=%d last_line=%s", job.Status, job.Progress, job.LastLine)
			for _, event := range events {
				if strings.HasPrefix(event, "uninstalled:") || strings.Contains(event, "Complete!") {
					t.Fatalf("failure emitted success: %v", events)
				}
			}
			if len(events) == 0 || !strings.HasPrefix(events[len(events)-1], "failed:") {
				t.Fatalf("failure was not broadcast: %v", events)
			}
			active, err := db.GetAppIngressConfig(config.AppName)
			if err != nil || (active != nil) != scenario.wantActive {
				t.Fatalf("unexpected rollback state: active=%+v error=%v", active, err)
			}
			var count int
			if err := db.DB.QueryRow(`SELECT COUNT(*) FROM app_updates WHERE package_name='maintainerr'`).Scan(&count); err != nil || count != 1 {
				t.Fatalf("failed teardown cleared update state: %d %v", count, err)
			}
		})
	}
}

func TestRunPackageActionRemovalFencesTrailingSaveAndRetainsLatestConfig(t *testing.T) {
	setupBlueprintTestDB(t)
	clearActiveJobs()
	t.Cleanup(clearActiveJobs)
	config := models.AppIngressConfig{AppName: "maintainerr", ListenPort: 18421, PublicDomain: "latest.example.test", ExternalAccessEnabled: true}
	if err := db.SetAppIngressConfig(config); err != nil {
		t.Fatal(err)
	}
	retentionRunner(t, func(writer http.ResponseWriter, request *http.Request) {
		if err := db.SetAppIngressConfig(config); err == nil {
			t.Error("concurrent ingress PUT bypassed actual Go worker reservation")
		}
		fmt.Fprintln(writer, "[PROGRESS:95] Fixture removal completed")
	}, false)
	SetPackageEventBroadcaster(func(app, action, status string, progress int, message string) {
		if status == "uninstalled" {
			if err := db.SetAppIngressConfig(config); err == nil {
				t.Error("trailing ingress PUT recreated active row before worker released teardown")
			}
		}
	})
	t.Cleanup(func() { SetPackageEventBroadcaster(nil) })
	RunPackageActionWithOptions("remove", "maintainerr", "removepackage-maintainerr", "", false)
	if job := GetPackageJobInfo("maintainerr"); job == nil || job.Status != "uninstalled" {
		t.Fatalf("removal worker failed: %+v", job)
	}
	if active, err := db.GetAppIngressConfig(config.AppName); err != nil || active != nil {
		t.Fatalf("active route survived teardown: %+v %v", active, err)
	}
	retained, err := db.GetRetainedAppIngressConfig(config.AppName)
	if err != nil || retained == nil || retained.ListenPort != config.ListenPort || retained.PublicDomain != config.PublicDomain || retained.TLSEnabled != config.TLSEnabled {
		t.Fatalf("worker lost reinstall settings: %+v %v", retained, err)
	}
}

func TestRunPackageActionInstallRetainedReadAndPersistErrorsFailJob(t *testing.T) {
	for _, scenario := range []string{"retained read", "ingress persist"} {
		t.Run(scenario, func(t *testing.T) {
			setupBlueprintTestDB(t)
			clearActiveJobs()
			t.Cleanup(clearActiveJobs)
			requests := retentionRunner(t, nil, false)
			config := models.AppIngressConfig{AppName: "maintainerr", ListenPort: 18421}
			if err := db.SetAppIngressConfig(config); err != nil {
				t.Fatal(err)
			}
			if err := db.ArchiveAppIngressConfig(config.AppName, false); err != nil {
				t.Fatal(err)
			}
			if scenario == "retained read" {
				if _, err := db.DB.Exec(`UPDATE retained_app_ingress_configs SET config_json='invalid-json'`); err != nil {
					t.Fatal(err)
				}
			} else if _, err := db.DB.Exec(`CREATE TRIGGER fail_install_ingress BEFORE INSERT ON app_ingress_configs BEGIN SELECT RAISE(ABORT,'fixture ingress persist failure'); END`); err != nil {
				t.Fatal(err)
			}
			RunPackageAction("install", "maintainerr", "installpackage-maintainerr", "")
			select {
			case <-requests:
			default:
				t.Fatal("actual install worker did not dispatch fake runner")
			}
			job := GetPackageJobInfo("maintainerr")
			if job == nil || job.Status != "failed" || !strings.Contains(job.LastLine, "ingress") {
				t.Fatalf("installer hid retained/read persistence error: %+v", job)
			}
			t.Logf("actual install worker: status=%s last_line=%s", job.Status, job.LastLine)
		})
	}
}

func TestBlueprintInstallerCallbacksRestoreRetainedFlagsWithMatchingOwner(t *testing.T) {
	for _, app := range []string{"maintainerr", "radarr"} {
		t.Run(app, func(t *testing.T) {
			setupBlueprintTestDB(t)
			retentionRunner(t, nil, false)
			t.Setenv("AETHERFLOW_OCCUPIED_PORTS", "")
			t.Setenv("AETHERFLOW_BASE_DOMAIN", "server.example.test")
			config := models.AppIngressConfig{AppName: app, ListenPort: 18421, PublicDomain: "", ExternalAccessEnabled: false, TLSEnabled: false}
			if err := db.SetAppIngressConfig(config); err != nil {
				t.Fatal(err)
			}
			if err := db.ArchiveAppIngressConfig(app, false); err != nil {
				t.Fatal(err)
			}
			jobID, release, err := db.ReserveAppIngressLifecycle(app, "install")
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			save := func(config models.AppIngressConfig) error {
				return db.SetAppIngressConfigForLifecycle(config, jobID, "install")
			}
			if app == "maintainerr" {
				_, err = applyPostInstallWithoutCallerRestartWithIngress(app, 18421, save)
			} else {
				_, err = applyBlueprintPostInstallWithIngress(app, 18421, save)
			}
			if err != nil {
				t.Fatalf("matching installer could not restore ingress: %v", err)
			}
			active, err := db.GetAppIngressConfig(app)
			if err != nil || active == nil || active.ListenPort != 18421 || active.PublicDomain != "" || active.ExternalAccessEnabled || active.TLSEnabled {
				t.Fatalf("retained private/TLS flags changed on reinstall: %+v %v", active, err)
			}
		})
	}
}

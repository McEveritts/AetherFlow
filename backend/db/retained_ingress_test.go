package db

import (
	"aetherflow/models"
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

func retainedIngressFixture(t *testing.T) models.AppIngressConfig {
	t.Helper()
	previous := DB
	var err error
	DB, err = sql.Open("sqlite", filepath.Join(t.TempDir(), "ingress.sqlite")+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	fixtureDB := DB
	t.Cleanup(func() {
		fixtureDB.Close()
		DB = previous
		InvalidateIngressCache()
	})
	_, err = DB.Exec(`CREATE TABLE app_ingress_configs (
		app_name TEXT PRIMARY KEY,public_domain TEXT,external_access_enabled BOOLEAN,
		listen_port INTEGER,tls_enabled BOOLEAN,created_at TEXT DEFAULT CURRENT_TIMESTAMP,
		updated_at TEXT DEFAULT CURRENT_TIMESTAMP)`)
	if err != nil {
		t.Fatal(err)
	}
	config := models.AppIngressConfig{AppName: "maintainerr", PublicDomain: "custom.example.test", ListenPort: 18421, ExternalAccessEnabled: true, TLSEnabled: false}
	if err := SetAppIngressConfig(config); err != nil {
		t.Fatal(err)
	}
	return config
}

func TestRetainedIngressArchivesLatestRowAndOnlyPurgesExplicitly(t *testing.T) {
	retainedIngressFixture(t)
	if _, err := GetAppIngressConfig("maintainerr"); err != nil {
		t.Fatal(err)
	}
	if _, err := DB.Exec(`UPDATE app_ingress_configs SET public_domain='new.example.test',listen_port=19421`); err != nil {
		t.Fatal(err)
	}
	if err := ArchiveAppIngressConfig("maintainerr", false); err != nil {
		t.Fatal(err)
	}
	active, err := GetAppIngressConfig("maintainerr")
	if err != nil || active != nil {
		t.Fatalf("active ingress survived archive: %+v %v", active, err)
	}
	retained, err := GetRetainedAppIngressConfig("maintainerr")
	if err != nil || retained == nil || retained.ListenPort != 19421 || retained.PublicDomain != "new.example.test" || !retained.ExternalAccessEnabled || retained.TLSEnabled {
		t.Fatalf("lost latest retained configuration: %+v %v", retained, err)
	}
	if err := ArchiveAppIngressConfig("maintainerr", false); err != nil {
		t.Fatal(err)
	}
	if retained, err := GetRetainedAppIngressConfig("maintainerr"); err != nil || retained == nil {
		t.Fatalf("idempotent removal lost archive: %+v %v", retained, err)
	}
	if err := ArchiveAppIngressConfig("maintainerr", true); err != nil {
		t.Fatal(err)
	}
	if retained, err := GetRetainedAppIngressConfig("maintainerr"); err != nil || retained != nil {
		t.Fatalf("explicit purge retained ingress: %+v %v", retained, err)
	}
}

func TestRetainedIngressArchiveSerializesWithConcurrentSQLiteWriter(t *testing.T) {
	retainedIngressFixture(t)
	ctx := context.Background()
	writer, err := DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.ExecContext(ctx, `BEGIN IMMEDIATE; UPDATE app_ingress_configs SET listen_port=19421,public_domain='concurrent.example.test'`); err != nil {
		t.Fatal(err)
	}
	defer writer.ExecContext(ctx, "ROLLBACK")
	started := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		close(started)
		finished <- ArchiveAppIngressConfig("maintainerr", false)
	}()
	<-started
	if _, err := writer.ExecContext(ctx, "COMMIT"); err != nil {
		t.Fatal(err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	retained, err := GetRetainedAppIngressConfig("maintainerr")
	if err != nil || retained == nil || retained.ListenPort != 19421 || retained.PublicDomain != "concurrent.example.test" {
		t.Fatalf("concurrent save was lost: %+v %v", retained, err)
	}
}

func TestRetainedIngressReservationFencesConcurrentAndTrailingSaveAliases(t *testing.T) {
	config := retainedIngressFixture(t)
	jobID, release, err := ReserveAppIngressLifecycle("maintainerr", "remove", "custom-unit.service")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, _, err := ReserveAppIngressLifecycle("af-maintainerr.service", "install"); err == nil {
		t.Fatal("overlapping alias reservation accepted")
	}
	for _, alias := range []string{"maintainerr", "af-maintainerr", "af-maintainerr.service", " Maintainerr.service ", "custom-unit.service"} {
		attempt := config
		attempt.AppName = alias
		finished := make(chan error, 1)
		go func() { finished <- SetAppIngressConfig(attempt) }()
		if err := <-finished; err == nil {
			t.Fatalf("concurrent save bypassed reservation: %s", alias)
		}
	}
	if err := ArchiveAppIngressConfigForLifecycle(config.AppName, false, "stale-job"); err == nil {
		t.Fatal("stale archive owner accepted")
	}
	if err := ArchiveAppIngressConfigForLifecycle(config.AppName, false, jobID); err != nil {
		t.Fatal(err)
	}
	if err := SetAppIngressConfig(config); err == nil {
		t.Fatal("trailing save recreated active ingress")
	}
	if err := SetAppIngressConfigForLifecycle(config, jobID, "remove"); err == nil {
		t.Fatal("removal job can create active ingress")
	}
	release()
	installID, releaseInstall, err := ReserveAppIngressLifecycle(config.AppName, "install")
	if err != nil {
		t.Fatal(err)
	}
	defer releaseInstall()
	retained, err := GetRetainedAppIngressConfig(config.AppName)
	if err != nil || retained == nil {
		t.Fatalf("missing retained ingress: %v", err)
	}
	if err := SetAppIngressConfigForLifecycle(*retained, jobID, "install"); err == nil {
		t.Fatal("stale installer callback accepted")
	}
	if err := SetAppIngressConfigForLifecycle(*retained, installID, "update"); err == nil {
		t.Fatal("wrong installer action accepted")
	}
	if err := SetAppIngressConfigForLifecycle(*retained, installID, "install"); err != nil {
		t.Fatalf("matching installer cannot restore retained settings: %v", err)
	}
	releaseInstall()
	if err := SetAppIngressConfigForLifecycle(config, installID, "install"); err == nil {
		t.Fatal("finished installer callback accepted")
	}
}

func TestRetainedIngressHonorsRustReservationsAndFailsClosed(t *testing.T) {
	config := retainedIngressFixture(t)
	if _, err := DB.Exec(`CREATE TABLE package_lifecycle_jobs(package_id TEXT,job_id TEXT,action TEXT,status TEXT,service_units TEXT);
		INSERT INTO package_lifecycle_jobs VALUES('maintainerr','rust-remove','remove','uninstalling','["af-maintainerr.service"]')`); err != nil {
		t.Fatal(err)
	}
	if err := SetAppIngressConfig(config); err == nil {
		t.Fatal("Go save bypassed Rust durable removal reservation")
	}
	if _, _, err := ReserveAppIngressLifecycle(config.AppName, "install"); err == nil {
		t.Fatal("Go lifecycle bypassed Rust reservation")
	}
	if err := ArchiveAppIngressConfigForLifecycle(config.AppName, false, "rust-remove"); err != nil {
		t.Fatal(err)
	}
	if _, err := DB.Exec(`UPDATE package_lifecycle_jobs SET job_id='rust-install',action='install',status='installing'`); err != nil {
		t.Fatal(err)
	}
	if err := SetAppIngressConfigForLifecycle(config, "rust-install", "install"); err != nil {
		t.Fatal(err)
	}
	if _, err := DB.Exec(`UPDATE package_lifecycle_jobs SET status='unknown'`); err != nil {
		t.Fatal(err)
	}
	if err := SetAppIngressConfigForLifecycle(config, "rust-install", "install"); err == nil {
		t.Fatal("unknown reservation phase did not fail closed")
	}
}

func TestRetainedIngressArchiveDeleteFailureRollsBackBothTables(t *testing.T) {
	retainedIngressFixture(t)
	if err := retainedIngressSchema(); err != nil {
		t.Fatal(err)
	}
	if _, err := DB.Exec(`CREATE TRIGGER refuse_ingress_delete BEFORE DELETE ON app_ingress_configs BEGIN SELECT RAISE(ABORT,'fixture ingress delete failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := ArchiveAppIngressConfig("maintainerr", false); err == nil || !strings.Contains(err.Error(), "fixture ingress delete failure") {
		t.Fatalf("expected archive deletion error, got %v", err)
	}
	active, err := GetAppIngressConfig("maintainerr")
	if err != nil || active == nil {
		t.Fatalf("failed archive deleted active config: %+v %v", active, err)
	}
	retained, err := GetRetainedAppIngressConfig("maintainerr")
	if err != nil || retained != nil {
		t.Fatalf("failed archive partially committed retained config: %+v %v", retained, err)
	}
}

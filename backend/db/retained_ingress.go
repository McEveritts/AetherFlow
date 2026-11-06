package db

import (
	"aetherflow/models"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

type ingressLifecycleOwner struct {
	jobID  string
	action string
}

type ingressLifecycleKey struct {
	database *sql.DB
	app      string
}

var ingressLifecycleMu sync.Mutex
var ingressLifecycleOwners = make(map[ingressLifecycleKey]ingressLifecycleOwner)

func canonicalIngressApp(app string) string {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(app)), ".service")
	switch name {
	case "af-maintainerr":
		return "maintainerr"
	case "af-palate":
		return "palate"
	case "af-kasmvnc":
		return "kasmvnc"
	case "af-mcvnc":
		return "mcvnc"
	case "deluged", "deluge-web":
		return "deluge"
	case "paperless", "paperless-webserver", "paperless-worker", "paperless-scheduler":
		return "paperless-ngx"
	case "dispatcharr-celery", "dispatcharr-celerybeat":
		return "dispatcharr"
	case "novnc-xvnc":
		return "novnc"
	case "xrdp-sesman":
		return "xrdp"
	case "node_exporter":
		return "prometheus"
	case "rclone-vfs":
		return "rclone"
	case "scrutiny-collector", "scrutiny-collector.timer":
		return "scrutiny"
	case "recyclarr.timer":
		return "recyclarr"
	}
	return name
}

func ReserveAppIngressLifecycle(app, action string, aliases ...string) (string, func(), error) {
	if action != "install" && action != "update" && action != "remove" {
		return "", nil, fmt.Errorf("invalid ingress lifecycle action %q", action)
	}
	identity := make([]byte, 16)
	if _, err := rand.Read(identity); err != nil {
		return "", nil, err
	}
	owner := ingressLifecycleOwner{jobID: fmt.Sprintf("%x", identity), action: action}
	ingressLifecycleMu.Lock()
	defer ingressLifecycleMu.Unlock()
	keys := make(map[ingressLifecycleKey]bool)
	for _, alias := range append([]string{app}, aliases...) {
		keys[ingressLifecycleKey{database: DB, app: canonicalIngressApp(alias)}] = true
	}
	if err := withIngressWrite(func(ctx context.Context, conn *sql.Conn) error {
		for key := range keys {
			if err := checkIngressReservation(ctx, conn, key.app, nil); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return "", nil, err
	}
	for key := range keys {
		ingressLifecycleOwners[key] = owner
	}
	return owner.jobID, func() {
		ingressLifecycleMu.Lock()
		defer ingressLifecycleMu.Unlock()
		for key := range keys {
			if ingressLifecycleOwners[key] == owner {
				delete(ingressLifecycleOwners, key)
			}
		}
	}, nil
}

func withIngressWrite(operation func(context.Context, *sql.Conn) error) error {
	if DB == nil {
		return fmt.Errorf("database unavailable")
	}
	ctx := context.Background()
	conn, err := DB.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	defer conn.ExecContext(ctx, "ROLLBACK")
	if err := operation(ctx, conn); err != nil {
		return err
	}
	_, err = conn.ExecContext(ctx, "COMMIT")
	return err
}

func checkIngressReservation(ctx context.Context, conn *sql.Conn, app string, owner *ingressLifecycleOwner) error {
	canonical := canonicalIngressApp(app)
	matchedOwner := false
	if active, exists := ingressLifecycleOwners[ingressLifecycleKey{database: DB, app: canonical}]; exists {
		if owner == nil || owner.jobID == "" || active != *owner {
			return fmt.Errorf("application lifecycle reservation is active for %s", canonical)
		}
		matchedOwner = true
	}
	var exists bool
	if err := conn.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='package_lifecycle_jobs')`).Scan(&exists); err != nil {
		return err
	}
	if exists {
		rows, err := conn.QueryContext(ctx, `SELECT package_id,job_id,action,status,service_units FROM package_lifecycle_jobs WHERE status NOT IN ('completed','failed','interrupted')`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var appID, jobID, action, status, rawUnits string
			if err := rows.Scan(&appID, &jobID, &action, &status, &rawUnits); err != nil {
				return err
			}
			var units []string
			if err := json.Unmarshal([]byte(rawUnits), &units); err != nil {
				return err
			}
			matches := canonicalIngressApp(appID) == canonical
			for _, unit := range units {
				matches = matches || canonicalIngressApp(unit) == canonical
			}
			if !matches {
				continue
			}
			expected := map[string]string{"install": "installing", "update": "updating", "remove": "uninstalling"}[action]
			if expected == "" || status != expected || owner == nil || owner.jobID == "" || owner.jobID != jobID || owner.action != action {
				return fmt.Errorf("application lifecycle reservation is active for %s", appID)
			}
			matchedOwner = true
		}
		if err := rows.Err(); err != nil {
			return err
		}
	}
	if owner != nil && !matchedOwner {
		return fmt.Errorf("ingress lifecycle reservation is missing or no longer active")
	}
	return nil
}

func SetAppIngressConfigForLifecycle(config models.AppIngressConfig, jobID, action string) error {
	if jobID == "" || (action != "install" && action != "update") {
		return fmt.Errorf("invalid ingress lifecycle owner")
	}
	return setAppIngressConfig(config, &ingressLifecycleOwner{jobID: jobID, action: action})
}

func setAppIngressConfig(config models.AppIngressConfig, owner *ingressLifecycleOwner) error {
	ingressLifecycleMu.Lock()
	defer ingressLifecycleMu.Unlock()
	err := withIngressWrite(func(ctx context.Context, conn *sql.Conn) error {
		if err := checkIngressReservation(ctx, conn, config.AppName, owner); err != nil {
			return err
		}
		return writeAppIngressConfig(ctx, conn, config)
	})
	if err == nil {
		InvalidateIngressCache()
	}
	return err
}

func retainedIngressSchema() error {
	if DB == nil {
		return fmt.Errorf("database unavailable")
	}
	_, err := DB.Exec(`CREATE TABLE IF NOT EXISTS retained_app_ingress_configs (app_name TEXT PRIMARY KEY, config_json TEXT NOT NULL)`)
	return err
}

func GetRetainedAppIngressConfig(app string) (*models.AppIngressConfig, error) {
	if err := retainedIngressSchema(); err != nil {
		return nil, err
	}
	var raw string
	err := DB.QueryRow(`SELECT config_json FROM retained_app_ingress_configs WHERE app_name=?`, app).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var config models.AppIngressConfig
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func ArchiveAppIngressConfig(app string, purge bool) error {
	return archiveAppIngressConfig(app, purge, nil)
}

func ArchiveAppIngressConfigForLifecycle(app string, purge bool, jobID string) error {
	if jobID == "" {
		return fmt.Errorf("ingress lifecycle job identity is required")
	}
	return archiveAppIngressConfig(app, purge, &ingressLifecycleOwner{jobID: jobID, action: "remove"})
}

func archiveAppIngressConfig(app string, purge bool, owner *ingressLifecycleOwner) error {
	ingressLifecycleMu.Lock()
	defer ingressLifecycleMu.Unlock()
	err := withIngressWrite(func(ctx context.Context, conn *sql.Conn) error {
		if err := checkIngressReservation(ctx, conn, app, owner); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS retained_app_ingress_configs (app_name TEXT PRIMARY KEY, config_json TEXT NOT NULL)`); err != nil {
			return err
		}
		if purge {
			if _, err := conn.ExecContext(ctx, `DELETE FROM retained_app_ingress_configs WHERE app_name=?`, app); err != nil {
				return err
			}
		} else {
			var config models.AppIngressConfig
			var created, updated string
			err := conn.QueryRowContext(ctx, `SELECT app_name,public_domain,external_access_enabled,listen_port,tls_enabled,COALESCE(CAST(created_at AS TEXT),''),COALESCE(CAST(updated_at AS TEXT),'') FROM app_ingress_configs WHERE app_name=?`, app).Scan(
				&config.AppName, &config.PublicDomain, &config.ExternalAccessEnabled, &config.ListenPort, &config.TLSEnabled, &created, &updated)
			if err != nil && err != sql.ErrNoRows {
				return err
			}
			if err == nil {
				for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05"} {
					if config.CreatedAt.IsZero() {
						config.CreatedAt, _ = time.Parse(layout, created)
					}
					if config.UpdatedAt.IsZero() {
						config.UpdatedAt, _ = time.Parse(layout, updated)
					}
				}
				raw, err := json.Marshal(config)
				if err != nil {
					return err
				}
				if _, err := conn.ExecContext(ctx, `INSERT INTO retained_app_ingress_configs (app_name,config_json) VALUES (?,?) ON CONFLICT(app_name) DO UPDATE SET config_json=excluded.config_json`, app, string(raw)); err != nil {
					return err
				}
			}
		}
		_, err := conn.ExecContext(ctx, `DELETE FROM app_ingress_configs WHERE app_name=?`, app)
		return err
	})
	if err == nil {
		InvalidateIngressCache()
	}
	return err
}

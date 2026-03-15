package services

import (
	"regexp"
	"testing"
	"time"
)

func TestValidateServiceName(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{name: "apache2", wantErr: false},
		{name: "docker.service", wantErr: false},
		{name: "nginx-1", wantErr: false},
		{name: "bad name", wantErr: true},
		{name: "bad;rm -rf /", wantErr: true},
		{name: "bad$(cmd)", wantErr: true},
	}

	for _, tt := range tests {
		err := validateServiceName(tt.name)
		if (err != nil) != tt.wantErr {
			t.Fatalf("validateServiceName(%q) error=%v wantErr=%v", tt.name, err, tt.wantErr)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		input time.Duration
		want  string
	}{
		{input: (3 * 24 * time.Hour) + (5 * time.Hour), want: "3d 5h"},
		{input: (2 * time.Hour) + (30 * time.Minute), want: "2h 30m"},
		{input: 45 * time.Minute, want: "45m"},
	}

	for _, tt := range tests {
		got := FormatDuration(tt.input)
		if got != tt.want {
			t.Fatalf("FormatDuration(%v)=%q want %q", tt.input, got, tt.want)
		}
	}
}

func TestFormatUptimeInvalidReturnsInput(t *testing.T) {
	raw := "not-a-systemd-time"
	if got := FormatUptime(raw); got != raw {
		t.Fatalf("FormatUptime(%q)=%q want same raw value", raw, got)
	}
}

func TestGetPM2ServiceInfo(t *testing.T) {
	now := time.Now()
	pm2Processes := map[string]PM2Process{
		"aetherflow-api": {
			Name: "aetherflow-api",
			PM2Env: struct {
				Status    string "json:\"status\""
				PMUptime  int64  "json:\"pm_uptime\""
				Version   string "json:\"version\""
				Instances int    "json:\"instances\""
			}{
				Status:   "online",
				PMUptime: now.Add(-2 * time.Minute).UnixMilli(),
				Version:  "1.2.3",
			},
		},
		"broken-proc": {
			Name: "broken-proc",
			PM2Env: struct {
				Status    string "json:\"status\""
				PMUptime  int64  "json:\"pm_uptime\""
				Version   string "json:\"version\""
				Instances int    "json:\"instances\""
			}{
				Status: "errored",
			},
		},
	}

	status, uptime, version := GetPM2ServiceInfo(pm2Processes, "aetherflow-api")
	if status != "running" {
		t.Fatalf("online PM2 status=%q want running", status)
	}
	if version != "1.2.3" {
		t.Fatalf("online PM2 version=%q want 1.2.3", version)
	}
	if uptime == "-" {
		t.Fatalf("online PM2 uptime should be computed, got %q", uptime)
	}
	if ok, _ := regexp.MatchString(`^\d+[mh]`, uptime); !ok {
		t.Fatalf("online PM2 uptime has unexpected format: %q", uptime)
	}

	status, uptime, version = GetPM2ServiceInfo(pm2Processes, "broken-proc")
	if status != "error" || uptime != "-" || version != "-" {
		t.Fatalf("errored PM2 result = (%q,%q,%q), want (error,-,-)", status, uptime, version)
	}

	status, uptime, version = GetPM2ServiceInfo(pm2Processes, "missing-proc")
	if status != "stopped" || uptime != "-" || version != "-" {
		t.Fatalf("missing PM2 result = (%q,%q,%q), want (stopped,-,-)", status, uptime, version)
	}
}

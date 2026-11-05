package services

import (
	"testing"
)

func TestParseHumanSize(t *testing.T) {
	cases := []struct {
		input string
		want  int64
	}{
		{"512MB", 512 * 1024 * 1024},
		{"2GB", 2 * 1024 * 1024 * 1024},
		{"1TB", 1024 * 1024 * 1024 * 1024},
	}

	for _, tc := range cases {
		got, err := ParseHumanSize(tc.input)
		if err != nil {
			t.Fatalf("ParseHumanSize(%q) returned error: %v", tc.input, err)
		}
		if got != tc.want {
			t.Fatalf("ParseHumanSize(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestQuotaScriptSizeRoundsUpToSupportedUnits(t *testing.T) {
	if got := quotaScriptSize(1536 * 1024 * 1024); got != "2GB" {
		t.Fatalf("quotaScriptSize rounded value = %q, want 2GB", got)
	}
	if got := quotaScriptSize(100); got != "1MB" {
		t.Fatalf("quotaScriptSize tiny value = %q, want 1MB", got)
	}
}

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{name: "alice", wantErr: false},
		{name: "bob.smith", wantErr: false},
		{name: "user-42", wantErr: false},
		{name: "bad user", wantErr: true},
		{name: "bad;rm -rf /", wantErr: true},
		{name: "bad$(cmd)", wantErr: true},
		{name: "-starts-with-dash", wantErr: true},
		{name: "", wantErr: true},
		{name: "a" + string(make([]byte, 32)), wantErr: true}, // > 32 chars
	}

	for _, tt := range tests {
		err := validateUsername(tt.name)
		if (err != nil) != tt.wantErr {
			t.Fatalf("validateUsername(%q) error=%v wantErr=%v", tt.name, err, tt.wantErr)
		}
	}
}

func TestQuotaNormalizationRetainsCapacityAndStorageSuspension(t *testing.T) {
	for _, source := range []string{"", "retired-provider", "manual", "runner"} {
		record := normalizeQuotaRecord(UserQuotaRecord{
			UserID: 42, QuotaBytes: 100, UsedBytes: 75,
			Status: "suspended", Source: source,
		})
		if record.Status != "suspended" || !record.Configured || record.AvailableBytes != 25 || record.UsagePct != 75 {
			t.Fatalf("quota normalization must preserve capacity and storage suspension: %+v", record)
		}
		wantSource := "manual"
		if source == "runner" {
			wantSource = "runner"
		}
		if record.Source != wantSource {
			t.Fatalf("source = %q, want %q", record.Source, wantSource)
		}
	}
}

func TestQuotaNormalizationDefaultsOnlyEmptyStatus(t *testing.T) {
	for input, expected := range map[string]string{"": "active", "  ": "active", " ACTIVE ": "active", " Suspended ": "suspended", "pending": "pending"} {
		if record := normalizeQuotaRecord(UserQuotaRecord{Status: input}); record.Status != expected {
			t.Fatalf("status %q normalized to %q, want %q", input, record.Status, expected)
		}
	}
}

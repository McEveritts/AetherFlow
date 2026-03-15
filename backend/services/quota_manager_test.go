package services

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
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

func TestVerifyBillingWebhookRequestWithHMAC(t *testing.T) {
	t.Setenv("WHMCS_WEBHOOK_SECRET", "super-secret")

	body := []byte(`{"event_type":"service_upgrade","username":"alice","quota":"500GB"}`)
	mac := hmac.New(sha256.New, []byte("super-secret"))
	mac.Write(body)
	signature := hex.EncodeToString(mac.Sum(nil))

	headers := http.Header{}
	headers.Set("X-WHMCS-Signature", signature)

	if err := VerifyBillingWebhookRequest("whmcs", headers, body); err != nil {
		t.Fatalf("VerifyBillingWebhookRequest() returned error: %v", err)
	}
}

func TestExtractBillingEventFallsBackToPlanMap(t *testing.T) {
	t.Setenv("BILLING_QUOTA_PLAN_MAP", `{"Enterprise":"4TB"}`)

	event, err := extractBillingEvent("blesta", []byte(`{
		"event_type":"service_upgrade",
		"client":{"email":"owner@example.com"},
		"product":{"name":"Enterprise"}
	}`))
	if err != nil {
		t.Fatalf("extractBillingEvent() returned error: %v", err)
	}

	if event.Plan != "Enterprise" {
		t.Fatalf("event.Plan = %q, want Enterprise", event.Plan)
	}
	if event.QuotaBytes != 4*1024*1024*1024*1024 {
		t.Fatalf("event.QuotaBytes = %d, want 4TB", event.QuotaBytes)
	}
	if event.Email != "owner@example.com" {
		t.Fatalf("event.Email = %q, want owner@example.com", event.Email)
	}
}

func TestVerifyBillingWebhookRequestWithBearerToken(t *testing.T) {
	t.Setenv("BLESTA_WEBHOOK_SECRET", "my-bearer-secret")

	body := []byte(`{"event_type":"service_create","username":"bob","quota":"1TB"}`)

	headers := http.Header{}
	headers.Set("Authorization", "Bearer my-bearer-secret")

	if err := VerifyBillingWebhookRequest("blesta", headers, body); err != nil {
		t.Fatalf("VerifyBillingWebhookRequest(bearer) returned error: %v", err)
	}

	// Should reject wrong bearer
	badHeaders := http.Header{}
	badHeaders.Set("Authorization", "Bearer wrong-secret")
	if err := VerifyBillingWebhookRequest("blesta", badHeaders, body); err == nil {
		t.Fatal("VerifyBillingWebhookRequest(bad bearer) should have returned an error")
	}
}

func TestBillingSecretFallsBackToGlobalSecret(t *testing.T) {
	t.Setenv("BLESTA_WEBHOOK_SECRET", "")
	t.Setenv("BILLING_WEBHOOK_SECRET", "fallback-secret")

	if got := billingSecret("blesta"); got != "fallback-secret" {
		t.Fatalf("billingSecret() = %q, want fallback-secret", got)
	}
}

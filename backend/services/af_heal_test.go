package services

import (
	"testing"
	"time"
)

// ── Phase 29: Control Domain — af-heal Restart Budget Tests ─────────────
//
// These tests verify the restart budget mechanism that prevents restart storms.
// The budget tracks restart counts per service per hour and rejects restarts
// once the budget is exhausted.

func TestRestartBudget_InitiallyAllows(t *testing.T) {
	rb := &restartBudget{
		counts:  make(map[string]int),
		resetAt: time.Now().Add(time.Hour),
	}

	if !rb.canRestart("nginx") {
		t.Error("Fresh budget should allow restarts")
	}
}

func TestRestartBudget_ExhaustsAfterMax(t *testing.T) {
	rb := &restartBudget{
		counts:  make(map[string]int),
		resetAt: time.Now().Add(time.Hour),
	}

	// Record maxRestartsPerHour restarts
	for i := 0; i < maxRestartsPerHour; i++ {
		if !rb.canRestart("nginx") {
			t.Fatalf("Budget should allow restart #%d", i+1)
		}
		rb.record("nginx")
	}

	// Now it should be exhausted
	if rb.canRestart("nginx") {
		t.Errorf("Budget should be exhausted after %d restarts", maxRestartsPerHour)
	}
}

func TestRestartBudget_IndependentPerService(t *testing.T) {
	rb := &restartBudget{
		counts:  make(map[string]int),
		resetAt: time.Now().Add(time.Hour),
	}

	// Exhaust budget for nginx
	for i := 0; i < maxRestartsPerHour; i++ {
		rb.record("nginx")
	}

	// redis should still have budget
	if !rb.canRestart("redis") {
		t.Error("Budget for redis should be independent of nginx")
	}

	// nginx should be exhausted
	if rb.canRestart("nginx") {
		t.Error("nginx budget should be exhausted")
	}
}

func TestRestartBudget_ResetsAfterWindow(t *testing.T) {
	rb := &restartBudget{
		counts:  make(map[string]int),
		resetAt: time.Now().Add(-1 * time.Minute), // already expired
	}

	// Record some restarts
	for i := 0; i < maxRestartsPerHour; i++ {
		rb.record("nginx")
	}

	// Budget check should reset the window since resetAt is in the past
	if !rb.canRestart("nginx") {
		t.Error("Budget should reset when window has expired")
	}
}

func TestRestartBudget_MaxConstant(t *testing.T) {
	if maxRestartsPerHour <= 0 {
		t.Error("maxRestartsPerHour must be positive")
	}
	if maxRestartsPerHour > 100 {
		t.Errorf("maxRestartsPerHour=%d seems too high — potential restart storm risk", maxRestartsPerHour)
	}
}

func TestCommandTimeout_Reasonable(t *testing.T) {
	if commandTimeout < 5*time.Second {
		t.Errorf("commandTimeout=%v is too short for service restart", commandTimeout)
	}
	if commandTimeout > 5*time.Minute {
		t.Errorf("commandTimeout=%v is too long — may hang the heal worker", commandTimeout)
	}
}

// --- FormatDuration Tests ---

func TestFormatDuration_Short(t *testing.T) {
	d := FormatDuration(45 * time.Second)
	if d == "" {
		t.Error("FormatDuration should return non-empty for 45 seconds")
	}
}

func TestFormatDuration_Hours(t *testing.T) {
	d := FormatDuration(3*time.Hour + 15*time.Minute)
	if d == "" {
		t.Error("FormatDuration should return non-empty for 3h15m")
	}
}

func TestFormatDuration_Days(t *testing.T) {
	d := FormatDuration(72 * time.Hour) // 3 days
	if d == "" {
		t.Error("FormatDuration should return non-empty for 72 hours")
	}
}

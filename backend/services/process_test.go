package services

import "testing"

func TestCheckProcessRunningUnknownProcess(t *testing.T) {
	// Intentionally absurd name to avoid accidental matches.
	if CheckProcessRunning("aetherflow-this-process-should-not-exist-123456789") {
		t.Fatal("CheckProcessRunning returned true for a non-existent process name")
	}
}

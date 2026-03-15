package services

import "testing"

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input float64
		want  string
	}{
		{input: 999, want: "999 B"},
		{input: 1024, want: "1.0 KB"},
		{input: 1536, want: "1.5 KB"},
		{input: 1048576, want: "1.0 MB"},
	}

	for _, tt := range tests {
		got := formatBytes(tt.input)
		if got != tt.want {
			t.Fatalf("formatBytes(%f)=%q want %q", tt.input, got, tt.want)
		}
	}
}

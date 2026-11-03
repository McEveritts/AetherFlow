package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackageScriptResolutionPrefersCurrentRelease(t *testing.T) {
	defaults := packageScriptRoots()
	expected := []string{
		"/opt/AetherFlow/current/packages/package",
		"/opt/AetherFlow/packages/package",
		"/usr/local/bin/AetherFlow/package",
	}
	root := t.TempDir()
	roots := make([]string, len(expected))
	write := func(path string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("release"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for i, path := range expected {
		if defaults[i] != path {
			t.Fatalf("root %d = %q, want %q", i, defaults[i], path)
		}
		roots[i] = filepath.Join(root, strings.TrimPrefix(path, "/"))
		write(filepath.Join(roots[i], "install", "installpackage-dispatcharr"))
	}
	// The current install fallback wins over a stale dedicated updater.
	write(filepath.Join(roots[1], "update", "updatepackage-dispatcharr"))
	for _, name := range []string{"installpackage-dispatcharr", "updatepackage-dispatcharr"} {
		got := resolvePackageScriptInRoots("update", name, roots)
		if want := filepath.Join(roots[0], "install", "installpackage-dispatcharr"); got != want {
			t.Fatalf("update %q = %q, want %q", name, got, want)
		}
	}
	write(filepath.Join(roots[0], "update", "updatepackage-dispatcharr"))
	if got, want := resolvePackageScriptInRoots("update", "installpackage-dispatcharr", roots), filepath.Join(roots[0], "update", "updatepackage-dispatcharr"); got != want {
		t.Fatalf("dedicated update = %q, want %q", got, want)
	}
	for i := range roots {
		if got, want := resolvePackageScriptInRoots("install", "installpackage-dispatcharr", roots), filepath.Join(roots[i], "install", "installpackage-dispatcharr"); got != want {
			t.Fatalf("fallback %d = %q, want %q", i, got, want)
		}
		if err := os.Remove(filepath.Join(roots[i], "install", "installpackage-dispatcharr")); err != nil {
			t.Fatal(err)
		}
	}
	// A directory named like a recipe must never be selected as a script.
	if err := os.MkdirAll(filepath.Join(roots[0], "install", "installpackage-dispatcharr"), 0755); err != nil {
		t.Fatal(err)
	}
	if got := resolvePackageScriptInRoots("install", "installpackage-dispatcharr", roots); got != "" {
		t.Fatalf("selected directory as script: %q", got)
	}
	if got := resolvePackageScriptInRoots("install", "../dispatcharr", roots); got != "" {
		t.Fatalf("accepted unsafe script name: %q", got)
	}
}

func TestMarketplaceConfigPathsPreferCurrentRelease(t *testing.T) {
	const envKey = "AF_TEST_MARKETPLACE_CONFIG"
	t.Setenv(envKey, "")
	paths := resolveConfigPaths(envKey, "packages.json")
	for i, want := range []string{
		"/opt/AetherFlow/current/config/packages.json",
		"/opt/AetherFlow/current/backend/config/packages.json",
	} {
		if paths[i] != want {
			t.Fatalf("config candidate %d = %q, want %q", i, paths[i], want)
		}
	}
	t.Setenv(envKey, "/custom/packages.json")
	if paths := resolveConfigPaths(envKey, "packages.json"); len(paths) != 1 || paths[0] != "/custom/packages.json" {
		t.Fatalf("explicit override not respected: %v", paths)
	}
}

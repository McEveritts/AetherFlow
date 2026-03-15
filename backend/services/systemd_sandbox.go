package services

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"aetherflow/models"
)

func resolveSandboxScriptPath() string {
	paths := []string{
		filepath.Join("/usr", "local", "bin", "AetherFlow", "system", "af-systemd-sandbox"),
		filepath.Join("packages", "system", "af-systemd-sandbox"),
		filepath.Join("..", "packages", "system", "af-systemd-sandbox"),
	}

	for _, candidate := range paths {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	return ""
}

func getPackageDefinition(pkgID string) *models.Package {
	for _, pkg := range GetPackages() {
		if pkg.Name == pkgID {
			copy := pkg
			return &copy
		}
	}

	return nil
}

func ApplyPackageSandbox(pkgID string) error {
	pkg := getPackageDefinition(pkgID)
	if pkg == nil {
		return fmt.Errorf("package %q not found", pkgID)
	}
	if pkg.ServiceType != "systemd" {
		return nil
	}
	if pkg.SandboxProfile == "" || len(pkg.SandboxReadWrite) == 0 {
		return nil
	}

	scriptPath := resolveSandboxScriptPath()
	if scriptPath == "" {
		return fmt.Errorf("af-systemd-sandbox helper not found")
	}

	args := []string{scriptPath, "apply", "--profile", pkg.SandboxProfile}
	for _, rwPath := range pkg.SandboxReadWrite {
		args = append(args, "--rw", rwPath)
	}

	units := append([]string(nil), pkg.SandboxServiceIDs...)
	if len(units) == 0 && pkg.ServiceName != "" {
		units = []string{pkg.ServiceName}
	}
	if len(units) == 0 {
		return nil
	}
	args = append(args, units...)

	cmd := exec.Command("bash", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(output))
	}

	return nil
}

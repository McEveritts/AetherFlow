package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestBrowseDirectories_AllowlistAndTraversal(t *testing.T) {
	tempDir := t.TempDir()
	sub1 := filepath.Join(tempDir, "alpha")
	sub2 := filepath.Join(tempDir, "beta")
	_ = os.Mkdir(sub1, 0755)
	_ = os.Mkdir(sub2, 0755)
	testFile := filepath.Join(tempDir, "sample.txt")
	_ = os.WriteFile(testFile, []byte("hello world"), 0644)

	t.Setenv("AF_ALLOWED_FS_ROOTS", tempDir)

	r := gin.New()
	r.GET("/fs", BrowseDirectories)

	// 1. Missing path parameter -> 400
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/fs", nil)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for missing path, got %d", w.Code)
		}
	}

	// 2. Non-existent path -> 404
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/fs?path="+filepath.Join(tempDir, "nonexistent"), nil)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for non-existent path, got %d", w.Code)
		}
	}

	// 3. Path pointing to file -> 400
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/fs?path="+testFile, nil)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for file path, got %d", w.Code)
		}
	}

	// 4. Directory traversal attempt outside allowed sandbox -> 403
	{
		outsideDir := os.TempDir()
		if outsideDir != tempDir {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/fs?path="+outsideDir, nil)
			r.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("expected 403 for directory outside allowed roots, got %d", w.Code)
			}
		}
	}

	// 5. Valid directory -> 200 with directory and entries list
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/fs?path="+tempDir, nil)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for valid directory, got %d: %s", w.Code, w.Body.String())
		}

		var res struct {
			CurrentPath string    `json:"current_path"`
			ParentPath  string    `json:"parent_path"`
			Directories []string  `json:"directories"`
			Entries     []FSEntry `json:"entries"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if len(res.Directories) != 2 {
			t.Fatalf("expected 2 directories (alpha, beta), got %d: %v", len(res.Directories), res.Directories)
		}
		if res.Directories[0] != "alpha" || res.Directories[1] != "beta" {
			t.Fatalf("unexpected directories: %v", res.Directories)
		}
		if len(res.Entries) != 3 {
			t.Fatalf("expected 3 entries total (2 dirs + 1 file), got %d", len(res.Entries))
		}
	}
}

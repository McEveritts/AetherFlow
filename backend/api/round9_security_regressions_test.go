package api

import (
	"bytes"
	"database/sql"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"aetherflow/services"

	"github.com/gin-gonic/gin"
	_ "modernc.org/sqlite"
)

func TestConcurrentStreamHub_RejectsOverlapWithoutPanic(t *testing.T) {
	const appName = "sonarr_race_test"
	defer services.StreamHub.DeregisterStream(appName)

	var wg sync.WaitGroup
	successCount := 0
	var mu sync.Mutex

	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch, ok := services.StreamHub.TryRegisterStream(appName)
			if !ok {
				return
			}
			mu.Lock()
			successCount++
			mu.Unlock()
			services.SendStreamMessage(ch, "[STEP 0] Concurrent test")
			services.StreamHub.DeregisterStreamIfMatch(appName, ch)
			// Sending after deregister must return false cleanly and never panic.
			if services.SendStreamMessage(ch, "after-close") {
				t.Errorf("expected SendStreamMessage on closed channel to return false")
			}
		}()
	}
	wg.Wait()
	if successCount < 1 {
		t.Fatal("expected at least one stream registration to succeed")
	}
}

func TestValidateAvatarURI_StrictAllowlist(t *testing.T) {
	rejected := []string{
		"",
		"javascript:alert(1)",
		"data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+PC9zdmc+",
		"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
		"http://insecure.example.com/avatar.png",
		"https://user:pass@example.com/avatar.png",
		"//evil.example.com/avatar.png",
		"/uploads/../../etc/passwd",
		"data:image/png;base64,not-valid-base64!!!",
	}
	for _, cand := range rejected {
		if _, err := validateAvatarURI(cand); err == nil {
			t.Errorf("expected validateAvatarURI(%q) to reject unsafe URI", cand)
		}
	}

	accepted := []string{
		"https://cdn.example.com/avatars/u1.png",
		"/uploads/avatars/u1.webp",
		"data:image/png;base64,iVBORw0KGgo=",
		"data:image/webp;base64,UklGRg==",
	}
	for _, cand := range accepted {
		if _, err := validateAvatarURI(cand); err != nil {
			t.Errorf("expected validateAvatarURI(%q) to succeed, got: %v", cand, err)
		}
	}
}

func TestNormalizeRecoveryCodeInput_AcceptsCompactAndHyphenated(t *testing.T) {
	norm, ok := normalizeRecoveryCodeInput("abcd2345")
	if !ok || norm != "ABCD-2345" {
		t.Fatalf("expected ABCD-2345, got %q (ok=%v)", norm, ok)
	}
	norm2, ok2 := normalizeRecoveryCodeInput("WXYZ-6789")
	if !ok2 || norm2 != "WXYZ-6789" {
		t.Fatalf("expected WXYZ-6789, got %q (ok=%v)", norm2, ok2)
	}
	if _, bad := normalizeRecoveryCodeInput("123456"); bad {
		t.Fatal("6-digit TOTP code must not match recovery code pattern")
	}
}

func TestSecurityHeaders_APIVsHTMLCSP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(SecurityHeadersMiddleware())
	r.GET("/api/v1/auth/session", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
	r.GET("/swagger/index.html", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	wAPI := httptest.NewRecorder()
	reqAPI, _ := http.NewRequest("GET", "/api/v1/auth/session", nil)
	reqAPI.Host = "mcflow.stream"
	r.ServeHTTP(wAPI, reqAPI)
	if got := wAPI.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'none'") {
		t.Fatalf("expected strict API CSP on /api/*, got %q", got)
	}

	wDoc := httptest.NewRecorder()
	reqDoc, _ := http.NewRequest("GET", "/swagger/index.html", nil)
	reqDoc.Host = "mcflow.stream"
	r.ServeHTTP(wDoc, reqDoc)
	gotDoc := wDoc.Header().Get("Content-Security-Policy")
	if !strings.Contains(gotDoc, "wss://mcflow.stream") || strings.Contains(gotDoc, "connect-src 'self' ws: wss:") {
		t.Fatalf("expected host-scoped connect-src on HTML route, got %q", gotDoc)
	}
}

func TestFileshareAndBackup_OsRootBlocksSymlinksAndNonSQLiteBackups(t *testing.T) {
	gin.SetMode(gin.TestMode)
	outsideDir := t.TempDir()
	outsideSecret := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideSecret, []byte("TOP_SECRET"), 0600); err != nil {
		t.Fatal(err)
	}

	uploadDir := t.TempDir()
	t.Setenv("AETHERFLOW_UPLOAD_DIR", uploadDir)
	if err := os.Symlink(outsideSecret, filepath.Join(uploadDir, "leak.txt")); err != nil {
		t.Fatal(err)
	}

	r := gin.New()
	r.GET("/files/:filename", HandleDownloadFile)
	r.DELETE("/files/:filename", DeleteSharedFile)
	r.POST("/files/upload", UploadFile)
	r.POST("/backup/upload/:filename", UploadBackupChunk)

	// 1. Symlink download blocked
	w1 := httptest.NewRecorder()
	req1, _ := http.NewRequest("GET", "/files/leak.txt", nil)
	r.ServeHTTP(w1, req1)
	if w1.Code == http.StatusOK {
		t.Fatalf("expected symlink download to be blocked, got 200")
	}

	// 2. Symlink delete blocked and outside file intact
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("DELETE", "/files/leak.txt", nil)
	r.ServeHTTP(w2, req2)
	if w2.Code == http.StatusOK {
		t.Fatalf("expected symlink delete to be blocked, got 200")
	}
	if _, err := os.Stat(outsideSecret); err != nil {
		t.Fatalf("outside secret file was deleted through symlink: %v", err)
	}

	// 3. Split-chunk ELF magic upload blocked on chunk 1 re-check
	sendChunk := func(idx string, data []byte) *httptest.ResponseRecorder {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		part, _ := mw.CreateFormFile("file", "innocent.bin")
		_, _ = part.Write(data)
		_ = mw.Close()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/files/upload", &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("X-Chunk-Index", idx)
		r.ServeHTTP(w, req)
		return w
	}
	// Chunk 0 writes 1 byte "\x7f" (not yet ELF), Chunk 1 appends "ELF..." -> assembled header is \x7fELF -> blocked!
	if wChunk0 := sendChunk("0", []byte{0x7f}); wChunk0.Code != http.StatusOK {
		t.Fatalf("expected 1-byte chunk 0 setup to return 200, got %d", wChunk0.Code)
	}
	if wChunk1 := sendChunk("1", []byte("ELF\x02\x01\x01\x00")); wChunk1.Code != http.StatusBadRequest {
		t.Fatalf("expected assembled ELF split-chunk upload to return 400, got %d: %s", wChunk1.Code, wChunk1.Body.String())
	}

	// 4. Backup upload rejects non-SQLite payload and accepts genuine SQLite 3 database
	dbDir := t.TempDir()
	dbFile := filepath.Join(dbDir, "aetherflow.sqlite")
	t.Setenv("DB_PATH", dbFile)

	wBad := httptest.NewRecorder()
	reqBad, _ := http.NewRequest("POST", "/backup/upload/fake.sqlite?chunk=0&total=1", strings.NewReader("not-a-sqlite-database"))
	r.ServeHTTP(wBad, reqBad)
	if wBad.Code != http.StatusBadRequest {
		t.Fatalf("expected non-SQLite backup upload to return 400, got %d: %s", wBad.Code, wBad.Body.String())
	}

	validSrc := filepath.Join(t.TempDir(), "valid.sqlite")
	srcConn, err := sql.Open("sqlite", validSrc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srcConn.Exec("CREATE TABLE t (id INTEGER PRIMARY KEY); INSERT INTO t VALUES (1);"); err != nil {
		t.Fatal(err)
	}
	_ = srcConn.Close()
	sqliteBytes, err := os.ReadFile(validSrc)
	if err != nil {
		t.Fatal(err)
	}

	wGood := httptest.NewRecorder()
	reqGood, _ := http.NewRequest("POST", "/backup/upload/good_backup.sqlite?chunk=0&total=1", bytes.NewReader(sqliteBytes))
	r.ServeHTTP(wGood, reqGood)
	if wGood.Code != http.StatusOK {
		t.Fatalf("expected valid SQLite backup upload to return 200, got %d: %s", wGood.Code, wGood.Body.String())
	}
}

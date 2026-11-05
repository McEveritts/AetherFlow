package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aetherflow/db"

	"github.com/gin-gonic/gin"
)

func TestQuotaUploadGuardRejectsUnknownLengthAndInvalidIdentity(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		length int64
		userID any
		want   int
	}{
		{"unknown length", -1, 1, http.StatusLengthRequired},
		{"missing identity", 1, nil, http.StatusUnauthorized},
		{"invalid identity", 1, "admin", http.StatusUnauthorized},
		{"invalid zero-byte identity", 0, -1, http.StatusUnauthorized},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			router := gin.New()
			router.Use(func(context *gin.Context) {
				if testCase.userID != nil {
					context.Set("user_id", testCase.userID)
				}
			})
			router.POST("/upload", QuotaUploadGuard(), func(context *gin.Context) { context.Status(http.StatusNoContent) })
			request := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("x"))
			request.ContentLength = testCase.length
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != testCase.want {
				t.Fatalf("status %d, want %d", response.Code, testCase.want)
			}
		})
	}
}

func TestQuotaUploadGuardFailsClosedWhenDatabaseIsUnavailable(t *testing.T) {
	setupTestDB(t)
	if err := db.DB.Close(); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(func(context *gin.Context) { context.Set("user_id", 1) })
	router.POST("/upload", QuotaUploadGuard(), func(context *gin.Context) { context.Status(http.StatusNoContent) })
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("x")))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

func TestQuotaUploadGuardEnforcesSuspensionForEmptyUploads(t *testing.T) {
	setupTestDB(t)
	if _, err := db.DB.Exec("INSERT INTO users(id, username, role) VALUES(731, 'quota-guard', 'admin')"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("INSERT INTO user_quotas(user_id, username, quota_bytes, used_bytes, status) VALUES(731, 'quota-guard', 100, 0, 'suspended')"); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(func(context *gin.Context) { context.Set("user_id", 731) })
	router.POST("/upload", QuotaUploadGuard(), func(context *gin.Context) { context.Status(http.StatusNoContent) })
	for status, expected := range map[string]int{"suspended": http.StatusForbidden, "pending": http.StatusForbidden, "active": http.StatusNoContent} {
		if _, err := db.DB.Exec("UPDATE user_quotas SET status=? WHERE user_id=731", status); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/upload", nil))
		if response.Code != expected {
			t.Fatalf("status %q returned %d, want %d", status, response.Code, expected)
		}
	}
}

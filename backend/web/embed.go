package web

import (
	"embed"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
)

//go:embed all:dist
var embeddedDist embed.FS

// GetFileSystem returns the embedded frontend filesystem (rooted at dist/),
// or an external static directory if STATIC_DIR is explicitly configured.
func GetFileSystem() (fs.FS, bool) {
	if customDir := strings.TrimSpace(os.Getenv("STATIC_DIR")); customDir != "" {
		if info, err := os.Stat(customDir); err == nil && info.IsDir() {
			return os.DirFS(customDir), true
		}
	}

	sub, err := fs.Sub(embeddedDist, "dist")
	if err != nil {
		return nil, false
	}

	// Check if index.html is present inside the embedded dist
	if _, err := fs.Stat(sub, "index.html"); err == nil {
		return sub, true
	}

	return sub, false
}

// RegisterSPAHandler mounts a NoRoute handler on the Gin router that serves
// the Next.js static export from the embedded binary (or STATIC_DIR) with
// clean URL resolution and SPA fallback, while preserving JSON 404s for /api.
func RegisterSPAHandler(r *gin.Engine) {
	staticFS, hasIndex := GetFileSystem()
	var fileServer http.Handler
	if staticFS != nil {
		fileServer = http.FileServer(http.FS(staticFS))
	}

	r.NoRoute(func(c *gin.Context) {
		reqPath := c.Request.URL.Path

		// Never serve HTML for unknown API or WebSocket endpoints.
		if strings.HasPrefix(reqPath, "/api/") || reqPath == "/api" || strings.HasPrefix(reqPath, "/ws/") {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "not_found",
				"message": "The requested API endpoint does not exist.",
			})
			return
		}

		if !hasIndex || staticFS == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "frontend_not_bundled",
				"message": "Static UI is not embedded in this dev build. Run with embedded dist or set STATIC_DIR.",
			})
			return
		}

		cleanPath := strings.TrimPrefix(path.Clean(reqPath), "/")
		if cleanPath == "" || cleanPath == "." {
			cleanPath = "index.html"
		}

		// Set aggressive caching for hashed Next.js static chunks; force revalidation for HTML, RSC, and Service Worker.
		if strings.HasPrefix(cleanPath, "_next/static/") {
			c.Header("Cache-Control", "public, max-age=31536000, immutable")
		} else if cleanPath == "sw.js" || cleanPath == "manifest.json" || strings.HasSuffix(cleanPath, ".html") || strings.HasSuffix(cleanPath, ".txt") {
			c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		}

		// 0. Next.js App Router RSC flight payload resolution (prevents soft navigation fallback to hard MPA reload)
		if c.GetHeader("RSC") == "1" || c.Query("_rsc") != "" {
			rscCandidates := []string{}
			if cleanPath == "index.html" {
				rscCandidates = append(rscCandidates, "index.txt")
			} else {
				rscCandidates = append(rscCandidates, cleanPath+".txt", path.Join(cleanPath, "index.txt"))
			}
			for _, candidate := range rscCandidates {
				if data, err := fs.ReadFile(staticFS, candidate); err == nil {
					c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
					c.Data(http.StatusOK, "text/x-component; charset=utf-8", data)
					return
				}
			}
		}

		// 1. Direct file match (e.g., _next/static/..., favicon.ico, index.html)
		if info, err := fs.Stat(staticFS, cleanPath); err == nil && !info.IsDir() {
			fileServer.ServeHTTP(c.Writer, c.Request)
			return
		}

		// 2. Clean route match for Next.js static export (e.g., /login -> login.html)
		htmlCandidate := cleanPath + ".html"
		if info, err := fs.Stat(staticFS, htmlCandidate); err == nil && !info.IsDir() {
			c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
			c.Request.URL.Path = "/" + htmlCandidate
			fileServer.ServeHTTP(c.Writer, c.Request)
			return
		}

		// 3. Directory index match (e.g., /login/ -> login/index.html)
		dirIndexCandidate := path.Join(cleanPath, "index.html")
		if info, err := fs.Stat(staticFS, dirIndexCandidate); err == nil && !info.IsDir() {
			c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
			c.Request.URL.Path = "/" + dirIndexCandidate
			fileServer.ServeHTTP(c.Writer, c.Request)
			return
		}

		// 4. SPA fallback: serve root index.html for client-side dynamic routes
		data, err := fs.ReadFile(staticFS, "index.html")
		if err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Data(http.StatusOK, "text/html; charset=utf-8", data)
	})
}

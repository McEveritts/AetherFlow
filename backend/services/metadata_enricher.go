package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"aetherflow/db"

	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

// validMediaExtensions is the set of file extensions to include in media scans.
var validMediaExtensions = map[string]bool{
	".mkv": true, ".mp4": true, ".avi": true, ".mov": true, ".wmv": true,
	".flv": true, ".webm": true, ".m4v": true, ".ts": true,
	".srt": true, ".ass": true, ".ssa": true, ".sub": true, ".vtt": true,
	".flac": true, ".mp3": true, ".aac": true, ".ogg": true, ".opus": true,
}

// MediaFile represents a discovered media file.
type MediaFile struct {
	Path     string `json:"path"`
	Filename string `json:"filename"`
	SizeBytes int64 `json:"size_bytes"`
	Extension string `json:"extension"`
}

// EnrichedMedia represents AI-enriched metadata for a media file.
type EnrichedMedia struct {
	ID           int    `json:"id"`
	FilePath     string `json:"file_path"`
	Filename     string `json:"filename"`
	Title        string `json:"title"`
	Year         string `json:"year"`
	Language     string `json:"language"`
	Quality      string `json:"quality"`
	SubtitlesJSON string `json:"subtitles_json"`
	EnrichedAt   string `json:"enriched_at"`
}

// MetadataEnricher handles media directory scanning and AI enrichment.
type MetadataEnricher struct {
	mu       sync.RWMutex
	scanning bool
	progress float64
	total    int
	done     int
	results  []EnrichedMedia
	lastErr  string
}

// Global enricher instance.
var Enricher *MetadataEnricher

func init() {
	Enricher = &MetadataEnricher{}
}

// IsScanning returns whether a scan is in progress.
func (me *MetadataEnricher) IsScanning() bool {
	me.mu.RLock()
	defer me.mu.RUnlock()
	return me.scanning
}

// Status returns the current scan status.
func (me *MetadataEnricher) Status() map[string]interface{} {
	me.mu.RLock()
	defer me.mu.RUnlock()
	return map[string]interface{}{
		"scanning": me.scanning,
		"progress": me.progress,
		"total":    me.total,
		"done":     me.done,
		"error":    me.lastErr,
	}
}

// ScanDirectory recursively lists media files in the given path.
func (me *MetadataEnricher) ScanDirectory(path string) ([]MediaFile, error) {
	cleanPath := filepath.Clean(path)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("path does not exist: %s", cleanPath)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", cleanPath)
	}

	var files []MediaFile
	err = filepath.Walk(cleanPath, func(fp string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip inaccessible paths
		}
		if fi.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(fi.Name()))
		if validMediaExtensions[ext] {
			files = append(files, MediaFile{
				Path:      fp,
				Filename:  fi.Name(),
				SizeBytes: fi.Size(),
				Extension: ext,
			})
		}
		return nil
	})

	return files, err
}

// StartEnrichment begins async metadata enrichment for files at the given path.
func (me *MetadataEnricher) StartEnrichment(scanPath string, apiKey string) {
	me.mu.Lock()
	if me.scanning {
		me.mu.Unlock()
		return
	}
	me.scanning = true
	me.progress = 0
	me.total = 0
	me.done = 0
	me.results = nil
	me.lastErr = ""
	me.mu.Unlock()

	go me.runEnrichment(scanPath, apiKey)
}

func (me *MetadataEnricher) runEnrichment(scanPath string, apiKey string) {
	defer func() {
		me.mu.Lock()
		me.scanning = false
		me.mu.Unlock()
	}()

	files, err := me.ScanDirectory(scanPath)
	if err != nil {
		me.mu.Lock()
		me.lastErr = err.Error()
		me.mu.Unlock()
		return
	}

	me.mu.Lock()
	me.total = len(files)
	me.mu.Unlock()

	if len(files) == 0 {
		me.mu.Lock()
		me.lastErr = "No media files found in directory"
		me.mu.Unlock()
		return
	}

	// Process in batches of 20
	batchSize := 20
	for i := 0; i < len(files); i += batchSize {
		end := i + batchSize
		if end > len(files) {
			end = len(files)
		}
		batch := files[i:end]

		enriched, err := me.enrichBatch(batch, apiKey)
		if err != nil {
			log.Printf("Metadata enrichment batch error: %v", err)
			me.mu.Lock()
			me.lastErr = fmt.Sprintf("Batch %d error: %v", i/batchSize, err)
			me.mu.Unlock()
			continue
		}

		// Store results in DB
		for _, em := range enriched {
			_, dbErr := db.DB.Exec(
				`INSERT OR REPLACE INTO media_metadata (file_path, filename, title, year, language, quality, subtitles_json, enriched_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				em.FilePath, em.Filename, em.Title, em.Year, em.Language, em.Quality, em.SubtitlesJSON, time.Now().Format(time.RFC3339),
			)
			if dbErr != nil {
				log.Printf("Failed to store enriched metadata: %v", dbErr)
			}
		}

		me.mu.Lock()
		me.done = end
		me.progress = float64(end) / float64(me.total) * 100
		me.results = append(me.results, enriched...)
		me.mu.Unlock()

		// Rate limit between batches
		time.Sleep(2 * time.Second)
	}

	log.Printf("Metadata enrichment complete: %d files processed", me.total)
}

func (me *MetadataEnricher) enrichBatch(files []MediaFile, apiKey string) ([]EnrichedMedia, error) {
	ctx := context.Background()
	client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create Gemini client: %v", err)
	}
	defer client.Close()

	// Build file list for the prompt
	var fileList strings.Builder
	for _, f := range files {
		fileList.WriteString(fmt.Sprintf("- %s (%s, %d bytes)\n", f.Filename, f.Extension, f.SizeBytes))
	}

	prompt := fmt.Sprintf(`You are a media metadata expert. Analyze these media filenames and infer structured metadata.
For each file, determine: title, year, language, quality (e.g., 1080p, 720p, 4K, FLAC), and any subtitle language matches.

Files:
%s

Respond with a JSON array ONLY (no markdown, no explanation). Each element must have:
{"filename": "...", "title": "...", "year": "...", "language": "...", "quality": "...", "subtitles": ["..."]}

If you cannot determine a field, use "unknown". For subtitle files (.srt, .ass, .vtt, etc.), identify the language from the filename.`, fileList.String())

	model := client.GenerativeModel("gemini-2.0-flash")
	resp, err := model.GenerateContent(ctx, genai.Text(prompt))
	if err != nil {
		return nil, fmt.Errorf("Gemini generation error: %v", err)
	}

	var replyText string
	if resp != nil && len(resp.Candidates) > 0 && resp.Candidates[0].Content != nil {
		for _, part := range resp.Candidates[0].Content.Parts {
			if text, ok := part.(genai.Text); ok {
				replyText += string(text)
			}
		}
	}

	// Parse JSON response
	replyText = strings.TrimSpace(replyText)
	replyText = strings.TrimPrefix(replyText, "```json")
	replyText = strings.TrimPrefix(replyText, "```")
	replyText = strings.TrimSuffix(replyText, "```")
	replyText = strings.TrimSpace(replyText)

	var parsed []struct {
		Filename  string   `json:"filename"`
		Title     string   `json:"title"`
		Year      string   `json:"year"`
		Language  string   `json:"language"`
		Quality   string   `json:"quality"`
		Subtitles []string `json:"subtitles"`
	}
	if err := json.Unmarshal([]byte(replyText), &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse AI response: %v (response: %s)", err, replyText[:min(200, len(replyText))])
	}

	// Map parsed results back to files
	fileMap := make(map[string]MediaFile)
	for _, f := range files {
		fileMap[f.Filename] = f
	}

	var results []EnrichedMedia
	for _, p := range parsed {
		subsJSON, _ := json.Marshal(p.Subtitles)
		filePath := ""
		if f, ok := fileMap[p.Filename]; ok {
			filePath = f.Path
		}
		results = append(results, EnrichedMedia{
			FilePath:      filePath,
			Filename:      p.Filename,
			Title:         p.Title,
			Year:          p.Year,
			Language:      p.Language,
			Quality:       p.Quality,
			SubtitlesJSON: string(subsJSON),
		})
	}

	return results, nil
}

// GetStoredMetadata returns all enriched metadata from the database.
func GetStoredMetadata() ([]EnrichedMedia, error) {
	rows, err := db.DB.Query("SELECT id, file_path, filename, title, year, language, quality, subtitles_json, enriched_at FROM media_metadata ORDER BY enriched_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []EnrichedMedia
	for rows.Next() {
		var em EnrichedMedia
		if err := rows.Scan(&em.ID, &em.FilePath, &em.Filename, &em.Title, &em.Year, &em.Language, &em.Quality, &em.SubtitlesJSON, &em.EnrichedAt); err != nil {
			continue
		}
		results = append(results, em)
	}
	return results, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

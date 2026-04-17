package services

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"aetherflow/db"
)

// FFprobeOutput maps the json layout
type FFprobeOutput struct {
	Streams []struct {
		CodecType string `json:"codec_type"`
		CodecName string `json:"codec_name"`
	} `json:"streams"`
	Format struct {
		Size string `json:"size"`
	} `json:"format"`
}

// MediaFlowQueuePoller continuously checks for approved items to transcode.
func MediaFlowQueuePoller() {
	go func() {
		for {
			MediaFlowEngineProcess() // Defined in mediaflow_engine.go
			time.Sleep(10 * time.Second) // Poll interval
		}
	}()
	slog.Info("MediaFlow Engine Queue Poller started")
}

// ScanLibrary recurses through a target directory passively searching for unoptimized h264 files
func ScanLibrary(ctx context.Context, directory string) error {
	slog.Info("MediaFlow Scan Initiated", "directory", directory)

	err := filepath.WalkDir(directory, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".mp4" && ext != ".mkv" && ext != ".avi" {
			return nil
		}

		// Fast DB check skip if already queued
		var exists int
		db.DB.QueryRow("SELECT 1 FROM mediaflow_queue WHERE file_path = ?", path).Scan(&exists)
		if exists == 1 {
			return nil // Already known, skip heavy ffprobe
		}

		// Investigate codec natively via ffprobe
		cmdArgs := []string{
			"-v", "quiet",
			"-print_format", "json",
			"-show_format",
			"-show_streams",
			path,
		}
		cmd := exec.CommandContext(ctx, "ffprobe", cmdArgs...)
		var out bytes.Buffer
		cmd.Stdout = &out

		if parseErr := cmd.Run(); parseErr != nil {
			slog.Warn("ffprobe failed to read file", "path", path, "error", parseErr)
			return nil
		}

		var probe FFprobeOutput
		if decodeErr := json.Unmarshal(out.Bytes(), &probe); decodeErr != nil {
			return nil
		}

		// Look for video stream
		for _, stream := range probe.Streams {
			if stream.CodecType == "video" {
				if stream.CodecName == "h264" {
					// We found a target for compression optimization
					sizeBytes := probe.Format.Size

					_, insertErr := db.DB.Exec(`
						INSERT INTO mediaflow_queue (file_path, original_codec, original_size, status)
						VALUES (?, ?, ?, 'PENDING_APPROVAL')
					`, path, "h264", sizeBytes)

					if insertErr != nil {
						slog.Error("Failed to queue item", "path", path, "error", insertErr)
					} else {
						slog.Info("MediaFlow flagged file for optimization approval", "path", path)
					}
				}
				break // only process first video stream
			}
		}

		return nil
	})

	if err != nil {
		slog.Error("MediaFlow scan terminated with error", "directory", directory, "error", err)
		return err
	}

	slog.Info("MediaFlow Scan Complete", "directory", directory)
	return nil
}

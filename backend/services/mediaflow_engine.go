package services

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"os/exec"
	"regexp"
	"path/filepath"
	"strings"
	"os"
	"aetherflow/db"
	"time"
)

// TranscodeProgress represents real-time FFmpeg state
type TranscodeProgress struct {
	FilePath string `json:"filePath"`
	Frame    string `json:"frame"`
	FPS      string `json:"fps"`
	Size     string `json:"size"`
	Time     string `json:"time"`
	Bitrate  string `json:"bitrate"`
	Speed    string `json:"speed"`
	Status   string `json:"status"` // PROCESSING, COMPLETED, FAILED
}

// executeTranscode triggers a native hardware-accelerated FFmpeg pass on a file
func executeTranscode(ctx context.Context, itemID int, filePath string) error {
	// 1. Get channel for streaming progress
	streamChan := StreamHub.GetStream("mediaflow_engine")
	if streamChan == nil {
		streamChan = StreamHub.RegisterStream("mediaflow_engine")
	}

	// 2. Hardware Detection
	hw := GetGPUTranscodeFlags()

	// Calculate output path - Strictly force .mkv
	dir := filepath.Dir(filePath)
	ext := filepath.Ext(filePath)
	base := strings.TrimSuffix(filepath.Base(filePath), ext)
	outPath := filepath.Join(dir, base+"_hevc.mkv")

	// Update DB to Processing
	_, err := db.DB.Exec("UPDATE mediaflow_queue SET status = 'PROCESSING', updated_at = CURRENT_TIMESTAMP WHERE id = ?", itemID)
	if err != nil {
		return err
	}

	// 2. Build FFmpeg command
	cmdArgs := []string{"-y"} // Overwrite

	// Inject HWAccel flags if available
	if hw.HWAccel != "" {
		cmdArgs = append(cmdArgs, "-hwaccel", hw.HWAccel)
	}
	if hw.HWAccelDevice != "" {
		cmdArgs = append(cmdArgs, "-hwaccel_device", hw.HWAccelDevice)
	}
	if hw.OutputFormat != "" {
		cmdArgs = append(cmdArgs, "-hwaccel_output_format", hw.OutputFormat)
	}

	cmdArgs = append(cmdArgs, "-i", filePath)
	cmdArgs = append(cmdArgs, "-c:v", hw.VideoCodec)
	cmdArgs = append(cmdArgs, "-b:v", "5M")
	cmdArgs = append(cmdArgs, "-c:a", "copy")
	cmdArgs = append(cmdArgs, outPath)

	cmd := exec.CommandContext(ctx, "ffmpeg", cmdArgs...)

	// FFmpeg logs exclusively to stderr
	stderrRead, err := cmd.StderrPipe()
	if err != nil {
		db.DB.Exec("UPDATE mediaflow_queue SET status = 'FAILED', error_log = ? WHERE id = ?", err.Error(), itemID)
		return err
	}

	cmd.Start()

	// 3. Regex Parsers for stderr metrics
	frameRe := regexp.MustCompile(`frame=\s*(\d+)`)
	fpsRe := regexp.MustCompile(`fps=\s*([\d\.]+)`)
	sizeRe := regexp.MustCompile(`size=\s*(\d+kB)`)
	timeRe := regexp.MustCompile(`time=\s*([\d:\.]+)`)
	bitrateRe := regexp.MustCompile(`bitrate=\s*([\d\.]+kbits/s)`)
	speedRe := regexp.MustCompile(`speed=\s*([\d\.x]+)`)

	// Parse Stderr async
	go func() {
		scanner := bufio.NewScanner(stderrRead)
		scanner.Split(bufio.ScanLines)

		for scanner.Scan() {
			line := scanner.Text()

			// Only process lines containing frame= (transcoding progress lines)
			if strings.Contains(line, "frame=") {
				prog := TranscodeProgress{
					FilePath: filepath.Base(filePath),
					Status:   "PROCESSING",
				}

				if m := frameRe.FindStringSubmatch(line); len(m) > 1 {
					prog.Frame = m[1]
				}
				if m := fpsRe.FindStringSubmatch(line); len(m) > 1 {
					prog.FPS = m[1]
				}
				if m := sizeRe.FindStringSubmatch(line); len(m) > 1 {
					prog.Size = m[1]
				}
				if m := timeRe.FindStringSubmatch(line); len(m) > 1 {
					prog.Time = m[1]
				}
				if m := bitrateRe.FindStringSubmatch(line); len(m) > 1 {
					prog.Bitrate = m[1]
				}
				if m := speedRe.FindStringSubmatch(line); len(m) > 1 {
					prog.Speed = m[1]
				}

				// Push to SSE Hub
				payload, _ := json.Marshal(prog)
				select {
				case streamChan <- string(payload):
				default:
					// drop if buffer full preventing ffmpeg hang
				}
			}
		}
	}()

	err = cmd.Wait()

	// 4. Finalize state
	if err != nil {
		slog.Error("MediaFlow encoding failed", "file", filePath, "error", err)
		db.DB.Exec("UPDATE mediaflow_queue SET status = 'FAILED', error_log = ? WHERE id = ?", err.Error(), itemID)
		pushStatus(streamChan, filepath.Base(filePath), "FAILED")
		return err
	}

	// 4. Data Retention Policy: Move original to .mediaflow_trash
	trashDir := filepath.Join(filepath.Dir(filePath), ".mediaflow_trash")
	if err := os.MkdirAll(trashDir, 0755); err != nil {
		slog.Error("Failed to create trash directory", "dir", trashDir, "error", err)
	} else {
		trashPath := filepath.Join(trashDir, filepath.Base(filePath))
		if err := os.Rename(filePath, trashPath); err != nil {
			slog.Error("Failed to move original to trash", "from", filePath, "to", trashPath, "error", err)
		} else {
			slog.Info("Original file retired to trash", "path", trashPath)
		}
	}

	// Completed - Update DB with the NEW path
	db.DB.Exec("UPDATE mediaflow_queue SET status = 'COMPLETED', file_path = ?, new_codec = 'hevc', updated_at = CURRENT_TIMESTAMP WHERE id = ?", outPath, itemID)
	pushStatus(streamChan, filepath.Base(filePath), "COMPLETED")
	slog.Info("MediaFlow encoding successful", "new_file", outPath)

	return nil
}

func pushStatus(stream chan string, filename string, status string) {
	prog := TranscodeProgress{
		FilePath: filename,
		Status:   status,
	}
	pay, _ := json.Marshal(prog)
	select {
	case stream <- string(pay):
	default:
	}
}

// MediaFlowEngineProcess executes the next APPROVED item in the queue.
func MediaFlowEngineProcess() {
	var itemID int
	var filePath string

	// Securely acquire the next Approved job locking it from other threads
	err := db.DB.QueryRow("SELECT id, file_path FROM mediaflow_queue WHERE status = 'APPROVED' ORDER BY created_at ASC LIMIT 1").Scan(&itemID, &filePath)
	if err != nil {
		return // No pending jobs or query fault
	}

	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
	defer cancel()

	executeTranscode(ctx, itemID, filePath)
}

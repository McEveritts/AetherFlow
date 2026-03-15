package services

import (
	"bufio"
	"encoding/json"
	"log"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// LogEntry represents a single log line with metadata.
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"`    // "journald", "syslog", "auth.log", etc.
	Unit     string    `json:"unit"`      // systemd unit name (if journald)
	Priority string    `json:"priority"`  // "emerg","alert","crit","err","warning","notice","info","debug"
	Message  string    `json:"message"`
	Hostname string    `json:"hostname"`
}

// LogFilter specifies search criteria for querying logs.
type LogFilter struct {
	Source    string    `json:"source"`
	Unit     string    `json:"unit"`
	Priority string    `json:"priority"`
	Keyword  string    `json:"keyword"`
	Since    time.Time `json:"since"`
	Until    time.Time `json:"until"`
	Limit    int       `json:"limit"`
	Offset   int       `json:"offset"`
}

// LogAggregator manages log collection and provides queryable access.
type LogAggregator struct {
	mu        sync.RWMutex
	buffer    []LogEntry
	maxSize   int
	listeners []chan LogEntry
	listMu    sync.Mutex
}

// Global log aggregator instance.
var Logs *LogAggregator

// InitLogAggregator creates the global log aggregator and starts streaming.
func InitLogAggregator() {
	Logs = &LogAggregator{
		buffer:  make([]LogEntry, 0, 10000),
		maxSize: 10000,
	}

	if runtime.GOOS == "linux" {
		go Logs.streamJournalctl()
	} else {
		log.Printf("Log aggregation: journalctl streaming not available on %s (running in read-only mode)", runtime.GOOS)
	}

	log.Println("Log aggregator initialized")
}

// Subscribe creates a new channel that receives log entries in real-time.
func (la *LogAggregator) Subscribe() chan LogEntry {
	ch := make(chan LogEntry, 256)
	la.listMu.Lock()
	la.listeners = append(la.listeners, ch)
	la.listMu.Unlock()
	return ch
}

// Unsubscribe removes a listener channel.
func (la *LogAggregator) Unsubscribe(ch chan LogEntry) {
	la.listMu.Lock()
	defer la.listMu.Unlock()
	for i, listener := range la.listeners {
		if listener == ch {
			la.listeners = append(la.listeners[:i], la.listeners[i+1:]...)
			close(ch)
			return
		}
	}
}

// push adds a log entry to the ring buffer and broadcasts to listeners.
func (la *LogAggregator) push(entry LogEntry) {
	la.mu.Lock()
	if len(la.buffer) >= la.maxSize {
		// Remove oldest 10% to avoid constant shifting
		removeCount := la.maxSize / 10
		la.buffer = la.buffer[removeCount:]
	}
	la.buffer = append(la.buffer, entry)
	la.mu.Unlock()

	// Broadcast to listeners (non-blocking)
	la.listMu.Lock()
	for _, ch := range la.listeners {
		select {
		case ch <- entry:
		default:
			// Listener is too slow, skip
		}
	}
	la.listMu.Unlock()
}

// Query searches the log buffer with the given filter.
func (la *LogAggregator) Query(filter LogFilter) []LogEntry {
	la.mu.RLock()
	defer la.mu.RUnlock()

	if filter.Limit <= 0 || filter.Limit > 500 {
		filter.Limit = 100
	}

	var results []LogEntry
	keyword := strings.ToLower(filter.Keyword)

	// Iterate in reverse (newest first)
	skipped := 0
	for i := len(la.buffer) - 1; i >= 0 && len(results) < filter.Limit; i-- {
		entry := la.buffer[i]

		// Apply filters
		if filter.Source != "" && entry.Source != filter.Source {
			continue
		}
		if filter.Unit != "" && entry.Unit != filter.Unit {
			continue
		}
		if filter.Priority != "" && entry.Priority != filter.Priority {
			continue
		}
		if keyword != "" && !strings.Contains(strings.ToLower(entry.Message), keyword) {
			continue
		}
		if !filter.Since.IsZero() && entry.Timestamp.Before(filter.Since) {
			continue
		}
		if !filter.Until.IsZero() && entry.Timestamp.After(filter.Until) {
			continue
		}

		// Apply offset
		if skipped < filter.Offset {
			skipped++
			continue
		}

		results = append(results, entry)
	}

	return results
}

// GetSources returns a list of unique log sources from the buffer.
func (la *LogAggregator) GetSources() []string {
	la.mu.RLock()
	defer la.mu.RUnlock()

	seen := make(map[string]bool)
	var sources []string

	for _, entry := range la.buffer {
		key := entry.Source
		if entry.Unit != "" {
			key = entry.Source + ":" + entry.Unit
		}
		if !seen[key] {
			seen[key] = true
			sources = append(sources, key)
		}
	}

	return sources
}

// journalctl priority mapping
var journaldPriorities = map[string]string{
	"0": "emerg",
	"1": "alert",
	"2": "crit",
	"3": "err",
	"4": "warning",
	"5": "notice",
	"6": "info",
	"7": "debug",
}

// streamJournalctl starts a journalctl -f subprocess and parses JSON output.
func (la *LogAggregator) streamJournalctl() {
	for {
		cmd := exec.Command("journalctl", "-f", "-o", "json", "--no-pager", "-n", "0")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Printf("Log aggregator: failed to create journalctl pipe: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}

		if err := cmd.Start(); err != nil {
			log.Printf("Log aggregator: failed to start journalctl: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}

		log.Println("Log aggregator: streaming from journalctl")
		scanner := bufio.NewScanner(stdout)
		// Increase buffer size for long log lines
		scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)

		for scanner.Scan() {
			var journalEntry map[string]interface{}
			if err := json.Unmarshal(scanner.Bytes(), &journalEntry); err != nil {
				continue
			}

			entry := LogEntry{
				Timestamp: time.Now(),
				Source:    "journald",
			}

			// Parse timestamp
			if ts, ok := journalEntry["__REALTIME_TIMESTAMP"].(string); ok {
				// microseconds since epoch
				if len(ts) > 6 {
					sec := ts[:len(ts)-6]
					usec := ts[len(ts)-6:]
					var s, us int64
					for _, c := range sec {
						s = s*10 + int64(c-'0')
					}
					for _, c := range usec {
						us = us*10 + int64(c-'0')
					}
					entry.Timestamp = time.Unix(s, us*1000)
				}
			}

			if msg, ok := journalEntry["MESSAGE"].(string); ok {
				entry.Message = msg
			}

			if unit, ok := journalEntry["_SYSTEMD_UNIT"].(string); ok {
				entry.Unit = unit
			} else if svcName, ok := journalEntry["SYSLOG_IDENTIFIER"].(string); ok {
				entry.Unit = svcName
			}

			if prio, ok := journalEntry["PRIORITY"].(string); ok {
				if name, exists := journaldPriorities[prio]; exists {
					entry.Priority = name
				} else {
					entry.Priority = prio
				}
			}

			if host, ok := journalEntry["_HOSTNAME"].(string); ok {
				entry.Hostname = host
			}

			la.push(entry)
		}

		if err := cmd.Wait(); err != nil {
			log.Printf("Log aggregator: journalctl exited: %v", err)
		}

		log.Println("Log aggregator: journalctl stream ended, restarting in 5s...")
		time.Sleep(5 * time.Second)
	}
}

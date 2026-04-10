package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// ── Phase 30: SQLite WAL Concurrency Load Tests ─────────────────────────
//
// These tests validate that the SQLite WAL configuration (journal_mode=WAL,
// busy_timeout=5000, MaxOpenConns=1) can sustain concurrent read/write pressure
// without SQLITE_BUSY errors or data corruption.

// setupWALTestDB creates a temporary WAL-mode SQLite database for testing.
func setupWALTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test_wal.sqlite")

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}

	// Mirror production configuration
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	pragmas := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA busy_timeout=5000;",
		"PRAGMA cache_size=-64000;",
		"PRAGMA foreign_keys=ON;",
		"PRAGMA temp_store=MEMORY;",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			t.Fatalf("PRAGMA failed: %s — %v", p, err)
		}
	}

	// Verify WAL mode is active
	var journalMode string
	if err := db.QueryRow("PRAGMA journal_mode;").Scan(&journalMode); err != nil {
		t.Fatalf("Failed to query journal_mode: %v", err)
	}
	if journalMode != "wal" {
		t.Fatalf("Expected WAL mode, got %q", journalMode)
	}

	// Create a test table
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS wal_test (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		key TEXT NOT NULL,
		value TEXT NOT NULL,
		created_at TEXT DEFAULT (datetime('now'))
	)`)
	if err != nil {
		t.Fatalf("Failed to create test table: %v", err)
	}

	t.Cleanup(func() {
		db.Close()
		os.Remove(path)
		os.Remove(path + "-wal")
		os.Remove(path + "-shm")
	})

	return db
}

func TestWAL_ModeActive(t *testing.T) {
	db := setupWALTestDB(t)
	var mode string
	db.QueryRow("PRAGMA journal_mode;").Scan(&mode)
	if mode != "wal" {
		t.Errorf("Expected WAL journal mode, got %q", mode)
	}
}

func TestWAL_BusyTimeoutSet(t *testing.T) {
	db := setupWALTestDB(t)
	var timeout int
	db.QueryRow("PRAGMA busy_timeout;").Scan(&timeout)
	if timeout != 5000 {
		t.Errorf("Expected busy_timeout=5000, got %d", timeout)
	}
}

func TestWAL_ConcurrentWriters(t *testing.T) {
	db := setupWALTestDB(t)

	const numWriters = 10
	const writesPerWorker = 50
	var errors int32

	var wg sync.WaitGroup
	wg.Add(numWriters)

	start := time.Now()

	for i := 0; i < numWriters; i++ {
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < writesPerWorker; j++ {
				key := fmt.Sprintf("worker-%d-key-%d", worker, j)
				value := fmt.Sprintf("value-%d-%d", worker, j)
				_, err := db.Exec("INSERT INTO wal_test (key, value) VALUES (?, ?)", key, value)
				if err != nil {
					t.Logf("Write error (worker %d, write %d): %v", worker, j, err)
					atomic.AddInt32(&errors, 1)
				}
			}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	// Verify all rows were inserted
	var count int
	db.QueryRow("SELECT COUNT(*) FROM wal_test").Scan(&count)

	expectedTotal := numWriters * writesPerWorker
	successfulWrites := expectedTotal - int(errors)

	t.Logf("WAL concurrent write: %d/%d rows in %v (%d errors)",
		count, expectedTotal, elapsed, errors)

	// Allow up to 5% failure rate under extreme concurrency
	if float64(errors)/float64(expectedTotal) > 0.05 {
		t.Errorf("Too many write errors: %d/%d (%.1f%%)",
			errors, expectedTotal, float64(errors)/float64(expectedTotal)*100)
	}

	if count != successfulWrites {
		t.Errorf("Row count mismatch: expected %d, got %d", successfulWrites, count)
	}
}

func TestWAL_ConcurrentReadsDuringWrites(t *testing.T) {
	db := setupWALTestDB(t)

	// Pre-seed some data
	for i := 0; i < 100; i++ {
		db.Exec("INSERT INTO wal_test (key, value) VALUES (?, ?)",
			fmt.Sprintf("seed-%d", i), fmt.Sprintf("val-%d", i))
	}

	const numReaders = 20
	const readsPerWorker = 50
	const numWriters = 5
	const writesPerWorker = 20

	var readErrors, writeErrors int32

	var wg sync.WaitGroup
	wg.Add(numReaders + numWriters)

	// Concurrent readers
	for i := 0; i < numReaders; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < readsPerWorker; j++ {
				var count int
				if err := db.QueryRow("SELECT COUNT(*) FROM wal_test").Scan(&count); err != nil {
					atomic.AddInt32(&readErrors, 1)
				}
			}
		}()
	}

	// Concurrent writers
	for i := 0; i < numWriters; i++ {
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < writesPerWorker; j++ {
				_, err := db.Exec("INSERT INTO wal_test (key, value) VALUES (?, ?)",
					fmt.Sprintf("concurrent-%d-%d", worker, j),
					fmt.Sprintf("cval-%d-%d", worker, j))
				if err != nil {
					atomic.AddInt32(&writeErrors, 1)
				}
			}
		}(i)
	}

	wg.Wait()

	t.Logf("Concurrent R/W: read_errors=%d, write_errors=%d", readErrors, writeErrors)

	if readErrors > 0 {
		t.Errorf("WAL should allow concurrent reads without errors, got %d read errors", readErrors)
	}
	if writeErrors > int32(numWriters*writesPerWorker/20) { // Allow 5% write failures
		t.Errorf("Too many write errors during concurrent R/W: %d", writeErrors)
	}
}

func TestWAL_TransactionCommitVisibility(t *testing.T) {
	db := setupWALTestDB(t)

	// Insert within a committed transaction
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Failed to begin transaction: %v", err)
	}
	tx.Exec("INSERT INTO wal_test (key, value) VALUES ('commit-test', 'committed')")
	if err := tx.Commit(); err != nil {
		t.Fatalf("Failed to commit: %v", err)
	}

	// Committed data should be visible
	var value string
	err = db.QueryRow("SELECT value FROM wal_test WHERE key = 'commit-test'").Scan(&value)
	if err != nil {
		t.Fatalf("Committed row not found: %v", err)
	}
	if value != "committed" {
		t.Errorf("Expected 'committed', got %q", value)
	}
}

func TestWAL_TransactionRollbackInvisible(t *testing.T) {
	db := setupWALTestDB(t)

	// Insert within a rolled-back transaction
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Failed to begin transaction: %v", err)
	}
	tx.Exec("INSERT INTO wal_test (key, value) VALUES ('rollback-test', 'should-not-exist')")
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Failed to rollback: %v", err)
	}

	// Rolled-back data should NOT be visible
	var count int
	db.QueryRow("SELECT COUNT(*) FROM wal_test WHERE key = 'rollback-test'").Scan(&count)
	if count != 0 {
		t.Errorf("Rolled-back row should not be visible, found %d rows", count)
	}
}

func TestWAL_LargeInsertBatch(t *testing.T) {
	db := setupWALTestDB(t)

	const batchSize = 1000

	start := time.Now()

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Failed to begin transaction: %v", err)
	}

	stmt, err := tx.Prepare("INSERT INTO wal_test (key, value) VALUES (?, ?)")
	if err != nil {
		t.Fatalf("Failed to prepare statement: %v", err)
	}

	for i := 0; i < batchSize; i++ {
		_, err := stmt.Exec(fmt.Sprintf("batch-%d", i), fmt.Sprintf("bval-%d", i))
		if err != nil {
			t.Fatalf("Insert %d failed: %v", i, err)
		}
	}

	stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatalf("Batch commit failed: %v", err)
	}

	elapsed := time.Since(start)

	var count int
	db.QueryRow("SELECT COUNT(*) FROM wal_test").Scan(&count)

	if count != batchSize {
		t.Errorf("Expected %d rows, got %d", batchSize, count)
	}

	t.Logf("Batch insert: %d rows in %v (%.0f rows/sec)",
		batchSize, elapsed, float64(batchSize)/elapsed.Seconds())

	// Performance gate: 1000 rows should complete in under 5 seconds
	if elapsed > 5*time.Second {
		t.Errorf("Batch insert too slow: %v (expected < 5s)", elapsed)
	}
}

func TestDBHealthCheck_Contract(t *testing.T) {
	// Save and restore global DB
	origDB := DB
	defer func() { DB = origDB }()

	DB = setupWALTestDB(t)

	info, err := DBHealthCheck()
	if err != nil {
		t.Fatalf("DBHealthCheck failed: %v", err)
	}

	if info == nil {
		t.Fatal("Expected non-nil health info")
	}

	if _, ok := info["latency_ms"]; !ok {
		t.Error("DBHealthCheck should include latency_ms")
	}
}

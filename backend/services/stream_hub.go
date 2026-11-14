package services

import (
	"sync"
)

// ActiveStreamRegistry provides a thread-safe hub mapping Application names to active SSE Status Channels
type activeStreamRegistry struct {
	sync.RWMutex
	streams map[string]chan string
}

var StreamHub = &activeStreamRegistry{
	streams: make(map[string]chan string),
}

// RegisterStream binds a channel for an application, returning the existing
// channel if one is already active so callers never overwrite an open stream.
func (r *activeStreamRegistry) RegisterStream(appName string) chan string {
	r.Lock()
	defer r.Unlock()
	if existing, exists := r.streams[appName]; exists {
		return existing
	}
	ch := make(chan string, 50)
	r.streams[appName] = ch
	return ch
}

// TryRegisterStream atomically registers a new deployment stream only when no
// stream is currently active for appName.
func (r *activeStreamRegistry) TryRegisterStream(appName string) (chan string, bool) {
	r.Lock()
	defer r.Unlock()
	if _, exists := r.streams[appName]; exists {
		return nil, false
	}
	ch := make(chan string, 50)
	r.streams[appName] = ch
	return ch, true
}

// GetStream fetches the channel. Returns nil if not deploying.
func (r *activeStreamRegistry) GetStream(appName string) chan string {
	r.RLock()
	defer r.RUnlock()
	return r.streams[appName]
}

// DeregisterStream closes and cleans up the channel for the specific application.
func (r *activeStreamRegistry) DeregisterStream(appName string) {
	r.Lock()
	defer r.Unlock()
	if ch, exists := r.streams[appName]; exists {
		delete(r.streams, appName)
		close(ch)
	}
}

// DeregisterStreamIfMatch closes and deletes the channel only if the currently
// registered channel matches expected, preventing concurrent close/send races.
func (r *activeStreamRegistry) DeregisterStreamIfMatch(appName string, expected chan string) {
	if expected == nil {
		return
	}
	r.Lock()
	defer r.Unlock()
	if ch, exists := r.streams[appName]; exists && ch == expected {
		delete(r.streams, appName)
		close(ch)
	}
}

// SendStreamMessage safely sends a status line on ch without panicking if ch was closed.
func SendStreamMessage(ch chan string, msg string) (sent bool) {
	if ch == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			sent = false
		}
	}()
	ch <- msg
	return true
}

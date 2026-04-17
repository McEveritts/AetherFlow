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

// RegisterStream binds a new channel for an application
func (r *activeStreamRegistry) RegisterStream(appName string) chan string {
	r.Lock()
	defer r.Unlock()
	ch := make(chan string, 50)
	r.streams[appName] = ch
	return ch
}

// GetStream fetches the channel. Returns nil if not deploying.
func (r *activeStreamRegistry) GetStream(appName string) chan string {
	r.RLock()
	defer r.RUnlock()
	return r.streams[appName]
}

// DeregisterStream closes and cleans up the channel for the specific application
func (r *activeStreamRegistry) DeregisterStream(appName string) {
	r.Lock()
	defer r.Unlock()
	if ch, exists := r.streams[appName]; exists {
		close(ch)
		delete(r.streams, appName)
	}
}

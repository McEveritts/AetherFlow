package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"aetherflow/db"
	"aetherflow/services"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

func canonicalOriginAuthority(scheme, hostPort string) string {
	s := strings.ToLower(strings.TrimSpace(scheme))
	h := strings.ToLower(strings.TrimSpace(hostPort))
	if h == "" {
		return ""
	}
	switch s {
	case "http", "ws":
		if !strings.Contains(h, ":") || strings.HasSuffix(h, "]") {
			return h + ":80"
		}
	case "https", "wss":
		if !strings.Contains(h, ":") || strings.HasSuffix(h, "]") {
			return h + ":443"
		}
	}
	return h
}

func isTrustedWSProxyRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("TRUST_PROXY_HEADERS")), "false") ||
		strings.TrimSpace(os.Getenv("TRUST_PROXY_HEADERS")) == "0" {
		return false
	}
	remoteAddr := strings.TrimSpace(r.RemoteAddr)
	if remoteAddr == "" {
		// Synthetic in-process http.NewRequest without a socket peer (matching Rust peer_ip == None).
		return strings.TrimSpace(os.Getenv("TRUSTED_PROXIES")) == ""
	}
	host := remoteAddr
	if splitHost, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = splitHost
	} else if strings.HasPrefix(remoteAddr, "[") && strings.HasSuffix(remoteAddr, "]") {
		host = remoteAddr[1 : len(remoteAddr)-1]
	}
	return isConfiguredTrustedProxyIP(net.ParseIP(host))
}

func requestExpectedWSScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if isTrustedWSProxyRequest(r) {
		if proto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); proto != "" {
			if strings.EqualFold(proto, "https") {
				return "https"
			}
			if strings.EqualFold(proto, "http") {
				return "http"
			}
			return ""
		}
		if strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Port"), ",")[0]) == "443" {
			return "https"
		}
	}
	return "http"
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	// Strict Origin validation matching Rust af-api ws.rs:
	//   1. Empty Origin allowed ONLY for non-cookie clients (Bearer/ticket CLI)
	//   2. Exact scheme + normalized host:port match against request Host
	//   3. Exact scheme + normalized host:port match against ALLOWED_CORS_ORIGIN
	CheckOrigin: func(r *http.Request) bool {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin == "" {
			// Browser cookie upgrades MUST carry an Origin header.
			return strings.TrimSpace(r.Header.Get("Cookie")) == ""
		}
		parsed, err := url.Parse(origin)
		if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return false
		}
		if parsed.Path != "" && parsed.Path != "/" {
			return false
		}
		var originScheme string
		switch strings.ToLower(parsed.Scheme) {
		case "http", "ws":
			originScheme = "http"
		case "https", "wss":
			originScheme = "https"
		default:
			return false
		}
		if parsed.Hostname() == "" {
			return false
		}
		originAuth := canonicalOriginAuthority(originScheme, parsed.Host)
		expectedScheme := requestExpectedWSScheme(r)
		reqHost := strings.TrimSpace(r.Host)
		if expectedScheme != "" && reqHost != "" && originScheme == expectedScheme {
			if originAuth == canonicalOriginAuthority(expectedScheme, reqHost) {
				return true
			}
		}
		if allowed := os.Getenv("ALLOWED_CORS_ORIGIN"); allowed != "" {
			for _, o := range strings.Split(allowed, ",") {
				o = strings.TrimSpace(o)
				if o == "" {
					continue
				}
				allowedParsed, err := url.Parse(o)
				if err != nil || allowedParsed.Hostname() == "" {
					continue
				}
				allowedScheme := strings.ToLower(allowedParsed.Scheme)
				if allowedScheme == originScheme && originAuth == canonicalOriginAuthority(allowedScheme, allowedParsed.Host) {
					return true
				}
			}
		}
		slog.Warn("WebSocket origin rejected",
			"origin", origin,
			"request_host", r.Host,
		)
		return false
	},
}

func SanitizeServicesForViewer(raw interface{}, isAdmin bool) interface{} {
	if isAdmin || raw == nil {
		return raw
	}
	typed, ok := raw.(map[string]gin.H)
	if !ok {
		return raw
	}
	sanitized := make(map[string]gin.H, len(typed))
	for svcKey, entry := range typed {
		clean := make(gin.H, len(entry))
		for k, v := range entry {
			if k == "api_key" {
				continue
			}
			clean[k] = v
		}
		if errStr, ok := clean["update_error"].(string); ok && errStr != "" {
			clean["update_error"] = "Update check failed"
		}
		if logLine, ok := clean["log_line"].(string); ok && logLine != "" {
			clean["log_line"] = "Package operation in progress"
		}
		sanitized[svcKey] = clean
	}
	return sanitized
}

type Client struct {
	hub        *Hub
	conn       *websocket.Conn
	send       chan []byte
	userID     int
	role       string
	sessionJTI string
	sessionVer int64
}

type hubEnvelope struct {
	raw          []byte
	nonAdminRaw  []byte
	adminOnly    bool
	targetUserID *int
}

type Hub struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	dispatch   chan hubEnvelope
	register   chan *Client
	unregister chan *Client
	mu         sync.Mutex
}

func newHub() *Hub {
	return &Hub{
		broadcast:  make(chan []byte, 256),
		dispatch:   make(chan hubEnvelope, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		clients:    make(map[*Client]bool),
	}
}

func isTokenRevokedBeyondGraceForUser(jti string, userID int) bool {
	if jti == "" || !db.IsTokenRevoked(jti) {
		return false
	}
	if graceEntry, ok := isWithinRotationGrace(jti); ok && graceEntry.userID == userID {
		return false
	}
	return true
}

func evaluateClientDelivery(cl *Client, env hubEnvelope) (alive bool, deliver bool) {
	role := cl.role
	if db.DB != nil && cl.userID > 0 {
		if isTokenRevokedBeyondGraceForUser(cl.sessionJTI, cl.userID) {
			return false, false
		}
		subj, err := loadActiveHumanSubject(db.DB, cl.userID)
		if err != nil || cl.sessionVer < subj.sessionsRevokedAfter {
			return false, false
		}
		role = subj.role
		cl.role = role
	}
	if env.adminOnly && role != "admin" {
		return true, false
	}
	if env.targetUserID != nil && *env.targetUserID > 0 && cl.userID != *env.targetUserID {
		return true, false
	}
	return true, true
}

func (h *Hub) fanout(env hubEnvelope) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for client := range h.clients {
		alive, deliver := evaluateClientDelivery(client, env)
		if !alive {
			close(client.send)
			delete(h.clients, client)
			continue
		}
		if !deliver {
			continue
		}
		out := env.raw
		if client.role != "admin" && len(env.nonAdminRaw) > 0 {
			out = env.nonAdminRaw
		}
		select {
		case client.send <- out:
		default:
			close(client.send)
			delete(h.clients, client)
		}
	}
}

func (h *Hub) sendToClient(cl *Client, msg []byte) {
	if cl == nil || len(msg) == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.clients[cl] {
		return
	}
	select {
	case cl.send <- msg:
	default:
	}
}

func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()
		case message := <-h.broadcast:
			h.fanout(hubEnvelope{raw: message})
		case env := <-h.dispatch:
			h.fanout(env)
		}
	}
}

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = 54 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 70 * time.Second
)

func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// The hub closed the channel.
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// readPump reads messages from the WebSocket connection.
// It resets the read deadline on every pong, detecting dead clients.
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				slog.Info("WebSocket unexpected close", "error", err)
			}
			break
		}
		// Client messages (e.g., PING from frontend) are acknowledged via pong handler above.
		// No application-level messages are expected from the client.
	}
}

// Global WSHub instance
var WSHub = newHub()

func init() {
	go WSHub.run()
	go broadcastMetricsLoop()
}

const wsTicketTTL = 30 * time.Second

type wsTicketEntry struct {
	UserID     int
	Role       string
	SessionJTI string
	SessionVer int64
	ClientIP   string
	ExpiresAt  int64
}

var (
	wsTickets   = make(map[string]wsTicketEntry)
	wsTicketsMu sync.Mutex
)

// IssueWSTicket generates a short-lived (30s) single-use ticket for WebSocket authentication.
func IssueWSTicket(c *gin.Context) {
	rawUserID, exists := c.Get("user_id")
	if !exists {
		Unauthorized(c, "Unauthorized")
		return
	}
	userID, ok := rawUserID.(int)
	if !ok || userID <= 0 {
		Unauthorized(c, "Unauthorized")
		return
	}

	role, _ := c.Get("user_role")
	roleStr, _ := role.(string)
	if roleStr == "" {
		roleStr = "user"
	}
	jtiVal, _ := c.Get("session_jti")
	sessionJTI, _ := jtiVal.(string)
	sessionJTI = strings.TrimSpace(sessionJTI)
	if sessionJTI == "" {
		anonBytes := make([]byte, 16)
		if _, err := rand.Read(anonBytes); err != nil {
			InternalError(c, "Failed to generate WebSocket session binding")
			return
		}
		sessionJTI = "ws-anon-" + hex.EncodeToString(anonBytes)
	}
	var sessionVer int64
	if verVal, hasVer := c.Get("session_ver"); hasVer {
		switch v := verVal.(type) {
		case int64:
			sessionVer = v
		case int:
			sessionVer = int64(v)
		}
	}

	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		InternalError(c, "Failed to generate WebSocket ticket")
		return
	}
	ticket := hex.EncodeToString(b)
	nowUnix := time.Now().Unix()

	wsTicketsMu.Lock()
	for k, existing := range wsTickets {
		if existing.ExpiresAt > 0 && nowUnix > existing.ExpiresAt {
			delete(wsTickets, k)
		}
	}
	wsTickets[ticket] = wsTicketEntry{
		UserID:     userID,
		Role:       roleStr,
		SessionJTI: sessionJTI,
		SessionVer: sessionVer,
		ClientIP:   c.ClientIP(),
		ExpiresAt:  nowUnix + int64(wsTicketTTL.Seconds()),
	}
	wsTicketsMu.Unlock()

	go func(t string) {
		time.Sleep(wsTicketTTL)
		wsTicketsMu.Lock()
		delete(wsTickets, t)
		wsTicketsMu.Unlock()
	}(ticket)

	c.JSON(http.StatusOK, gin.H{"ticket": ticket})
}

func isLoopbackIP(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1" || ip == "localhost"
}

// HandleWebSocket authenticates the request via WS ticket with IP-binding and session revocation validation.
func HandleWebSocket(c *gin.Context) {
	ticket := c.Query("ticket")
	if ticket == "" {
		RespondError(c, http.StatusUnauthorized, "WS_MISSING_TICKET", "Missing ticket")
		return
	}

	wsTicketsMu.Lock()
	entry, ok := wsTickets[ticket]
	if ok {
		delete(wsTickets, ticket) // single-use token consumed immediately
	}
	wsTicketsMu.Unlock()

	if !ok || (entry.ExpiresAt > 0 && time.Now().Unix() > entry.ExpiresAt) {
		RespondError(c, http.StatusUnauthorized, "WS_INVALID_TICKET", "Invalid or expired ticket")
		return
	}

	// IP-binding: reject tickets used from a different IP than issuance
	clientIP := c.ClientIP()
	if entry.ClientIP != "" && entry.ClientIP != clientIP && !(isLoopbackIP(entry.ClientIP) && isLoopbackIP(clientIP)) {
		slog.Warn("WS ticket IP mismatch", "issued_to", entry.ClientIP, "used_from", clientIP)
		RespondError(c, http.StatusForbidden, "WS_IP_MISMATCH", "Ticket IP mismatch")
		return
	}

	resolvedRole := entry.Role
	if resolvedRole == "" {
		resolvedRole = "user"
	}
	if db.DB != nil && entry.UserID > 0 {
		if isTokenRevokedBeyondGraceForUser(entry.SessionJTI, entry.UserID) {
			RespondError(c, http.StatusUnauthorized, ErrCodeSessionExpired, "Session revoked")
			return
		}
		subj, subErr := loadActiveHumanSubject(db.DB, entry.UserID)
		if subErr != nil {
			if errors.Is(subErr, errSubjectSuspended) {
				RespondError(c, http.StatusForbidden, ErrCodeForbidden, "Account is not active")
				return
			}
			RespondError(c, http.StatusUnauthorized, ErrCodeUnauthorized, "Unauthorized")
			return
		}
		if entry.SessionVer < subj.sessionsRevokedAfter {
			RespondError(c, http.StatusUnauthorized, ErrCodeSessionExpired, "Session revoked")
			return
		}
		resolvedRole = subj.role
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		slog.Error("WebSocket upgrade error", "error", err)
		return
	}
	client := &Client{
		hub:        WSHub,
		conn:       conn,
		send:       make(chan []byte, 256),
		userID:     entry.UserID,
		role:       resolvedRole,
		sessionJTI: entry.SessionJTI,
		sessionVer: entry.SessionVer,
	}
	client.hub.register <- client

	// Immediately push an initial METRICS_UPDATE snapshot so the newly connected
	// client renders live metrics on frame 0 without waiting for the next tick.
	go func(cl *Client) {
		systemStateMutex.RLock()
		m := cachedMetrics
		s := cachedServices
		systemStateMutex.RUnlock()

		if m == nil {
			m = services.GetSystemMetricsCore()
			systemStateMutex.Lock()
			cachedMetrics = m
			systemStateMutex.Unlock()
		}
		if s == nil {
			s = services.GetActiveServices()
			systemStateMutex.Lock()
			cachedServices = s
			systemStateMutex.Unlock()
		}

		payload := map[string]interface{}{
			"type": "METRICS_UPDATE",
			"data": map[string]interface{}{
				"system":   m,
				"services": SanitizeServicesForViewer(s, cl.role == "admin"),
			},
		}
		if message, err := json.Marshal(payload); err == nil {
			cl.hub.sendToClient(cl, message)
		}
	}(client)

	go client.writePump()
	go client.readPump()
}

var (
	cachedServices   interface{}
	cachedMetrics    interface{}
	systemStateMutex sync.RWMutex
)

func maintainSystemState() {
	// Seed initial state immediately so the first WebSocket client gets valid data
	initialMetrics := services.GetSystemMetricsCore()
	initialServices := services.GetActiveServices()
	systemStateMutex.Lock()
	cachedMetrics = initialMetrics
	cachedServices = initialServices
	systemStateMutex.Unlock()

	metricsTicker := time.NewTicker(1 * time.Second)
	serviceTicker := time.NewTicker(15 * time.Second)

	// Keep services updated on its own cadence
	go func() {
		for {
			<-serviceTicker.C
			WSHub.mu.Lock()
			clientCount := len(WSHub.clients)
			WSHub.mu.Unlock()

			if clientCount > 0 {
				s := services.GetActiveServices()
				systemStateMutex.Lock()
				cachedServices = s
				systemStateMutex.Unlock()
			}
		}
	}()

	// Keep metrics updated on its own cadence
	go func() {
		for {
			<-metricsTicker.C
			WSHub.mu.Lock()
			clientCount := len(WSHub.clients)
			WSHub.mu.Unlock()

			if clientCount > 0 {
				m := services.GetSystemMetricsCore()
				systemStateMutex.Lock()
				cachedMetrics = m
				systemStateMutex.Unlock()
			}
		}
	}()
}

func broadcastMetricsLoop() {
	broadcastTicker := time.NewTicker(1 * time.Second)
	defer broadcastTicker.Stop()

	// Initial kick off for state maintenance
	go maintainSystemState()

	for {
		<-broadcastTicker.C

		WSHub.mu.Lock()
		clientCount := len(WSHub.clients)
		WSHub.mu.Unlock()

		if clientCount == 0 {
			continue
		}

		systemStateMutex.RLock()
		m := cachedMetrics
		s := cachedServices
		systemStateMutex.RUnlock()

		if m == nil {
			// Not ready yet
			continue
		}

		adminPayload := map[string]interface{}{
			"type": "METRICS_UPDATE",
			"data": map[string]interface{}{
				"system":   m,
				"services": s,
			},
		}
		userPayload := map[string]interface{}{
			"type": "METRICS_UPDATE",
			"data": map[string]interface{}{
				"system":   m,
				"services": SanitizeServicesForViewer(s, false),
			},
		}

		adminMsg, err := json.Marshal(adminPayload)
		if err != nil {
			slog.Error("Failed to marshal metrics payload for WebSocket broadcast", "error", err)
			continue
		}
		userMsg, uErr := json.Marshal(userPayload)
		if uErr != nil {
			userMsg = adminMsg
		}
		// Non-blocking viewer-scoped dispatch
		select {
		case WSHub.dispatch <- hubEnvelope{raw: adminMsg, nonAdminRaw: userMsg}:
		default:
			slog.Warn("WebSocket broadcast channel full, dropping metrics payload")
		}
	}
}

// BroadcastNotification sends a notification to the target user (or all connected clients when global).
func BroadcastNotification(n services.Notification) {
	payload := map[string]interface{}{
		"type": "NOTIFICATION",
		"data": map[string]interface{}{
			"id":         n.ID,
			"level":      string(n.Level),
			"title":      n.Title,
			"message":    n.Message,
			"created_at": n.CreatedAt,
		},
	}

	message, err := json.Marshal(payload)
	if err != nil {
		return
	}

	var targetUID *int
	if n.UserID != nil && *n.UserID > 0 {
		uid := *n.UserID
		targetUID = &uid
	}

	select {
	case WSHub.dispatch <- hubEnvelope{raw: message, targetUserID: targetUID}:
	default:
		slog.Info("WARNING: WebSocket dispatch channel full, dropping notification", "title", n.Title)
	}
}

func BroadcastMarketplaceUpdates(packages []string) {
	go func() {
		s := services.GetActiveServices()
		systemStateMutex.Lock()
		cachedServices = s
		systemStateMutex.Unlock()
	}()

	payload := map[string]interface{}{
		"type": "MARKETPLACE_UPDATE",
		"data": map[string]interface{}{
			"packages": packages,
		},
	}

	message, err := json.Marshal(payload)
	if err != nil {
		return
	}

	select {
	case WSHub.dispatch <- hubEnvelope{raw: message, adminOnly: true}:
	default:
		slog.Warn("WebSocket dispatch channel full, dropping marketplace update")
	}
}

func BroadcastMarketplaceJobEvent(pkgId, action, status string, progress int, lastLine string) {
	if progress <= 1 || status == "installed" || status == "uninstalled" || status == "failed" {
		go func() {
			s := services.GetActiveServices()
			systemStateMutex.Lock()
			cachedServices = s
			systemStateMutex.Unlock()
		}()
	}

	payload := map[string]interface{}{
		"type": "MARKETPLACE_UPDATE",
		"data": map[string]interface{}{
			"packages": []string{pkgId},
			"package":  pkgId,
			"action":   action,
			"status":   status,
			"progress": progress,
			"log_line": lastLine,
		},
	}

	message, err := json.Marshal(payload)
	if err != nil {
		return
	}

	select {
	case WSHub.dispatch <- hubEnvelope{raw: message, adminOnly: true}:
	default:
		slog.Warn("WebSocket dispatch channel full, dropping marketplace job event")
	}
}

// BroadcastActionQueued sends an ACTION_QUEUED WebSocket message exclusively to connected admin clients.
func BroadcastActionQueued(actionID int64, classification, source, action string) {
	payload := map[string]interface{}{
		"type": "ACTION_QUEUED",
		"data": map[string]interface{}{
			"action_id":      actionID,
			"classification": classification,
			"source":         source,
			"action":         action,
		},
	}

	message, err := json.Marshal(payload)
	if err != nil {
		return
	}

	select {
	case WSHub.dispatch <- hubEnvelope{raw: message, adminOnly: true}:
	default:
		slog.Warn("WebSocket dispatch channel full, dropping action queued event")
	}
}

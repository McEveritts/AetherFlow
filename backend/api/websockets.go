package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"aetherflow/services"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	// Strict origin check: parse the Origin header properly and compare host
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true // Non-browser clients (curl, server-side, etc.)
		}
		parsed, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return parsed.Host == r.Host
	},
}

type Client struct {
	hub  *Hub
	conn *websocket.Conn
	send chan []byte
}

type Hub struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	mu         sync.Mutex
}

func newHub() *Hub {
	return &Hub{
		broadcast:  make(chan []byte, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		clients:    make(map[*Client]bool),
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
			h.mu.Lock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mu.Unlock()
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
				log.Printf("WebSocket unexpected close: %v", err)
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

type wsTicketEntry struct {
	UserID   int
	ClientIP string
}

var (
	wsTickets   = make(map[string]wsTicketEntry)
	wsTicketsMu sync.Mutex
)

// IssueWSTicket generates a short-lived (30s) single-use ticket for WebSocket authentication.
func IssueWSTicket(c *gin.Context) {
	rawUserID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	b := make([]byte, 16)
	rand.Read(b)
	ticket := hex.EncodeToString(b)

	wsTicketsMu.Lock()
	wsTickets[ticket] = wsTicketEntry{
		UserID:   rawUserID.(int),
		ClientIP: c.ClientIP(),
	}
	wsTicketsMu.Unlock()

	// 30 seconds expiry for ticket
	go func(t string) {
		time.Sleep(30 * time.Second)
		wsTicketsMu.Lock()
		delete(wsTickets, t)
		wsTicketsMu.Unlock()
	}(ticket)

	c.JSON(http.StatusOK, gin.H{"ticket": ticket})
}

// HandleWebSocket authenticates the request via WS ticket with IP-binding validation.
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

	if !ok {
		RespondError(c, http.StatusUnauthorized, "WS_INVALID_TICKET", "Invalid or expired ticket")
		return
	}

	// IP-binding: reject tickets used from a different IP than issuance
	if entry.ClientIP != "" && entry.ClientIP != c.ClientIP() {
		log.Printf("WS ticket IP mismatch: issued to %s, used from %s", entry.ClientIP, c.ClientIP())
		RespondError(c, http.StatusForbidden, "WS_IP_MISMATCH", "Ticket IP mismatch")
		return
	}

	_ = entry.UserID // validated user — available for future per-user channel filtering

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Println("Upgrade Error:", err)
		return
	}
	client := &Client{hub: WSHub, conn: conn, send: make(chan []byte, 256)}
	client.hub.register <- client

	go client.writePump()
	go client.readPump()
}

var (
	cachedServices   interface{}
	cachedMetrics    interface{}
	systemStateMutex sync.RWMutex
)

func maintainSystemState() {
	metricsTicker := time.NewTicker(3 * time.Second)
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
	broadcastTicker := time.NewTicker(3 * time.Second)
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

		payload := map[string]interface{}{
			"type": "METRICS_UPDATE",
			"data": map[string]interface{}{
				"system":   m,
				"services": s,
			},
		}

		message, err := json.Marshal(payload)
		if err == nil {
			// Non-blocking broadcast
			select {
			case WSHub.broadcast <- message:
			default:
				log.Printf("WARNING: WebSocket broadcast channel full, dropping metrics payload")
			}
		}
	}
}

// BroadcastNotification sends a notification to all connected WebSocket clients.
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

	select {
	case WSHub.broadcast <- message:
	default:
		log.Printf("WARNING: WebSocket broadcast channel full, dropping notification: %s", n.Title)
	}
}

func BroadcastMarketplaceUpdates(packages []string) {
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
	case WSHub.broadcast <- message:
	default:
		log.Printf("WARNING: WebSocket broadcast channel full, dropping marketplace update")
	}
}

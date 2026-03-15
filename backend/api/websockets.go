package api

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"aetherflow/services"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
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
		broadcast:  make(chan []byte),
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

// HandleWebSocket authenticates the request via JWT cookie before upgrading.
func HandleWebSocket(c *gin.Context) {
	// Require valid session cookie for WebSocket connections
	cookie, err := c.Cookie("aetherflow_session")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "WebSocket requires authentication"})
		return
	}

	token, err := jwt.Parse(cookie, func(token *jwt.Token) (interface{}, error) {
		// Prevent algorithm confusion: only accept HMAC signing
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return getJWTSecret(), nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired session"})
		return
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Println("Upgrade Error:", err)
		return
	}
	client := &Client{hub: WSHub, conn: conn, send: make(chan []byte, 256)}
	client.hub.register <- client

	// Start both pumps in goroutines
	go client.writePump()
	go client.readPump()
}

func broadcastMetricsLoop() {
	metricsTicker := time.NewTicker(3 * time.Second)
	serviceTicker := time.NewTicker(15 * time.Second)
	defer metricsTicker.Stop()
	defer serviceTicker.Stop()

	// Cache the last services result so we include it in every metrics push
	var cachedServices interface{}

	for {
		select {
		case <-serviceTicker.C:
			// Refresh services list on the slower interval (systemctl + pm2 are expensive)
			WSHub.mu.Lock()
			clientCount := len(WSHub.clients)
			WSHub.mu.Unlock()
			if clientCount > 0 {
				cachedServices = services.GetActiveServices()
			}

		case <-metricsTicker.C:
			WSHub.mu.Lock()
			clientCount := len(WSHub.clients)
			WSHub.mu.Unlock()

			if clientCount == 0 {
				continue
			}

			metrics := services.GetSystemMetricsCore()

			payload := map[string]interface{}{
				"type": "METRICS_UPDATE",
				"data": map[string]interface{}{
					"system":   metrics,
					"services": cachedServices,
				},
			}

			message, err := json.Marshal(payload)
			if err == nil {
				WSHub.broadcast <- message
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

	WSHub.broadcast <- message
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

	WSHub.broadcast <- message
}

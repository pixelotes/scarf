package logger

import (
	"log"
	"io"
	"sync"
	"net/http"
	"github.com/gorilla/websocket"
)

var (
	broadcaster = &Broadcaster{
		clients:    make(map[*websocket.Conn]bool),
		register:   make(chan *websocket.Conn),
		unregister: make(chan *websocket.Conn),
		messages:   make(chan []byte),
	}
	logWriter io.Writer
)

func init() {
	go broadcaster.run()
	logWriter = io.MultiWriter(log.Writer(), broadcaster)
	log.SetOutput(logWriter)
}

// Broadcaster manages WebSocket clients
type Broadcaster struct {
	clients    map[*websocket.Conn]bool
	register   chan *websocket.Conn
	unregister chan *websocket.Conn
	messages   chan []byte
	mu         sync.Mutex
}

func (b *Broadcaster) run() {
	for {
		select {
		case client := <-b.register:
			b.mu.Lock()
			b.clients[client] = true
			b.mu.Unlock()
		case client := <-b.unregister:
			b.mu.Lock()
			if _, ok := b.clients[client]; ok {
				delete(b.clients, client)
				client.Close()
			}
			b.mu.Unlock()
		case message := <-b.messages:
			b.mu.Lock()
			for client := range b.clients {
				if err := client.WriteMessage(websocket.TextMessage, message); err != nil {
					go func(c *websocket.Conn) { b.unregister <- c }(client)
				}
			}
			b.mu.Unlock()
		}
	}
}

func (b *Broadcaster) Write(p []byte) (n int, err error) {
	b.messages <- p
	return len(p), nil
}

// WebSocketHandler handles new log viewer connections
func WebSocketHandler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade WebSocket: %v", err)
		return
	}
	broadcaster.register <- conn
}
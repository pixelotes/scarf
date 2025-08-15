package logger

import (
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"sync"

	"github.com/gorilla/websocket"
)

var (
	broadcaster = &Broadcaster{
		clients:    make(map[*websocket.Conn]bool),
		register:   make(chan *websocket.Conn),
		unregister: make(chan *websocket.Conn),
		messages:   make(chan []byte),
	}
)

// Init initializes the global structured logger.
func Init(debug bool) {
	go broadcaster.run()

	logLevel := slog.LevelInfo
	if debug {
		logLevel = slog.LevelDebug
	}

	// Create a handler that writes to both stdout and the WebSocket broadcaster.
	// Using a TextHandler makes logs human-readable in the console and UI.
	handler := slog.NewTextHandler(io.MultiWriter(os.Stdout, broadcaster), &slog.HandlerOptions{
		Level:     logLevel,
		AddSource: true, // Adds source file and line number, useful for debugging.
	})

	logger := slog.New(handler)
	slog.SetDefault(logger)

	// Redirect the standard `log` package to our new structured logger.
	// This captures logs from third-party libraries that still use the old logger.
	log.SetFlags(0)
	log.SetOutput(slog.NewLogLogger(logger.Handler(), slog.LevelInfo).Writer())
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
			// Make a copy of the message slice to avoid data races
			msgCopy := make([]byte, len(message))
			copy(msgCopy, message)

			b.mu.Lock()
			for client := range b.clients {
				if err := client.WriteMessage(websocket.TextMessage, msgCopy); err != nil {
					// Unregister the client in a separate goroutine to avoid deadlock
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
		slog.Warn("Failed to upgrade WebSocket", "error", err)
		return
	}
	broadcaster.register <- conn
}

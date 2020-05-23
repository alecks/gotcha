package gotcha

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// Server is a Gotcha instance.
type Server struct {
	// Address is the address to listen on.
	Address string
	// Timeout is the maximum time that a client has to send a request.
	Timeout time.Duration
	// Render is called when a response is about to be returned. It can be used to return styled HTML responses.
	Render func(c *gin.Context, status int, body map[string]string)
	// BlockList is a map of IP addresses to reasons. Clients can see these reasons if they're blocked.
	BlockList map[string]string
	// UseTLS decides on whether or not the server will be served under HTTPS.
	UseTLS bool
	// TLSCert is the filepath to an SSL/TLS certificate.
	TLSCert string
	// TLSKey is the filepath to an SSL/TLS key.
	TLSKey string

	router  *gin.Engine
	awaited map[string]awaited
}

type awaited struct {
	start    time.Time
	statChan chan int
}

// Serve starts the HTTP server. Uses gin-gonic.
func (server *Server) Serve() error {
	attached := true
	if server.router == nil {
		attached = false
		server.router = gin.New()
		gin.SetMode(gin.ReleaseMode)
	}
	if server.Render == nil {
		server.Render = func(c *gin.Context, status int, body map[string]string) {
			c.JSON(status, body)
		}
	}

	server.router.GET("/verify/:identifier", func(c *gin.Context) {
		identifier := c.Param("identifier")
		body := map[string]string{}
		// Possibly use 404?
		status := http.StatusUnauthorized

		if found, ok := server.awaited[c.Param("identifier")]; ok {
			if time.Now().Sub(found.start) >= server.Timeout {
				found.statChan <- 1
				status = http.StatusGone
			} else if reason, ok := server.BlockList[c.ClientIP()]; ok {
				found.statChan <- 2
				body["reason"] = reason
				status = http.StatusForbidden
			} else {
				found.statChan <- 0
				status = http.StatusOK
			}

			close(found.statChan)
			delete(server.awaited, identifier)
		}

		body["message"] = http.StatusText(status)
		server.Render(c, status, body)
	})

	if !attached {
		if server.UseTLS {
			return server.router.RunTLS(server.Address, server.TLSCert, server.TLSKey)
		}
		return server.router.Run(server.Address)
	}
	return nil
}

// Await waits for a GET request to /verify/:identifier.
// It'll return 0 if the request was fulfilled, 1 if Timeout elapsed, or 2 if it was blocked.
// This function blocks.
func (server *Server) Await(identifier string) int {
	if server.awaited == nil {
		server.awaited = map[string]awaited{}
	}
	server.awaited[identifier] = awaited{
		start:    time.Now(),
		statChan: make(chan int, 1),
	}
	return <-server.awaited[identifier].statChan
}

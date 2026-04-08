package socks4

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// genRandom creates n random bytes.
func genRandom(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

// echoServer starts a simple echo server that echoes back all data.
func echoServer(t *testing.T) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start echo server: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c) // echo back everything
			}(conn)
		}
	}()

	return ln
}

// startSOCKS4Server starts a SOCKS4 server with the given handler.
func startSOCKS4Server(t *testing.T, handler ServerHandler) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start SOCKS4 server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() {
		if err := Serve(ctx, ln, handler); err != nil {
			t.Logf("SOCKS4 server ended: %v", err)
		}
	}()

	// Give server time to start
	time.Sleep(10 * time.Millisecond)
	return ln
}

func TestBaseServerHandler_OnConnect_Success(t *testing.T) {
	// Start echo server
	echoLn := echoServer(t)
	defer echoLn.Close()

	// Start SOCKS4 server with CONNECT enabled
	handler := &BaseServerHandler{
		RequestTimeout:     2 * time.Second,
		ConnectConnTimeout: 2 * time.Second,
		ConnectBufferSize:  1024 * 32,
		AllowConnect:       true,
		AllowBind:          false,
	}

	socksLn := startSOCKS4Server(t, handler)
	defer socksLn.Close()

	// Create SOCKS4 dialer
	dialer := NewDialer(socksLn.Addr().String(), "testuser", nil)

	// Connect through SOCKS4 proxy to echo server
	conn, err := dialer.DialContext(context.Background(), "tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect through SOCKS4 proxy: %v", err)
	}
	defer conn.Close()

	// Test data transfer with random payload
	payload := genRandom(32 * 1024) // 32KB test
	response := make([]byte, len(payload))

	// Send data and expect echo
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Failed to write test data: %v", err)
	}

	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if !bytes.Equal(payload, response) {
		t.Fatalf("Echo data mismatch")
	}

	t.Log("CONNECT test passed with 32KB payload")
}

func TestBaseServerHandler_OnConnect_Disabled(t *testing.T) {
	// Start SOCKS4 server with CONNECT disabled
	handler := &BaseServerHandler{
		RequestTimeout: 1 * time.Second,
		AllowConnect:   false,
		AllowBind:      false,
	}

	socksLn := startSOCKS4Server(t, handler)
	defer socksLn.Close()

	// Create SOCKS4 dialer
	dialer := NewDialer(socksLn.Addr().String(), "testuser", nil)

	// Try to connect - should fail
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", "127.0.0.1:80")
	if err == nil {
		conn.Close()
		t.Fatalf("Expected connection to fail when CONNECT is disabled")
	}

	t.Logf("CONNECT correctly rejected: %v", err)
	t.Log("CONNECT disabled test passed")
}

func TestBaseServerHandler_OnConnect_TargetUnreachable(t *testing.T) {
	// Start SOCKS4 server
	handler := &BaseServerHandler{
		RequestTimeout:     1 * time.Second,
		ConnectConnTimeout: 500 * time.Millisecond, // short timeout for faster test
		AllowConnect:       true,
		AllowBind:          false,
	}

	socksLn := startSOCKS4Server(t, handler)
	defer socksLn.Close()

	// Create SOCKS4 dialer
	dialer := NewDialer(socksLn.Addr().String(), "testuser", nil)

	// Try to connect to non-existent target - should fail
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", "192.0.2.1:12345")
	if err == nil {
		conn.Close()
		t.Fatalf("Expected connection to unreachable target to fail")
	}

	t.Logf("Target unreachable correctly rejected: %v", err)
	t.Log("Target unreachable test passed")
}

func TestBaseServerHandler_OnBind_Success(t *testing.T) {
	// Start SOCKS4 server with BIND enabled
	handler := &BaseServerHandler{
		RequestTimeout:     2 * time.Second,
		BindAcceptTimeout:  2 * time.Second,
		ConnectConnTimeout: 2 * time.Second,
		AllowConnect:       false,
		AllowBind:          true,
	}

	socksLn := startSOCKS4Server(t, handler)
	defer socksLn.Close()

	// Create SOCKS4 dialer
	dialer := NewDialer(socksLn.Addr().String(), "testuser", nil)

	// Use BindContext for BIND operation
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, bindAddr, readyCh, err := dialer.BindContext(ctx, "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Failed to bind through SOCKS4 proxy: %v", err)
	}
	defer conn.Close()

	t.Logf("SOCKS4 server bound to: %v", bindAddr)

	// Test data that will flow through the proxy
	testData := genRandom(16 * 1024) // 16KB test
	var incomingData []byte
	var err1 error

	// Connect to the bound address from another goroutine
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond) // give time for server to start listening

		// Connect to bound address
		incomingConn, err := net.Dial("tcp", bindAddr.String())
		if err != nil {
			err1 = err
			return
		}
		defer incomingConn.Close()

		// Read data that comes through the proxy from the main connection
		buffer := make([]byte, len(testData))
		if _, err := io.ReadFull(incomingConn, buffer); err != nil {
			err1 = err
			return
		}
		incomingData = buffer

		// Send a response back through the proxy
		responseData := []byte("response from incoming connection")
		if _, err := incomingConn.Write(responseData); err != nil {
			err1 = err
			return
		}
	}()

	// Wait for BIND to be ready
	if err := <-readyCh; err != nil {
		t.Fatalf("BIND ready channel error: %v", err)
	}

	// Send test data through the proxy to the incoming connection
	if _, err := conn.Write(testData); err != nil {
		t.Fatalf("Failed to write through proxy: %v", err)
	}

	// Read the response from the incoming connection through the proxy
	responseBuffer := make([]byte, len("response from incoming connection"))
	if _, err := io.ReadFull(conn, responseBuffer); err != nil {
		t.Fatalf("Failed to read response through proxy: %v", err)
	}

	wg.Wait() // wait for incoming connection goroutine

	// Check for errors from the goroutine
	if err1 != nil {
		t.Fatalf("Error in incoming connection: %v", err1)
	}

	// Verify data was correctly transmitted through the proxy
	if !bytes.Equal(testData, incomingData) {
		t.Fatalf("Data mismatch through BIND proxy")
	}

	expectedResponse := []byte("response from incoming connection")
	if !bytes.Equal(expectedResponse, responseBuffer) {
		t.Fatalf("Response mismatch through BIND proxy")
	}

	t.Log("BIND test passed with 16KB payload")
}

func TestBaseServerHandler_OnBind_Disabled(t *testing.T) {
	// Start SOCKS4 server with BIND disabled
	handler := &BaseServerHandler{
		RequestTimeout: 1 * time.Second,
		AllowConnect:   false,
		AllowBind:      false,
	}

	socksLn := startSOCKS4Server(t, handler)
	defer socksLn.Close()

	// Create SOCKS4 dialer
	dialer := NewDialer(socksLn.Addr().String(), "testuser", nil)

	// Try to bind - should fail
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, _, _, err := dialer.BindContext(ctx, "tcp", "0.0.0.0:0")
	if err == nil {
		conn.Close()
		t.Fatalf("Expected BIND to fail when disabled")
	}

	t.Logf("BIND correctly rejected: %v", err)
	t.Log("BIND disabled test passed")
}

func TestBaseServerHandler_UserIDValidation(t *testing.T) {
	// Start an echo server
	echoLn := echoServer(t)
	defer echoLn.Close()

	tests := []struct {
		name          string
		userIDChecker func(userID string) bool
		connectUserID string
		expectSuccess bool
	}{
		{
			name:          "No validation - allow all",
			userIDChecker: nil,
			connectUserID: "anyuser",
			expectSuccess: true,
		},
		{
			name:          "No validation - allow empty",
			userIDChecker: nil,
			connectUserID: "",
			expectSuccess: true,
		},
		{
			name: "Allow specific user - match",
			userIDChecker: func(userID string) bool {
				return userID == "alice"
			},
			connectUserID: "alice",
			expectSuccess: true,
		},
		{
			name: "Allow specific user - no match",
			userIDChecker: func(userID string) bool {
				return userID == "alice"
			},
			connectUserID: "bob",
			expectSuccess: false,
		},
		{
			name: "Require non-empty - with user",
			userIDChecker: func(userID string) bool {
				return userID != ""
			},
			connectUserID: "someuser",
			expectSuccess: true,
		},
		{
			name: "Require non-empty - empty user",
			userIDChecker: func(userID string) bool {
				return userID != ""
			},
			connectUserID: "",
			expectSuccess: false,
		},
		{
			name: "Allow multiple users - match first",
			userIDChecker: func(userID string) bool {
				allowed := []string{"alice", "bob", "charlie"}
				for _, id := range allowed {
					if id == userID {
						return true
					}
				}
				return false
			},
			connectUserID: "alice",
			expectSuccess: true,
		},
		{
			name: "Allow multiple users - match last",
			userIDChecker: func(userID string) bool {
				allowed := []string{"alice", "bob", "charlie"}
				for _, id := range allowed {
					if id == userID {
						return true
					}
				}
				return false
			},
			connectUserID: "charlie",
			expectSuccess: true,
		},
		{
			name: "Allow multiple users - no match",
			userIDChecker: func(userID string) bool {
				allowed := []string{"alice", "bob", "charlie"}
				for _, id := range allowed {
					if id == userID {
						return true
					}
				}
				return false
			},
			connectUserID: "eve",
			expectSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create handler with user ID validation
			handler := &BaseServerHandler{
				RequestTimeout: 2 * time.Second,
				AllowConnect:   true,
				AllowBind:      false,
				UserIDChecker:  tt.userIDChecker,
			}

			// Start SOCKS4 server
			socksLn := startSOCKS4Server(t, handler)
			defer socksLn.Close()

			// Create SOCKS4 dialer with the test user ID
			dialer := NewDialer(socksLn.Addr().String(), tt.connectUserID, nil)

			// Try to connect through the proxy
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			conn, err := dialer.DialContext(ctx, "tcp", echoLn.Addr().String())

			if tt.expectSuccess {
				if err != nil {
					t.Fatalf("Expected connection to succeed but got error: %v", err)
				}
				defer conn.Close()

				// Test that the connection actually works
				testData := []byte("hello user validation")
				_, err = conn.Write(testData)
				if err != nil {
					t.Fatalf("Failed to write test data: %v", err)
				}

				response := make([]byte, len(testData))
				_, err = io.ReadFull(conn, response)
				if err != nil {
					t.Fatalf("Failed to read response: %v", err)
				}

				if !bytes.Equal(testData, response) {
					t.Fatalf("Echo response mismatch: got %q, expected %q", response, testData)
				}

				t.Logf("Connection succeeded and data echoed correctly for user %q", tt.connectUserID)
			} else {
				if err == nil {
					conn.Close()
					t.Fatalf("Expected connection to fail but it succeeded for user %q", tt.connectUserID)
				}
				t.Logf("Connection correctly rejected for user %q: %v", tt.connectUserID, err)
			}
		})
	}
}

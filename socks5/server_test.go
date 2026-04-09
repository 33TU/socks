package socks5_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/33TU/socks/socks5"
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

// startSOCKS5Server starts a SOCKS5 server with the given handler.
func startSOCKS5Server(t *testing.T, handler socks5.ServerHandler) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start SOCKS5 server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() {
		if err := socks5.Serve(ctx, ln, handler); err != nil {
			t.Logf("SOCKS5 server ended: %v", err)
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

	// Start SOCKS5 server with CONNECT enabled
	handler := &socks5.BaseServerHandler{
		RequestTimeout:     2 * time.Second,
		ConnectConnTimeout: 2 * time.Second,
		ConnectBufferSize:  1024 * 32,
		AllowConnect:       true,
		AllowBind:          false,
		AllowUDPAssociate:  false,
		SupportedMethods:   []byte{socks5.MethodNoAuth},
	}

	socksLn := startSOCKS5Server(t, handler)
	defer socksLn.Close()

	// Create SOCKS5 dialer (no auth)
	dialer := socks5.NewDialer(socksLn.Addr().String(), nil, nil)

	// Connect through SOCKS5 proxy to echo server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect through SOCKS5 proxy: %v", err)
	}
	defer conn.Close()

	// Set a deadline for the connection operations
	conn.SetDeadline(time.Now().Add(3 * time.Second))

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
	// Start SOCKS5 server with CONNECT disabled
	handler := &socks5.BaseServerHandler{
		RequestTimeout:    1 * time.Second,
		AllowConnect:      false,
		AllowBind:         false,
		AllowUDPAssociate: false,
		SupportedMethods:  []byte{socks5.MethodNoAuth},
	}

	socksLn := startSOCKS5Server(t, handler)
	defer socksLn.Close()

	// Create SOCKS5 dialer
	dialer := socks5.NewDialer(socksLn.Addr().String(), nil, nil)

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
	// Start SOCKS5 server
	handler := &socks5.BaseServerHandler{
		RequestTimeout:     1 * time.Second,
		ConnectConnTimeout: 500 * time.Millisecond, // short timeout for faster test
		AllowConnect:       true,
		AllowBind:          false,
		AllowUDPAssociate:  false,
		SupportedMethods:   []byte{socks5.MethodNoAuth},
	}

	socksLn := startSOCKS5Server(t, handler)
	defer socksLn.Close()

	// Create SOCKS5 dialer
	dialer := socks5.NewDialer(socksLn.Addr().String(), nil, nil)

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
	// Start SOCKS5 server with BIND enabled
	handler := &socks5.BaseServerHandler{
		RequestTimeout:     2 * time.Second,
		BindAcceptTimeout:  2 * time.Second,
		ConnectConnTimeout: 2 * time.Second,
		AllowConnect:       false,
		AllowBind:          true,
		AllowUDPAssociate:  false,
		SupportedMethods:   []byte{socks5.MethodNoAuth},
	}

	socksLn := startSOCKS5Server(t, handler)
	defer socksLn.Close()

	// Create SOCKS5 dialer
	dialer := socks5.NewDialer(socksLn.Addr().String(), nil, nil)

	// Use BindContext for BIND operation
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, bindAddr, readyCh, err := dialer.BindContext(ctx, "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Failed to bind through SOCKS5 proxy: %v", err)
	}
	defer conn.Close()

	t.Logf("SOCKS5 server bound to: %v", bindAddr)

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
	// Start SOCKS5 server with BIND disabled
	handler := &socks5.BaseServerHandler{
		RequestTimeout:    1 * time.Second,
		AllowConnect:      false,
		AllowBind:         false,
		AllowUDPAssociate: false,
		SupportedMethods:  []byte{socks5.MethodNoAuth},
	}

	socksLn := startSOCKS5Server(t, handler)
	defer socksLn.Close()

	// Create SOCKS5 dialer
	dialer := socks5.NewDialer(socksLn.Addr().String(), nil, nil)

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

func TestBaseServerHandler_UserPassAuth(t *testing.T) {
	// Start an echo server
	echoLn := echoServer(t)
	defer echoLn.Close()

	errUnauthorized := fmt.Errorf("invalid credentials")

	tests := []struct {
		name          string
		authenticator func(ctx context.Context, username, password string) error
		connectAuth   *socks5.Auth
		expectSuccess bool
	}{
		{
			name:          "No auth required - no credentials",
			authenticator: nil,
			connectAuth:   nil,
			expectSuccess: true,
		},
		{
			name:          "No auth required - with credentials",
			authenticator: nil,
			connectAuth:   &socks5.Auth{Username: "user", Password: "pass"},
			expectSuccess: true,
		},
		{
			name: "Auth required - valid credentials",
			authenticator: func(ctx context.Context, username, password string) error {
				if username == "alice" && password == "secret123" {
					return nil
				}
				return errUnauthorized
			},
			connectAuth:   &socks5.Auth{Username: "alice", Password: "secret123"},
			expectSuccess: true,
		},
		{
			name: "Auth required - invalid username",
			authenticator: func(ctx context.Context, username, password string) error {
				if username == "alice" && password == "secret123" {
					return nil
				}
				return errUnauthorized
			},
			connectAuth:   &socks5.Auth{Username: "bob", Password: "secret123"},
			expectSuccess: false,
		},
		{
			name: "Auth required - invalid password",
			authenticator: func(ctx context.Context, username, password string) error {
				if username == "alice" && password == "secret123" {
					return nil
				}
				return errUnauthorized
			},
			connectAuth:   &socks5.Auth{Username: "alice", Password: "wrongpass"},
			expectSuccess: false,
		},
		{
			name: "Auth required - empty credentials",
			authenticator: func(ctx context.Context, username, password string) error {
				if username != "" && password != "" {
					return nil
				}
				return errUnauthorized
			},
			connectAuth:   &socks5.Auth{Username: "", Password: ""},
			expectSuccess: false,
		},
		{
			name: "Multiple valid users",
			authenticator: func(ctx context.Context, username, password string) error {
				validCreds := map[string]string{
					"alice":   "password1",
					"bob":     "password2",
					"charlie": "password3",
				}
				if expected, ok := validCreds[username]; ok && expected == password {
					return nil
				}
				return errUnauthorized
			},
			connectAuth:   &socks5.Auth{Username: "bob", Password: "password2"},
			expectSuccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Determine supported methods based on test case
			var supportedMethods []byte
			if tt.authenticator != nil {
				supportedMethods = []byte{socks5.MethodUserPass}
			} else {
				supportedMethods = []byte{socks5.MethodNoAuth}
			}

			// Create handler with user/pass authentication
			handler := &socks5.BaseServerHandler{
				RequestTimeout:        2 * time.Second,
				AllowConnect:          true,
				AllowBind:             false,
				AllowUDPAssociate:     false,
				SupportedMethods:      supportedMethods,
				UserPassAuthenticator: tt.authenticator,
			}

			// Start SOCKS5 server
			socksLn := startSOCKS5Server(t, handler)
			defer socksLn.Close()

			// Create SOCKS5 dialer with the test credentials
			dialer := socks5.NewDialer(socksLn.Addr().String(), tt.connectAuth, nil)

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
				testData := []byte("hello user authentication")
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

				if tt.connectAuth != nil {
					t.Logf("Connection succeeded and data echoed correctly for user %q", tt.connectAuth.Username)
				} else {
					t.Log("Connection succeeded with no auth")
				}
			} else {
				if err == nil {
					conn.Close()
					if tt.connectAuth != nil {
						t.Fatalf("Expected connection to fail but it succeeded for user %q", tt.connectAuth.Username)
					} else {
						t.Fatalf("Expected connection to fail but it succeeded")
					}
				}
				if tt.connectAuth != nil {
					t.Logf("Connection correctly rejected for user %q: %v", tt.connectAuth.Username, err)
				} else {
					t.Logf("Connection correctly rejected: %v", err)
				}
			}
		})
	}
}

func TestBaseServerHandler_MethodNegotiation(t *testing.T) {
	// Start an echo server
	echoLn := echoServer(t)
	defer echoLn.Close()

	tests := []struct {
		name             string
		supportedMethods []byte
		clientAuth       *socks5.Auth
		expectSuccess    bool
		description      string
	}{
		{
			name:             "NoAuth only - no credentials",
			supportedMethods: []byte{socks5.MethodNoAuth},
			clientAuth:       nil,
			expectSuccess:    true,
			description:      "Server supports only no-auth, client provides no credentials",
		},
		{
			name:             "UserPass only - valid credentials",
			supportedMethods: []byte{socks5.MethodUserPass},
			clientAuth:       &socks5.Auth{Username: "test", Password: "pass"},
			expectSuccess:    true,
			description:      "Server supports only user/pass, client provides credentials",
		},
		{
			name:             "UserPass only - no credentials",
			supportedMethods: []byte{socks5.MethodUserPass},
			clientAuth:       nil,
			expectSuccess:    false,
			description:      "Server supports only user/pass, client provides no credentials",
		},
		{
			name:             "Both methods - no credentials",
			supportedMethods: []byte{socks5.MethodNoAuth, socks5.MethodUserPass},
			clientAuth:       nil,
			expectSuccess:    true,
			description:      "Server supports both methods, client should use no-auth",
		},
		{
			name:             "Both methods - with credentials",
			supportedMethods: []byte{socks5.MethodNoAuth, socks5.MethodUserPass},
			clientAuth:       &socks5.Auth{Username: "test", Password: "pass"},
			expectSuccess:    true,
			description:      "Server supports both methods, client should use user/pass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create simple authenticator for user/pass
			authenticator := func(ctx context.Context, username, password string) error {
				if username == "test" && password == "pass" {
					return nil
				}
				return fmt.Errorf("invalid credentials")
			}

			// Create handler
			handler := &socks5.BaseServerHandler{
				RequestTimeout:        2 * time.Second,
				AllowConnect:          true,
				AllowBind:             false,
				AllowUDPAssociate:     false,
				SupportedMethods:      tt.supportedMethods,
				UserPassAuthenticator: authenticator,
			}

			// Start SOCKS5 server
			socksLn := startSOCKS5Server(t, handler)
			defer socksLn.Close()

			// Create SOCKS5 dialer
			dialer := socks5.NewDialer(socksLn.Addr().String(), tt.clientAuth, nil)

			// Try to connect through the proxy
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			conn, err := dialer.DialContext(ctx, "tcp", echoLn.Addr().String())

			if tt.expectSuccess {
				if err != nil {
					t.Fatalf("Expected connection to succeed but got error: %v", err)
				}
				defer conn.Close()

				// Quick connectivity test
				testData := []byte("method negotiation test")
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
					t.Fatalf("Echo response mismatch")
				}

				t.Logf("Success: %s", tt.description)
			} else {
				if err == nil {
					conn.Close()
					t.Fatalf("Expected connection to fail but it succeeded: %s", tt.description)
				}
				t.Logf("Correctly rejected: %s - %v", tt.description, err)
			}
		})
	}
}

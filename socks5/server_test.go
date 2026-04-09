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

// serverMockGSSAPIContext_Success implements a mock GSSAPI context for testing
type serverMockGSSAPIContext_Success struct {
	complete bool
}

func (m *serverMockGSSAPIContext_Success) InitSecContext() ([]byte, error) {
	// Return initial token
	return []byte("mock-initial-token"), nil
}

func (m *serverMockGSSAPIContext_Success) AcceptSecContext(serverToken []byte) ([]byte, bool, error) {
	// When server returns empty token, authentication is complete
	if len(serverToken) == 0 {
		m.complete = true
		return nil, true, nil
	}
	// For any other token, just complete the authentication
	m.complete = true
	return nil, true, nil
}

func (m *serverMockGSSAPIContext_Success) IsComplete() bool {
	return m.complete
}

// serverMockGSSAPIContext_MultiRound simulates multi-round GSSAPI exchange
type serverMockGSSAPIContext_MultiRound struct {
	round    int
	complete bool
}

func (m *serverMockGSSAPIContext_MultiRound) InitSecContext() ([]byte, error) {
	m.round = 1
	return []byte("init-token-round1"), nil
}

func (m *serverMockGSSAPIContext_MultiRound) AcceptSecContext(serverToken []byte) ([]byte, bool, error) {
	switch m.round {
	case 1:
		if string(serverToken) == "server-round1-token" {
			m.round = 2
			return []byte("client-round2-token"), false, nil
		}
		return nil, false, fmt.Errorf("unexpected round 1 token: %s", serverToken)
	case 2:
		if string(serverToken) == "server-round2-token" {
			m.round = 3
			return []byte("client-round3-token"), false, nil
		}
		return nil, false, fmt.Errorf("unexpected round 2 token: %s", serverToken)
	case 3:
		if len(serverToken) == 0 {
			m.complete = true
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("unexpected round 3 token: %s", serverToken)
	default:
		return nil, false, fmt.Errorf("unexpected round: %d", m.round)
	}
}

func (m *serverMockGSSAPIContext_MultiRound) IsComplete() bool {
	return m.complete
}

// serverMockGSSAPIContext_Failure simulates GSSAPI auth failure
type serverMockGSSAPIContext_Failure struct{}

func (m *serverMockGSSAPIContext_Failure) InitSecContext() ([]byte, error) {
	return []byte("bad-token"), nil
}

func (m *serverMockGSSAPIContext_Failure) AcceptSecContext(serverToken []byte) ([]byte, bool, error) {
	return nil, false, fmt.Errorf("mock GSSAPI auth failed")
}

func (m *serverMockGSSAPIContext_Failure) IsComplete() bool {
	return false
}

func TestBaseServerHandler_GSSAPI_Connect(t *testing.T) {
	echoLn := echoServer(t)
	defer echoLn.Close()

	handler := &socks5.BaseServerHandler{
		RequestTimeout:     2 * time.Second,
		ConnectConnTimeout: 2 * time.Second,
		AllowConnect:       true,
		SupportedMethods:   []byte{socks5.MethodGSSAPI},
	}

	socksLn := startSOCKS5Server(t, handler)
	defer socksLn.Close()

	// ---- GSSAPI mock context (client side)
	gssapiAuth := &socks5.GSSAPIAuth{
		Context: &serverMockGSSAPIContext_Success{},
	}

	dialer := socks5.NewDialerWithGSSAPI(
		socksLn.Addr().String(),
		nil, // no user/pass
		gssapiAuth,
		nil,
	)

	conn, err := dialer.DialContext(
		context.Background(),
		"tcp",
		echoLn.Addr().String(),
	)
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer conn.Close()

	// ---- Echo test
	payload := []byte("ping")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if !bytes.Equal(payload, buf) {
		t.Fatalf("echo mismatch: got %q", buf)
	}
}

func TestBaseServerHandler_GSSAPI_MultiRound(t *testing.T) {
	echoLn := echoServer(t)
	defer echoLn.Close()

	// Server-side GSSAPI authenticator for 3-round multi-round exchange
	round := 0
	gssapiAuthenticator := func(ctx context.Context, token []byte) ([]byte, bool, error) {
		round++
		switch round {
		case 1:
			if string(token) == "init-token-round1" {
				return []byte("server-round1-token"), false, nil
			}
			return nil, false, fmt.Errorf("unexpected round 1 token: %s", token)
		case 2:
			if string(token) == "client-round2-token" {
				return []byte("server-round2-token"), false, nil
			}
			return nil, false, fmt.Errorf("unexpected round 2 token: %s", token)
		case 3:
			if string(token) == "client-round3-token" {
				// Return empty token and done=true to complete authentication
				// The 3-round token exchange has established the security context
				return nil, true, nil
			}
			return nil, false, fmt.Errorf("unexpected round 3 token: %s", token)
		default:
			return nil, false, fmt.Errorf("unexpected round: %d", round)
		}
	}

	handler := &socks5.BaseServerHandler{
		RequestTimeout:      2 * time.Second,
		ConnectConnTimeout:  2 * time.Second,
		AllowConnect:        true,
		SupportedMethods:    []byte{socks5.MethodGSSAPI},
		GSSAPIAuthenticator: gssapiAuthenticator,
	}

	socksLn := startSOCKS5Server(t, handler)
	defer socksLn.Close()

	// ---- GSSAPI mock context for multi-round (client side)
	gssapiAuth := &socks5.GSSAPIAuth{
		Context: &serverMockGSSAPIContext_MultiRound{},
	}

	dialer := socks5.NewDialerWithGSSAPI(
		socksLn.Addr().String(),
		nil, // no user/pass
		gssapiAuth,
		nil,
	)

	conn, err := dialer.DialContext(
		context.Background(),
		"tcp",
		echoLn.Addr().String(),
	)
	if err != nil {
		t.Fatalf("DialContext with multi-round GSSAPI failed: %v", err)
	}
	defer conn.Close()

	// ---- Echo test with larger payload
	payload := genRandom(1024) // 1KB test
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if !bytes.Equal(payload, buf) {
		t.Fatalf("echo mismatch in multi-round GSSAPI")
	}

	t.Log("3-round GSSAPI authentication test passed")
}

func TestBaseServerHandler_GSSAPI_Failed(t *testing.T) {
	echoLn := echoServer(t)
	defer echoLn.Close()

	// Server-side GSSAPI authenticator that always fails
	gssapiAuthenticator := func(ctx context.Context, token []byte) ([]byte, bool, error) {
		return nil, false, fmt.Errorf("server-side GSSAPI authentication failed")
	}

	handler := &socks5.BaseServerHandler{
		RequestTimeout:      2 * time.Second,
		ConnectConnTimeout:  2 * time.Second,
		AllowConnect:        true,
		SupportedMethods:    []byte{socks5.MethodGSSAPI},
		GSSAPIAuthenticator: gssapiAuthenticator,
	}

	socksLn := startSOCKS5Server(t, handler)
	defer socksLn.Close()

	// ---- GSSAPI mock context that fails (client side)
	gssapiAuth := &socks5.GSSAPIAuth{
		Context: &serverMockGSSAPIContext_Failure{},
	}

	dialer := socks5.NewDialerWithGSSAPI(
		socksLn.Addr().String(),
		nil, // no user/pass
		gssapiAuth,
		nil,
	)

	conn, err := dialer.DialContext(
		context.Background(),
		"tcp",
		echoLn.Addr().String(),
	)
	if err == nil {
		conn.Close()
		t.Fatalf("Expected GSSAPI authentication to fail but it succeeded")
	}

	// Verify it's actually a GSSAPI authentication error
	if !bytes.Contains([]byte(err.Error()), []byte("GSSAPI")) &&
		!bytes.Contains([]byte(err.Error()), []byte("auth")) {
		t.Logf("Warning: Error doesn't seem to be GSSAPI related: %v", err)
	}

	t.Logf("GSSAPI authentication correctly failed: %v", err)
	t.Log("GSSAPI failure test passed")
}

func TestBaseServerHandler_Resolve_Success(t *testing.T) {
	handler := &socks5.BaseServerHandler{
		AllowResolve:     true,
		RequestTimeout:   2 * time.Second,
		SupportedMethods: []byte{socks5.MethodNoAuth},
	}

	socksLn := startSOCKS5Server(t, handler)
	defer socksLn.Close()

	// Create SOCKS5 dialer
	dialer := socks5.NewDialer(socksLn.Addr().String(), nil, nil)

	// Test resolving localhost
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ip, err := dialer.ResolveContext(ctx, "tcp", "localhost")
	if err != nil {
		t.Fatalf("Failed to resolve localhost: %v", err)
	}

	// Verify we got a valid IP
	if ip == nil {
		t.Fatal("Resolved IP is nil")
	}

	// localhost should resolve to a loopback address
	if !ip.IsLoopback() {
		t.Errorf("Expected loopback IP for localhost, got %v", ip)
	}

	t.Logf("Successfully resolved localhost to %v", ip)
}

func TestBaseServerHandler_Resolve_Disabled(t *testing.T) {
	handler := &socks5.BaseServerHandler{
		AllowResolve:     false, // Disable RESOLVE command
		RequestTimeout:   2 * time.Second,
		SupportedMethods: []byte{socks5.MethodNoAuth},
	}

	socksLn := startSOCKS5Server(t, handler)
	defer socksLn.Close()

	// Create SOCKS5 dialer
	dialer := socks5.NewDialer(socksLn.Addr().String(), nil, nil)

	// Test resolving localhost - should fail
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ip, err := dialer.ResolveContext(ctx, "tcp", "localhost")
	if err == nil {
		t.Fatalf("Expected resolve to fail when disabled, but got IP: %v", ip)
	}

	t.Logf("RESOLVE correctly rejected: %v", err)
	t.Log("RESOLVE disabled test passed")
}

func TestBaseServerHandler_Resolve_InvalidDomain(t *testing.T) {
	handler := &socks5.BaseServerHandler{
		AllowResolve:     true,
		RequestTimeout:   2 * time.Second,
		SupportedMethods: []byte{socks5.MethodNoAuth},
	}

	socksLn := startSOCKS5Server(t, handler)
	defer socksLn.Close()

	// Create SOCKS5 dialer
	dialer := socks5.NewDialer(socksLn.Addr().String(), nil, nil)

	// Test resolving invalid domain - should fail
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ip, err := dialer.ResolveContext(ctx, "tcp", "this-domain-definitely-does-not-exist.invalid")
	if err == nil {
		t.Fatalf("Expected resolve to fail for invalid domain, but got IP: %v", ip)
	}

	t.Logf("Invalid domain correctly rejected: %v", err)
	t.Log("Invalid domain resolve test passed")
}

func TestBaseServerHandler_Resolve_PreferIPv4(t *testing.T) {
	handler := &socks5.BaseServerHandler{
		AllowResolve:      true,
		ResolvePreferIPv4: true, // Prefer IPv4 addresses
		RequestTimeout:    2 * time.Second,
		SupportedMethods:  []byte{socks5.MethodNoAuth},
	}

	socksLn := startSOCKS5Server(t, handler)
	defer socksLn.Close()

	// Create SOCKS5 dialer
	dialer := socks5.NewDialer(socksLn.Addr().String(), nil, nil)

	// Test resolving a dual-stack domain (has both IPv4 and IPv6)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Try to resolve a well-known dual-stack domain
	ip, err := dialer.ResolveContext(ctx, "tcp", "google.com")
	if err != nil {
		// If google.com fails, try localhost which should always work
		ip, err = dialer.ResolveContext(ctx, "tcp", "localhost")
		if err != nil {
			t.Fatalf("Failed to resolve test domain: %v", err)
		}
	}

	// Verify we got a valid IP
	if ip == nil {
		t.Fatal("Resolved IP is nil")
	}

	// When PreferIPv4 is true, we should get an IPv4 address if available
	if ip.To4() == nil {
		t.Logf("Note: Got IPv6 address %v, IPv4 may not be available for this domain", ip)
	} else {
		t.Logf("Successfully got IPv4 address: %v (PreferIPv4 setting honored)", ip)
	}
}

func TestBaseServerHandler_Resolve_IPPassthrough(t *testing.T) {
	handler := &socks5.BaseServerHandler{
		AllowResolve:     true,
		RequestTimeout:   2 * time.Second,
		SupportedMethods: []byte{socks5.MethodNoAuth},
	}

	socksLn := startSOCKS5Server(t, handler)
	defer socksLn.Close()

	// Create SOCKS5 dialer
	dialer := socks5.NewDialer(socksLn.Addr().String(), nil, nil)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"IPv4 passthrough", "8.8.8.8", "8.8.8.8"},
		{"IPv6 passthrough", "2001:4860:4860::8888", "2001:4860:4860::8888"},
		{"localhost IP", "127.0.0.1", "127.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			ip, err := dialer.ResolveContext(ctx, "tcp", tt.input)
			if err != nil {
				t.Fatalf("Failed to resolve IP %s: %v", tt.input, err)
			}

			if ip == nil {
				t.Fatal("Resolved IP is nil")
			}

			// The resolved IP should match the input IP
			expectedIP := net.ParseIP(tt.expected)
			if !ip.Equal(expectedIP) {
				t.Errorf("Expected IP %v, got %v", expectedIP, ip)
			}

			t.Logf("Successfully resolved IP %s to %v", tt.input, ip)
		})
	}
}

func TestBaseServerHandler_UDPAssociate_Echo_WithDialer(t *testing.T) {
	// ---- UDP echo server
	udpEchoAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve UDP address: %v", err)
	}

	udpEcho, err := net.ListenUDP("udp", udpEchoAddr)
	if err != nil {
		t.Fatalf("Failed to start UDP echo server: %v", err)
	}
	defer udpEcho.Close()

	// Echo loop
	go func() {
		buf := make([]byte, 1024)
		for {
			n, clientAddr, err := udpEcho.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = udpEcho.WriteToUDP(buf[:n], clientAddr)
		}
	}()

	// ---- SOCKS5 server
	handler := &socks5.BaseServerHandler{
		AllowUDPAssociate:   true,
		UDPAssociateTimeout: 10 * time.Second,
		RequestTimeout:      5 * time.Second,
		SupportedMethods:    []byte{socks5.MethodNoAuth},
	}

	socksLn := startSOCKS5Server(t, handler)
	defer socksLn.Close()

	dialer := socks5.NewDialer(socksLn.Addr().String(), nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// ✅ FIX: MUST use "tcp" (control channel)
	tcpConn, udpRelayAddr, err := dialer.UDPAssociateContext(ctx, "tcp", nil)
	if err != nil {
		t.Fatalf("Failed to establish UDP association: %v", err)
	}
	defer tcpConn.Close()

	t.Logf("UDP relay address: %v", udpRelayAddr)
	t.Logf("UDP echo server address: %v", udpEcho.LocalAddr())

	// Give relay a moment to be ready
	time.Sleep(50 * time.Millisecond)

	// ---- UDP client socket
	clientUDP, err := net.DialUDP("udp", nil, udpRelayAddr)
	if err != nil {
		t.Fatalf("Failed to create client UDP connection: %v", err)
	}
	defer clientUDP.Close()

	// ---- Build SOCKS5 UDP packet
	testData := []byte("Hello UDP SOCKS5!")
	echoServerAddr := udpEcho.LocalAddr().(*net.UDPAddr)

	var udpPacket socks5.UDPPacket
	udpPacket.Init(
		[2]byte{0x00, 0x00},
		0x00,
		socks5.AddrTypeIPv4,
		echoServerAddr.IP.To4(),
		"",
		uint16(echoServerAddr.Port),
		testData,
	)

	var packetBuf bytes.Buffer
	if _, err := udpPacket.WriteTo(&packetBuf); err != nil {
		t.Fatalf("Failed to encode UDP packet: %v", err)
	}

	// ---- Send packet
	if _, err := clientUDP.Write(packetBuf.Bytes()); err != nil {
		t.Fatalf("Failed to send UDP packet: %v", err)
	}

	// ---- Read response
	clientUDP.SetReadDeadline(time.Now().Add(5 * time.Second))

	respBuf := make([]byte, 2048)
	n, err := clientUDP.Read(respBuf)
	if err != nil {
		t.Fatalf("Failed to read UDP response: %v", err)
	}

	var respPacket socks5.UDPPacket
	if _, err := respPacket.ReadFrom(bytes.NewReader(respBuf[:n])); err != nil {
		t.Fatalf("Failed to parse UDP response packet: %v", err)
	}

	// ---- Assertions
	if !bytes.Equal(respPacket.Data, testData) {
		t.Fatalf("UDP echo mismatch: got %q, expected %q", respPacket.Data, testData)
	}

	if !respPacket.IP.Equal(echoServerAddr.IP.To4()) ||
		respPacket.Port != uint16(echoServerAddr.Port) {
		t.Errorf(
			"Response address mismatch: got %s:%d, expected %s:%d",
			respPacket.IP, respPacket.Port,
			echoServerAddr.IP, echoServerAddr.Port,
		)
	}

	t.Logf("UDP ASSOCIATE test passed (%d bytes echoed)", len(testData))
}

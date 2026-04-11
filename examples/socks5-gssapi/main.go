// Simple SOCKS5 GSSAPI authentication demo using an HMAC-SHA256 challenge-response exchange with a pre-shared secret.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/33TU/socks/socks5"
)

// sharedSecret is the pre-shared key used by both the client and server to
// authenticate the challenge-response exchange.
//
// For this demo, the client proves knowledge of this secret by returning
// HMAC-SHA256(challenge, sharedSecret).
var sharedSecret = []byte("demo-shared-secret-change-me-1234567890")

// challenges stores issued server challenges that have not yet been completed.
//
// The server sends a random 32-byte challenge to the client, then verifies the
// client's HMAC response against the stored value. Once a challenge is used, it
// is removed to prevent replay within this demo process.
var challenges sync.Map // map[string]struct{}

// AuthContext implements the client side of the SOCKS5 GSSAPI authentication
// exchange used in this example.
//
// The flow is:
//
//  1. The client sends an empty initial token.
//  2. The server replies with a random challenge.
//  3. The client returns HMAC-SHA256(challenge, sharedSecret).
//  4. The server verifies the proof and responds with an empty token to signal
//     that authentication is complete.
type AuthContext struct {
	complete bool
}

// InitSecContext implements [socks5.GSSAPIContext].
func (a *AuthContext) InitSecContext() ([]byte, error) {
	// Send an empty initial token so the server can begin the challenge-response exchange by returning a challenge.
	return []byte(""), nil
}

// AcceptSecContext implements [socks5.GSSAPIContext].
func (a *AuthContext) AcceptSecContext(serverToken []byte) ([]byte, bool, error) {
	// An empty server token means the server accepted our proof and the authentication exchange is complete.
	if len(serverToken) == 0 {
		a.complete = true
		return nil, true, nil
	}

	// Otherwise, the server token is the challenge that we must authenticate.
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write(serverToken)
	proof := mac.Sum(nil)

	return proof, false, nil
}

// IsComplete implements [socks5.GSSAPIContext].
func (a *AuthContext) IsComplete() bool {
	return a.complete
}

func startSOCKS5Server() error {
	handler := &socks5.BaseServerHandler{
		AllowConnect:      true,
		AllowBind:         true,
		AllowUDPAssociate: true,
		AllowResolve:      true,

		SupportedMethods: []byte{socks5.MethodGSSAPI},

		GSSAPIAuthenticator: func(ctx context.Context, token []byte) (resp []byte, done bool, err error) {
			log.Printf("Received GSSAPI token: %x", token)

			// Any non-HMAC-sized token is treated as the initial client token that
			// starts authentication. In response, issue a fresh random challenge.
			if len(token) != sha256.Size {
				var challenge [32]byte
				if _, err := rand.Read(challenge[:]); err != nil {
					return nil, false, fmt.Errorf("failed to generate challenge: %w", err)
				}

				challenges.Store(string(challenge[:]), struct{}{})
				log.Printf("Issued challenge: %x", challenge)
				return challenge[:], false, nil
			}

			// A 32-byte token is treated as the client's HMAC-SHA256 proof. Check
			// it against the challenges currently issued by this server instance.
			var matchedChallenge []byte

			challenges.Range(func(key, value any) bool {
				challenge := []byte(key.(string))

				mac := hmac.New(sha256.New, sharedSecret)
				mac.Write(challenge)
				expected := mac.Sum(nil)

				if hmac.Equal(expected, token) {
					matchedChallenge = challenge
					return false
				}

				return true
			})

			if matchedChallenge == nil {
				return nil, false, fmt.Errorf("invalid client proof")
			}

			challenges.Delete(string(matchedChallenge))
			log.Printf("Client authenticated with challenge: %x", matchedChallenge)

			// Return an empty token to indicate that the authentication exchange is complete.
			return []byte{}, true, nil
		},
	}

	log.Println("SOCKS5 listening on 127.0.0.1:1080")
	return socks5.ListenAndServe(context.Background(), "tcp", "127.0.0.1:1080", handler)
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() {
		if err := startSOCKS5Server(); err != nil {
			log.Println("SOCKS5 server error:", err)
		}
	}()

	time.Sleep(time.Second)

	authContext := &AuthContext{}
	dialer := socks5.NewDialerWithGSSAPI(
		"127.0.0.1:1080",
		nil,
		&socks5.GSSAPIAuth{Context: authContext},
		nil,
	)

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://httpbin.org/ip", nil)
	if err != nil {
		log.Fatalln("Failed to make HTTP request:", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln("Failed to make HTTP request:", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln("Failed to read response body:", err)
	}

	log.Println("Success - response:", string(body))
}

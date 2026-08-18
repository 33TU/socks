# 🧦 socks

A lightweight, pure Go implementation of the **SOCKS4**, **SOCKS4a**, **SOCKS5**, and **Shadowsocks 2022** protocols, providing both **client** and **server** support with advanced features like proxy chaining and multi-protocol muxing.

## ✨ Features

- 🔌 **Full SOCKS support**: SOCKS4, SOCKS4a, and SOCKS5
- 🛡️ **Shadowsocks 2022**: TCP and UDP, client and server, with replay protection
- 🔀 **Multi-protocol mux**: Handle both SOCKS4 and SOCKS5 on the same port
- ⛓️ **Proxy chaining**: Chain multiple SOCKS proxies together
- 🔐 **Authentication**: Support for no-auth, username/password, and GSSAPI
- 🎛️ **Customizable handlers**: Implement custom authentication and request handling
- 📡 Command support: CONNECT, BIND, RESOLVE, and UDP ASSOCIATE
- 🚀 **High performance**: Efficient connection handling and minimal allocations

## 📦 Installation

```bash
go get github.com/33TU/socks
```

Shadowsocks 2022 lives in its own module, so its cryptographic dependencies stay
out of the SOCKS packages:

```bash
go get github.com/33TU/socks/shadowsocks
````

## 🚀 Quick Start

### SOCKS5 Server

```go
package main

import (
    "context"
    "log"

    "github.com/33TU/socks/socks5"
)

func main() {
    handler := &socks5.BaseServerHandler{
        AllowConnect:      true,
        AllowBind:         true,
        AllowUDPAssociate: true,
        AllowResolve:      true,
    }

    log.Println("SOCKS5 server listening on :1080")
    if err := socks5.ListenAndServe(context.Background(), "tcp", ":1080", handler); err != nil {
        log.Fatal(err)
    }
}
```

### Multi-Protocol Mux Server

```go
package main

import (
	"context"
	"log"

	"github.com/33TU/socks/proxy"
	"github.com/33TU/socks/socks4"
	"github.com/33TU/socks/socks5"
)

func main() {
	handler := &proxy.ServerHandler{
		Socks4: socks4.DefaultServerHandler,
		Socks5: socks5.DefaultServerHandler,
	}

	log.Println("SOCKS4+5 mux server listening on :1080")
	if err := proxy.ListenAndServe(context.Background(), "tcp", ":1080", handler); err != nil {
		log.Fatal(err)
	}
}
```

### SOCKS5 Client

```go
package main

import (
    "context"
    "fmt"
    "io"
    "net/http"

    "github.com/33TU/socks/socks5"
)

func main() {
    dialer := &socks5.Dialer{
        ProxyAddr: "127.0.0.1:1080",
    }

    httpClient := &http.Client{
        Transport: &http.Transport{
            DialContext: dialer.DialContext,
        },
    }

    resp, err := httpClient.Get("http://httpbin.org/ip")
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    fmt.Println(string(body))
}
```

## 🔗 Proxy Chaining

Chain multiple SOCKS proxies for enhanced anonymity:

```go
package main

import (
	"context"

	"github.com/33TU/socks/chain"
	"github.com/33TU/socks/socks4"
	"github.com/33TU/socks/socks5"
)

func main() {
	dialer, err := chain.New(
		&socks4.Dialer{ProxyAddr: "127.0.0.1:1081"},
		&socks5.Dialer{ProxyAddr: "127.0.0.1:1082"},
	)
	if err != nil {
		panic(err)
	}

	conn, err := dialer.DialContext(context.Background(), "tcp", "httpbin.org:443")
	if err != nil {
		panic(err)
	}
	defer conn.Close()
}
```

## 🎛️ Custom Handlers

```go
type CustomHandler struct{}

func (h *CustomHandler) OnAccept(ctx context.Context, conn net.Conn) error {
    return nil
}

func (h *CustomHandler) OnAuthUserPass(ctx context.Context, conn net.Conn, username, password string) error {
    if username == "admin" && password == "secret" {
        return nil
    }
    return errors.New("invalid credentials")
}

func (h *CustomHandler) OnRequest(ctx context.Context, conn net.Conn, req *socks5.Request) error {
	if req.Command != socks5.CmdConnect {
		return errors.New("only CONNECT command is supported")
	}
	return c.OnConnect(ctx, conn, req)
}
```

### UDP ASSOCIATE (DNS over SOCKS5)

Run server:

```bash
go run examples/socks5/main.go
```

Run client:

```bash
go run examples/socks5-udp-associate/main.go
```

Example output:

```
SOCKS5 UDP ready
Sent DNS query
Received bytes: 44
Response from: 0.1.0.1:53
Payload size: 44
DNS raw (first 32 bytes): 12348180000100010000000006676f6f676c6503636f6d0000010001c00c0001
```

```go
package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/33TU/socks/socks5"
)

func main() {
	d := socks5.NewDialer("127.0.0.1:1080", nil, nil)

	// 1. Get PacketConn (this does UDP ASSOCIATE internally)
	pc, err := d.ListenPacket(context.Background(), "tcp", nil)
	if err != nil {
		panic(err)
	}
	defer pc.Close()

	fmt.Println("SOCKS5 UDP ready")

	// Optional: timeout so Read doesn't hang forever
	pc.SetDeadline(time.Now().Add(5 * time.Second))

	// 2. DNS query (google.com A record)
	dnsQuery := []byte{
		0x12, 0x34, 0x01, 0x00,
		0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,

		0x06, 'g', 'o', 'o', 'g', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,

		0x00, 0x01, 0x00, 0x01,
	}

	target := &net.UDPAddr{
		IP:   net.IPv4(1, 1, 1, 1),
		Port: 53,
	}

	var buf [4096]byte

	// Send multiple queries to demonstrate that the same PacketConn can be reused without re-associating
	for i := 0; i < 3; i++ {
		// 3. Send DNS query
		_, err = pc.WriteTo(dnsQuery, target)
		if err != nil {
			panic(err)
		}

		fmt.Println("Sent DNS query")

		// 4. Read response
		n, addr, err := pc.ReadFrom(buf[:])
		if err != nil {
			panic(err)
		}

		fmt.Println("Received bytes:", n)
		fmt.Println("Response from:", addr)

		// 5. DNS payload is already unwrapped (no SOCKS5 header!)
		data := buf[:n]

		fmt.Println("Payload size:", len(data))
		fmt.Printf("DNS raw (first 32 bytes): %x\n", data[:min(32, len(data))])
	}
}
```

---

### RESOLVE (DNS via SOCKS5)

Run server:

```bash
go run examples/socks5/main.go
```

Run client:

```bash
go run examples/socks5-resolve/main.go
```

Example output:

```
Resolved localhost       -> ::1
Resolved google.com      -> 2a00:1450:4026:807::200e
Resolved cloudflare.com  -> 2606:4700::6810:84e5
```

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/33TU/socks/socks5"
)

func main() {
	d := socks5.NewDialer("127.0.0.1:1080", nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hosts := []string{
		"localhost",
		"google.com",
		"cloudflare.com",
	}

	for _, host := range hosts {
		ip, err := d.ResolveContext(ctx, "tcp", host)
		if err != nil {
			fmt.Printf("Resolve failed for %s: %v\n", host, err)
			continue
		}

		fmt.Printf("Resolved %-15s -> %v\n", host, ip)
	}
}
```

## 🛡️ Shadowsocks 2022

The [`shadowsocks/`](shadowsocks/) package implements the
[Shadowsocks 2022 Edition](shadowsocks/doc.txt) (`2022-blake3-*`) for both TCP and UDP.
Earlier editions are deliberately not supported: they lack mandatory replay
protection and rely on obsolete cryptography.

It is a **separate Go module**, `github.com/33TU/socks/shadowsocks`, so that
BLAKE3 and `golang.org/x/crypto` are only pulled in by projects that actually use
Shadowsocks. Importing `github.com/33TU/socks/socks5` brings in neither. The
module is versioned with its own `shadowsocks/vX.Y.Z` tags.

Supported methods:

| Method | Key/salt bytes | UDP construction |
| --- | --: | --- |
| `2022-blake3-aes-128-gcm` | 16 | AES-GCM with an encrypted separate header |
| `2022-blake3-aes-256-gcm` | 32 | AES-GCM with an encrypted separate header |
| `2022-blake3-chacha20-poly1305` | 32 | XChaCha20-Poly1305 with a random nonce |

The pre-shared key is supplied directly, base64 encoded, and must be the exact
size the method requires. Generate one with:

```bash
openssl rand -base64 16   # 2022-blake3-aes-128-gcm
openssl rand -base64 32   # 2022-blake3-aes-256-gcm, 2022-blake3-chacha20-poly1305
```

### Shadowsocks Server

```go
package main

import (
	"context"
	"log"
	"time"

	"github.com/33TU/socks/shadowsocks"
)

func main() {
	cfg := &shadowsocks.Config{
		Method: shadowsocks.Method2022Blake3AES128GCM,
		PSK:    "iDN+jVYAcTkUxwNICMTQRA==",
	}

	handler := &shadowsocks.BaseServerHandler{
		Config:             cfg,
		AllowConnect:       true,
		RequestTimeout:     30 * time.Second,
		ConnectConnTimeout: 5 * time.Minute,
	}

	// UDP relay on the same port.
	go func() {
		udp := &shadowsocks.BaseUDPServerHandler{Config: cfg, AllowRelay: true}
		log.Fatal(shadowsocks.ListenAndServePacket(context.Background(), ":8388", udp))
	}()

	log.Println("Shadowsocks 2022 server listening on :8388")
	log.Fatal(shadowsocks.ListenAndServe(context.Background(), "tcp", ":8388", handler))
}
```

Requests are validated before anything is relayed: the header type, a timestamp
within 30 seconds of system time, and a salt that has not been seen in the last
60 seconds. A connection that fails any of these is drained rather than closed,
so a prober cannot learn how many bytes the server consumed.

TCP and UDP are wholly independent: separate entry points, separate handlers,
and no shared runtime state. Serve whichever transports you want, on the same
address if you want both.

| Mode | Call |
| --- | --- |
| TCP only | `ListenAndServe(ctx, "tcp", addr, handler)` |
| UDP only | `ListenAndServePacket(ctx, addr, udpHandler)` |
| Both | both, same address |

Unlike SOCKS5 UDP ASSOCIATE, a Shadowsocks UDP relay needs no TCP connection to
work, so a UDP-only server is perfectly usable on its own. `Dialer.ListenPacket`
opens a UDP socket and nothing else.

Both servers take a handler, `ServerHandler` for TCP and `UDPServerHandler` for
UDP, with `BaseServerHandler` and `BaseUDPServerHandler` covering the usual
cases. The UDP handler decides policy and placement per session:

```go
handler := &shadowsocks.BaseUDPServerHandler{
	Config:     cfg,
	AllowRelay: true,

	// Source address outbound sockets bind to.
	OutboundAddr: &net.UDPAddr{IP: net.ParseIP("2001:db8::1")},

	// Called for every validated packet, before name resolution.
	TargetAuthorizer: func(ctx context.Context, session *shadowsocks.UDPSession, target shadowsocks.Addr, payload []byte) error {
		if target.Port == 25 {
			return fmt.Errorf("smtp not allowed")
		}
		return nil
	},
}
```

Implement `UDPServerHandler` directly for more control: `OnSession` admits or
rejects a session, `ListenPacket` supplies its outbound socket, `OnPacket`
screens each datagram, and `OnSessionClose`, `OnError` and `OnPanic` report what
happens. A panic in any of them is contained rather than taking down the relay.

### Shadowsocks Client (TCP)

```go
dialer, err := shadowsocks.NewDialerFromURLString(
	"ss://2022-blake3-aes-128-gcm:iDN+jVYAcTkUxwNICMTQRA==@127.0.0.1:8388",
	nil,
)
if err != nil {
	log.Fatal(err)
}

client := &http.Client{
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
	},
}

resp, err := client.Get("https://example.com")
```

### Local SOCKS5 Front End

A Shadowsocks client is normally exposed to local applications as a SOCKS5
server. Because `shadowsocks.Dialer` satisfies the dialer interface the SOCKS5
server takes, that is just a matter of wiring the two together:

```go
dialer, err := shadowsocks.NewDialerFromURLString("ss://...", nil)
if err != nil {
	log.Fatal(err)
}

handler := &socks5.BaseServerHandler{
	Dialer:       dialer, // every outbound connection goes through the tunnel
	AllowConnect: true,
}

log.Fatal(socks5.ListenAndServe(ctx, "tcp", "127.0.0.1:1080", handler))
```

```bash
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

Target host names are passed through to the Shadowsocks server and resolved
there, so DNS does not leak locally. Leave BIND, UDP ASSOCIATE and RESOLVE
disabled on such a handler: the SOCKS5 server implements those with its own
sockets and resolver, which would send that traffic outside the tunnel. For UDP
through Shadowsocks, use `Dialer.ListenPacket` instead.

### Shadowsocks Client (UDP)

`ListenPacket` opens one UDP relay session and returns a `net.PacketConn`, so
datagrams can be sent to any target through the proxy:

```go
conn, err := dialer.ListenPacket(context.Background(), nil)
if err != nil {
	log.Fatal(err)
}
defer conn.Close()

resolver, _ := net.ResolveUDPAddr("udp", "1.1.1.1:53")
if _, err := conn.WriteTo(dnsQuery, resolver); err != nil {
	log.Fatal(err)
}

buf := make([]byte, 4096)
n, from, err := conn.ReadFrom(buf)
```

Packets that fail to decrypt or validate are dropped and reading continues.
Each session keeps a sliding window filter against replayed packet IDs, and the
server routes by session ID rather than source address, so a session survives a
client changing network.

### Padding

Header padding hides the length of small messages. The policy is configurable:

```go
dialer.Padding = shadowsocks.PadWhenEmpty(shadowsocks.MaxPaddingLength) // default for TCP
udpHandler.Padding = shadowsocks.PadPlainDNS(shadowsocks.MaxPaddingLength) // default for UDP
```

`PadWhenEmpty` pads only requests that carry no initial payload, which the
protocol requires; `PadPlainDNS` pads port 53 traffic; `PadAlways` and
`PadNever` are also available.

### Interoperability

The wire format was verified against the reference implementation,
[shadowsocks-go](https://github.com/database64128/shadowsocks-go), in both
directions: bytes this package emits were parsed by its parsers, and bytes its
encoders produced were parsed here. Those exact byte sequences are frozen as
test vectors in `shadowsocks/wire_vectors_test.go`, so any change to the
encoding fails the test suite. The reference implementation itself is not a
dependency.

## 📁 Examples

Check the [`examples/`](examples/) directory for more complete examples:

* [`socks4/`](examples/socks4/) - Simple SOCKS4 server
* [`socks5/`](examples/socks5/) - Simple SOCKS5 server
* [`mux/`](examples/mux/) - Multi-protocol mux server
* [`chain/`](examples/chain/) - Multi-hop proxy chaining
* [`socks5-custom-handler/`](examples/socks5-custom-handler/) - Custom handler implementation
* [`socks5-udp-associate/`](examples/socks5-udp-associate/) - UDP via SOCKS5
* [`socks5-resolve/`](examples/socks5-resolve/) - DNS resolve via SOCKS5
* [`shadowsocks/examples/server/`](shadowsocks/examples/server/) - Shadowsocks 2022 TCP and UDP server
* [`shadowsocks/examples/dial/`](shadowsocks/examples/dial/) - HTTP request through a Shadowsocks 2022 proxy
* [`shadowsocks/examples/udp/`](shadowsocks/examples/udp/) - DNS query through a Shadowsocks 2022 UDP relay
* [`shadowsocks/examples/socks5-local/`](shadowsocks/examples/socks5-local/) - Local SOCKS5 server tunnelling through Shadowsocks 2022

---

## 🏗️ Architecture

* **`socks4/`** - SOCKS4/4a protocol implementation
* **`socks5/`** - SOCKS5 protocol with authentication support
* **`shadowsocks/`** - Shadowsocks 2022 Edition, TCP and UDP (separate module)
* **`proxy/`** - Multi-protocol mux server
* **`chain/`** - Proxy chaining functionality
* **`net/`** - Network utilities and custom connection types
* **`internal/`** - Internal utilities and helpers

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🔗 Related Projects

- [socks-ipv6-relay](https://github.com/33TU/socks6-relay) - High-performance SOCKS4a/SOCKS5 relay that assigns a unique or sequential IPv6 address per connection. Useful for IP rotation and bypassing rate limits.

## 📄 License

socks is available under the [MIT License](LICENSE).

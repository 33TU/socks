# 🧦 socks

A lightweight, pure Go implementation of **SOCKS4**, **SOCKS4a**, and **SOCKS5** protocols, providing both **client** and **server** support with advanced features like proxy chaining and multi-protocol muxing.

## ✨ Features

- 🔌 **Full SOCKS support**: SOCKS4, SOCKS4a, and SOCKS5
- 🔀 **Multi-protocol mux**: Handle both SOCKS4 and SOCKS5 on the same port
- ⛓️ **Proxy chaining**: Chain multiple SOCKS proxies together
- 🔐 **Authentication**: Support for no-auth, username/password, and GSSAPI
- 🎛️ **Customizable handlers**: Implement custom authentication and request handling
- 📡 Command support: CONNECT, BIND, RESOLVE, and UDP ASSOCIATE
- 🚀 **High performance**: Efficient connection handling and minimal allocations

## 📦 Installation

```bash
go get github.com/33TU/socks
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

## 📁 Examples

Check the [`examples/`](examples/) directory for more complete examples:

* [`socks4/`](examples/socks4/) - Simple SOCKS4 server
* [`socks5/`](examples/socks5/) - Simple SOCKS5 server
* [`mux/`](examples/mux/) - Multi-protocol mux server
* [`chain/`](examples/chain/) - Multi-hop proxy chaining
* [`socks5-custom-handler/`](examples/socks5-custom-handler/) - Custom handler implementation
* [`socks5-udp-associate/`](examples/socks5-udp-associate/) - UDP via SOCKS5
* [`socks5-resolve/`](examples/socks5-resolve/) - DNS resolve via SOCKS5

---

## 🏗️ Architecture

* **`socks4/`** - SOCKS4/4a protocol implementation
* **`socks5/`** - SOCKS5 protocol with authentication support
* **`proxy/`** - Multi-protocol mux server
* **`chain/`** - Proxy chaining functionality
* **`net/`** - Network utilities and custom connection types
* **`internal/`** - Internal utilities and helpers

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🔗 Related Projects

- [socks-ipv6-relay](https://github.com/33TU/socks6-relay) - High-performance SOCKS4a/SOCKS5 relay that assigns a unique or sequential IPv6 address per connection. Useful for IP rotation and bypassing rate limits.

## 📄 License

MIT

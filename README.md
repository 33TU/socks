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
```

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
        AllowConnect: true,
        AllowBind:    true,
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
	// Create a chain: Client -> SOCKS4 -> SOCKS5 -> Target
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

	// Use the connection...
}
```

## 🎛️ Custom Handlers

Implement custom authentication and request handling:

```go
type CustomHandler struct{}

func (h *CustomHandler) OnAccept(ctx context.Context, conn net.Conn) error {
    // Custom connection acceptance logic
    return nil
}

func (h *CustomHandler) OnAuthUserPass(ctx context.Context, conn net.Conn, username, password string) error {
    // Custom username/password authentication
    if username == "admin" && password == "secret" {
        return nil
    }
    return errors.New("invalid credentials")
}

func (h *CustomHandler) OnRequest(ctx context.Context, conn net.Conn, req *socks5.Request) error {
	if req.Command != socks5.CmdConnect {
		return errors.New("only CONNECT command is supported")
	}

	return c.OnConnect(ctx, conn, req) // pass to OnConnect for handling
}
```

## 📁 Examples

Check the [`examples/`](examples/) directory for more complete examples:

- [`socks4/`](examples/socks4/) - Simple SOCKS4 server
- [`socks5/`](examples/socks5/) - Simple SOCKS5 server  
- [`mux/`](examples/mux/) - Multi-protocol mux server
- [`chain/`](examples/chain/) - Multi-hop proxy chaining
- [`socks5-custom-handler/`](examples/socks5-custom-handler/) - Custom handler implementation

## 🏗️ Architecture

- **`socks4/`** - SOCKS4/4a protocol implementation
- **`socks5/`** - SOCKS5 protocol with authentication support
- **`proxy/`** - Multi-protocol mux server
- **`chain/`** - Proxy chaining functionality
- **`net/`** - Network utilities and custom connection types
- **`internal/`** - Internal utilities and helpers

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

MIT

# 🧦 socks

A lightweight, dependency-free Go implementation of **SOCKS4**, **SOCKS4a**, and soon **SOCKS5**, providing both **client** and **server** support.

## Features

### ✅ SOCKS4 / SOCKS4a

* Full client (`Dialer`) and server (`ServeContext`) implementations
* Supports both `CONNECT` and `BIND` commands
* Customizable via handler callbacks (`OnConnect`, `OnBind`, `OnRequest`, `OnError`, etc.)
* Default handlers for simple proxying and rejection logic
* Extensive tests covering end-to-end CONNECT and BIND behavior
* `context.Context` support throughout client and server code

### 🧩 Planned

* SOCKS5 support (both client and server)
* Username/password authentication
* UDP ASSOCIATE (SOCKS5)

---

## Quick Start

### Run a SOCKS4 proxy server

```bash
go run ./cmd/socks4/main.go
```

By default, it listens on `:1080` (TCP).
You can test it using curl:

```bash
curl -v --socks4 127.0.0.1:1080 https://example.com
```

---

## Example: Using the SOCKS4 Dialer

```go
dialer := socks4.NewDialer("127.0.0.1:1080", "tcp", "user", nil)

conn, err := dialer.Connect("example.com:80")
if err != nil {
    log.Fatal(err)
}
defer conn.Close()

fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
io.Copy(os.Stdout, conn)
```

---

## Project Goals

1. Provide a **clean**, **readable**, and **tested** SOCKS implementation.
2. Support both **client** and **server** use cases.
3. No external dependencies.
4. Be fast and correct for real-world proxy usage.

---

## License

MIT

run-example-chain:
    go run examples/chain/main.go

run-example-mux:
    go run examples/mux/main.go

run-example-socks4:
    go run examples/socks4/main.go

run-example-socks5:
    go run examples/socks5/main.go

run-example-socks5-gssapi:
    go run examples/socks5-gssapi/main.go

run-example-socks5-custom-handler:
    go run examples/socks5-custom-handler/main.go

run-example-socks5-resolve:
    go run examples/socks5-resolve/main.go

run-example-socks5-udp-associate:
    go run examples/socks5-udp-associate/main.go

# The shadowsocks module is separate, so its examples are run from inside it.
run-example-shadowsocks-server:
    cd shadowsocks && go run ./examples/server

run-example-shadowsocks-dial:
    cd shadowsocks && go run ./examples/dial

run-example-shadowsocks-udp:
    cd shadowsocks && go run ./examples/udp

# Local SOCKS5 front end tunnelling through a Shadowsocks proxy.
run-example-shadowsocks-socks5-local:
    cd shadowsocks && go run ./examples/socks5-local

test-shadowsocks:
    cd shadowsocks && go test ./...

curl-socks4-server:
    curl --socks4 127.0.0.1:1080 https://httpbin.org/ip

curl-socks4a-server:
    curl --socks4a 127.0.0.1:1080 https://httpbin.org/ip

curl-socks5-server:
    curl --socks5 127.0.0.1:1080 https://httpbin.org/ip

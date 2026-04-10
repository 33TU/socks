build-all:
    just build-socks4-server build-socks5-server build-mux-server

build-socks4-server:
    go build -o bin/socks4-server ./cmd/socks4-server/*go

build-socks5-server:
    go build -o bin/socks5-server ./cmd/socks5-server/*go

build-mux-server:
    go build -o bin/mux-server ./cmd/mux-server/*go

run-mux-server:
    bin/mux-server

run-socks4-server:
    bin/socks4-server

run-socks5-server:
    bin/socks5-server

curl-socks4-server:
    curl --socks4 127.0.0.1:1080 https://httpbin.org/ip

curl-socks4a-server:
    curl --socks4a 127.0.0.1:1080 https://httpbin.org/ip

curl-socks5-server:
    curl --socks5 127.0.0.1:1080 https://httpbin.org/ip

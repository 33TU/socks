run-example-chain:
    go run examples/chain/main.go

run-example-mux:
    go run examples/mux/main.go

run-example-socks4:
    go run examples/socks4/main.go

run-example-socks5:
    go run examples/socks5/main.go

run-example-socks5-custom-handler:
    go run examples/socks5-custom-handler/main.go

curl-socks4-server:
    curl --socks4 127.0.0.1:1080 https://httpbin.org/ip

curl-socks4a-server:
    curl --socks4a 127.0.0.1:1080 https://httpbin.org/ip

curl-socks5-server:
    curl --socks5 127.0.0.1:1080 https://httpbin.org/ip

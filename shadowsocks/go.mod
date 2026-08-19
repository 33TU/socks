module github.com/33TU/socks/shadowsocks

go 1.25.1

require (
	github.com/33TU/socks v0.4.0
	github.com/zeebo/blake3 v0.2.4
	golang.org/x/crypto v0.50.0
	golang.org/x/sync v0.20.0
)

require (
	github.com/klauspost/cpuid/v2 v2.0.12 // indirect
	golang.org/x/sys v0.43.0 // indirect
)

// Build against the parent module in this repository rather than a released
// version of it. Consumers ignore this and resolve the require above.
replace github.com/33TU/socks => ../

package shadowsocks

import "fmt"

// PaddingPolicy decides how many padding bytes a header carries for a message
// to target with payloadLen bytes of payload.
//
// Padding hides the length of small messages. A TCP request header must carry
// either padding or an initial payload, so a policy that returns zero for an
// empty payload cannot be used for request headers.
type PaddingPolicy func(target Addr, payloadLen int) (int, error)

// PadWhenEmpty returns a policy that pads messages carrying no payload with a
// random length in [1, maxPadding], and pads nothing otherwise. It is the
// default for TCP request headers.
func PadWhenEmpty(maxPadding int) PaddingPolicy {
	return func(_ Addr, payloadLen int) (int, error) {
		if payloadLen > 0 {
			return 0, nil
		}
		return randomPaddingLength(maxPadding)
	}
}

// PadAlways returns a policy that pads every message with a random length in
// [1, maxPadding].
func PadAlways(maxPadding int) PaddingPolicy {
	return func(Addr, int) (int, error) {
		return randomPaddingLength(maxPadding)
	}
}

// PadPlainDNS returns a policy that pads messages to port 53 with a random
// length in [1, maxPadding], and pads nothing otherwise. It is the default for
// UDP, where plain DNS is the traffic most identifiable by packet length.
func PadPlainDNS(maxPadding int) PaddingPolicy {
	return func(target Addr, _ int) (int, error) {
		if target.Port != 53 {
			return 0, nil
		}
		return randomPaddingLength(maxPadding)
	}
}

// PadNever is a policy that never pads.
func PadNever(Addr, int) (int, error) {
	return 0, nil
}

// randomPaddingLength returns a random non-zero padding length up to maxPadding.
func randomPaddingLength(maxPadding int) (int, error) {
	if maxPadding <= 0 {
		return 0, nil
	}
	if maxPadding > MaxPaddingLength {
		return 0, fmt.Errorf("padding too large: got %d, max %d", maxPadding, MaxPaddingLength)
	}
	return RandomInt(1, maxPadding)
}

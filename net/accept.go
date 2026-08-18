package net

import (
	"context"
	"errors"
	"net"
	"time"
)

// Accept backoff bounds applied when a listener reports a recoverable error,
// such as running out of file descriptors.
const (
	MinAcceptDelay = 5 * time.Millisecond
	MaxAcceptDelay = time.Second
)

// AcceptLoop accepts connections from listener and passes each to handle.
//
// It returns nil once ctx is done, and the accept error once the listener has
// failed permanently. Any other error is reported to onError and retried with an
// increasing delay: looping straight back into Accept would spin a core for as
// long as the condition lasts, and drown the caller in error callbacks.
//
// The listener is closed when ctx is done, which is what unblocks Accept.
// onError may be nil.
func AcceptLoop(
	ctx context.Context,
	listener net.Listener,
	onError func(error),
	handle func(net.Conn),
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	var delay time.Duration

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}

			if onError != nil {
				onError(err)
			}

			// A closed listener is terminal; anything else may be transient.
			if errors.Is(err, net.ErrClosed) {
				return err
			}

			if delay == 0 {
				delay = MinAcceptDelay
			} else {
				delay = min(2*delay, MaxAcceptDelay)
			}

			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}

			continue
		}

		delay = 0
		handle(conn)
	}
}

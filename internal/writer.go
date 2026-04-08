package internal

import (
	"bufio"
	"io"
	"sync"
)

// writerPool is a pool of bufio.Writer.
var writerPool = sync.Pool{
	New: func() any {
		return bufio.NewWriterSize(nil, 128)
	},
}

// GetWriter returns a writer from the pool and resets it to the provided writer.
func GetWriter(wr io.Writer) *bufio.Writer {
	w := writerPool.Get().(*bufio.Writer)
	w.Reset(wr)
	return w
}

// PutWriter returns a writer to the pool and resets it.
func PutWriter(w *bufio.Writer) {
	w.Reset(nil)
	writerPool.Put(w)
}

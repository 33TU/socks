package internal

import (
	"bufio"
	"io"
	"sync"
)

// readerPool is a pool of bufio.Reader.
var readerPool = sync.Pool{
	New: func() any {
		return bufio.NewReaderSize(nil, 128)
	},
}

// GetReader returns a reader from the pool and resets it to the provided reader.
func GetReader(rd io.Reader) *bufio.Reader {
	r := readerPool.Get().(*bufio.Reader)
	r.Reset(rd)
	return r
}

// PutReader returns a reader to the pool and resets it.
func PutReader(r *bufio.Reader) {
	r.Reset(nil)
	readerPool.Put(r)
}

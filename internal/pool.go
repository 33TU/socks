package internal

import (
	"bufio"
	"io"
	"sync"
)

// ReaderPool is a pool of bufio.Reader.
var ReaderPool = sync.Pool{
	New: func() interface{} {
		return bufio.NewReaderSize(nil, 256)
	},
}

// GetReader returns a reader from the pool and resets it to the provided reader.
func GetReader(rd io.Reader) *bufio.Reader {
	r := ReaderPool.Get().(*bufio.Reader)
	r.Reset(rd)
	return r
}

// PutReader returns a reader to the pool and resets it.
func PutReader(r *bufio.Reader) {
	r.Reset(nil)
	ReaderPool.Put(r)
}

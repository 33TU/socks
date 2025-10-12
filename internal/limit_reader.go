package internal

import "io"

// A LimitedReader reads from R but limits the amount of
// data returned to just N bytes. Each call to Read
// updates N to reflect the new amount remaining.
// Read returns EOF when N <= 0 or when the underlying R returns EOF.
// See std io.LimitedReader for details.
type LimitedReader struct {
	R io.Reader // underlying reader
	N int64     // max bytes remaining
}

// Init initializes a LimitedReader.
func (r *LimitedReader) Init(src io.Reader, n int64) {
	r.R = src
	r.N = n
}

// Read reads up to len(p) bytes from the reader into p.
func (l *LimitedReader) Read(p []byte) (n int, err error) {
	if l.N <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > l.N {
		p = p[0:l.N]
	}
	n, err = l.R.Read(p)
	l.N -= int64(n)
	return
}

// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/apptimistco/asn/debug"
	"github.com/apptimistco/asn/debug/accumulator"
)

const (
	BlobVerOff     = int64(0)
	BlobVerSz      = 1
	BlobIdOff      = BlobVerOff + BlobVerSz
	BlobIdSz       = 1
	BlobMagic      = "asnmagic"
	BlobMagicOff   = BlobIdOff + BlobIdSz
	BlobMagicSz    = 8
	BlobRandomOff  = BlobMagicOff + BlobMagicSz
	BlobRandomSz   = 32
	BlobOwnerOff   = BlobRandomOff + BlobRandomSz
	BlobAuthorOff  = BlobOwnerOff + PubEncrSz
	BlobTimeOff    = BlobAuthorOff + PubEncrSz
	BlobTimeSz     = 8
	BlobNameLenOff = BlobTimeOff + BlobTimeSz
	BlobNameLenSz  = 1
	BlobNameOff    = BlobNameLenOff + BlobNameLenSz
)

var (
	blobs struct {
		debug.Debug
		c chan *Blob
	}
	ErrNotMagic = errors.New("Not Magic")
)

func init() {
	blobs.Set("blobs")
	blobs.c = make(chan *Blob, 16)
}

// BlobTime seeks and reads time from named or opened file.
func BlobTime(v interface{}) (t time.Time) {
	var (
		f   *os.File
		fn  string
		err error
		ok  bool
	)
	if fn, ok = v.(string); ok {
		if f, err = os.Open(fn); err != nil {
			return
		}
		defer f.Close()
	} else if f, ok = v.(*os.File); !ok {
		return
	}
	f.Seek(BlobTimeOff, os.SEEK_SET)
	(NBOReader{f}).ReadNBO(&t)
	return
}

// BlobSeek moves the ReadSeeker past the ASN blob headers
func BlobSeek(r io.ReadSeeker) (n int64, err error) {
	defer func() {
		if perr := recover(); perr != nil {
			err = perr.(error)
		}
	}()
	n = blobSeek(r)
	return
}

// blobSeek will panic on error so the calling function must recover.
func blobSeek(r io.ReadSeeker) int64 {
	var b [1]byte
	_, err := r.Seek(BlobNameLenOff, os.SEEK_SET)
	if err != nil {
		panic(err)
	}
	_, err = r.Read(b[:])
	if err != nil {
		panic(err)
	}
	n, err := r.Seek(int64(b[0]), os.SEEK_CUR)
	if err != nil {
		panic(err)
	}
	return n
}

type Blob struct {
	Owner  PubEncr
	Author PubEncr
	Time   time.Time
	Name   string
	wo     int64
	l      int
}

func BlobPoolFlush() {
	for {
		select {
		case <-blobs.c:
		default:
			return
		}
	}
}

func NewBlob() (blob *Blob) {
	select {
	case blob = <-blobs.c:
	default:
		blob = &Blob{}
	}
	return
}

func NewBlobFrom(r io.Reader) (blob *Blob, err error) {
	blob = NewBlob()
	if _, err = blob.ReadFrom(r); err != nil {
		blob.Free()
		blob = nil
	}
	return
}

func NewBlobWith(owner, author *PubEncr, s string, t time.Time) (blob *Blob) {
	blob = NewBlob()
	blob.Owner = *owner
	blob.Author = *author
	blob.Name = s
	blob.Time = t
	return
}

// FN returns a formatted file name of its time and abbreviated sum.
func (blob *Blob) FN(sum string) string {
	return fmt.Sprintf("%016x_%s", blob.Time.UnixNano(), sum[:16])
}

// Free the Blob by pooling or release it to GC if pool is full.
func (blob *Blob) Free() {
	if blob != nil {
		blob.Owner.Reset()
		blob.Author.Reset()
		blob.Time = Time0
		blob.Name = ""
		blob.wo = 0
		select {
		case blobs.c <- blob:
		default:
		}
	}
}

// Blob{}.ReadFrom *after* Id{}.ReadFrom(r)
func (blob *Blob) ReadFrom(r io.Reader) (n int64, err error) {
	var (
		b [256]byte
		a accumulator.Int64
	)
	defer func() {
		if r := recover(); r != nil {
			err, _ = r.(error)
			blobs.Diag(debug.Depth(3), err)
		}
		n = int64(a)
	}()
	a.Accumulate(r.Read(b[:BlobMagicSz]))
	if string(b[:a]) != BlobMagic {
		err = ErrNotMagic
		return
	}
	a.Accumulate(r.Read(b[:BlobRandomSz]))
	a.Accumulate(r.Read(blob.Owner[:]))
	a.Accumulate(r.Read(blob.Author[:]))
	a.Accumulate((NBOReader{r}).ReadNBO(&blob.Time))
	a.Accumulate(r.Read(b[:1]))
	if l := int(b[0]); l > 0 {
		a.Accumulate(r.Read(b[:l]))
		blob.Name = string(b[:l])
	} else {
		blob.Name = ""
	}
	return
}

// RFC822Z returns formatted time.
func (blob *Blob) RFC822Z() string { return blob.Time.Format(time.RFC822Z) }

func (blob *Blob) String() string {
	b := &bytes.Buffer{}
	fmt.Fprintln(b, "name:", blob.Name)
	fmt.Fprintln(b, "owner:", blob.Owner)
	fmt.Fprintln(b, "author:", blob.Author)
	fmt.Fprint(b, "time: ", blob.RFC822Z())
	return b.String()
}

// Write to blob header is intended to be used from a io.MultiWriter to peel
// the blob header from a stream, the first and second bytes written are
// ignored as these are the version and id fields; also ignore everything after
// the name field.
func (blob *Blob) Write(b []byte) (n int, err error) {
	n = len(b)
	switch {
	case len(b) == 0:
		blobs.Diag(debug.Depth(2), "empty write")
	case blob.Name != "":
		// done, ignore the reset
		return
	case blob.wo < BlobMagicOff:
		blob.wo += 1
		b = b[1:]
	case blob.wo >= BlobMagicOff && blob.wo < BlobRandomOff:
		if string(b[:BlobMagicSz]) != BlobMagic {
			err = ErrNotMagic
		} else {
			blob.wo += BlobMagicSz
			b = b[BlobMagicSz:]
		}
	case blob.wo >= BlobRandomOff && blob.wo < BlobOwnerOff:
		blob.wo += PubEncrSz
		b = b[BlobRandomSz:]
	case blob.wo >= BlobOwnerOff && blob.wo < BlobAuthorOff:
		copy(blob.Owner[:], b[:PubEncrSz])
		blob.wo += PubEncrSz
		b = b[PubEncrSz:]
	case blob.wo >= BlobAuthorOff && blob.wo < BlobTimeOff:
		copy(blob.Author[:], b[:PubEncrSz])
		blob.wo += PubEncrSz
		b = b[PubEncrSz:]
	case blob.wo >= BlobTimeOff && blob.wo < BlobNameLenOff:
		nanoepoch := int64(binary.BigEndian.Uint64(b[:BlobTimeSz]))
		isec := int64(time.Second)
		blob.Time = time.Unix(nanoepoch/isec, nanoepoch%isec)
		blob.wo += 8
		b = b[8:]
	case blob.wo >= BlobNameLenOff && blob.wo < BlobNameOff:
		blob.l = int(b[0])
		blob.wo += 1
		b = b[1:]
	case blob.wo >= BlobNameOff:
		if blob.l > n {
			blobs.Diag(debug.Depth(2), "incomplete name:",
				n, "bytes vs.", blob.l)
			blob.l = n
		}
		blob.Name = string(b[:blob.l])
		return
	}
	if err == nil && len(b) > 0 {
		_, err = blob.Write(b)
	}
	return
}

func (blob *Blob) WriteTo(w io.Writer) (n int64, err error) {
	var (
		b [BlobRandomSz]byte
		a accumulator.Int64
	)
	defer func() {
		if r := recover(); r != nil {
			err, _ = r.(error)
		}
		n = int64(a)
	}()
	a.Accumulate(w.Write([]byte(BlobMagic)))
	rand.Reader.Read(b[:BlobRandomSz])
	a.Accumulate(w.Write(b[:BlobRandomSz]))
	a.Accumulate(w.Write(blob.Owner[:]))
	a.Accumulate(w.Write(blob.Author[:]))
	a.Accumulate((NBOWriter{w}).WriteNBO(blob.Time))
	b[0] = byte(len(blob.Name))
	a.Accumulate(w.Write(b[:1]))
	if len(blob.Name) > 0 {
		a.Accumulate(w.Write([]byte(blob.Name)))
	}
	return
}

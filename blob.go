// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	BlobOff        = IdOff + int64(IdSz)
	BlobMagic      = "asnmagic"
	BlobMagicSz    = len(BlobMagic)
	BlobRandomSz   = 32
	BlobKeysSz     = 2 * EncrPubSz
	BlobTimeOff    = BlobOff + int64(BlobMagicSz+BlobRandomSz+BlobKeysSz)
	BlobTimeSz     = 8
	BlobNameLenOff = BlobTimeOff + int64(BlobTimeSz)
)

var (
	BlobPool    chan *Blob
	ErrNotMagic = errors.New("Not Magic")
)

func init() { BlobPool = make(chan *Blob, 16) }

func BlobFilter(fn string, after time.Time,
	f func(fn string) error) (err error) {
	fi, err := os.Stat(fn)
	if err != nil {
		return
	}
	if fi.IsDir() {
		filepath.Walk(fn,
			func(wn string, info os.FileInfo, err error) error {
				if err == nil && !info.IsDir() &&
					(after.IsZero() ||
						BlobTime(wn).After(after)) {
					err = f(wn)
				}
				return err
			})
	} else if after.IsZero() || BlobTime(fn).After(after) {
		err = f(fn)
	}
	return
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

// blobGets will panic on error so the calling function must recover.
func blobGets(fn string) string {
	f, err := os.Open(fn)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		panic(err)
	}
	defer f.Close()
	pos := blobSeek(f)
	fi, err := f.Stat()
	if err != nil {
		panic(err)
	}
	b := make([]byte, int(fi.Size()-pos))
	if _, err = f.Read(b); err != nil {
		panic(err)
	}
	return string(b)
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
	Owner  EncrPub
	Author EncrPub
	Time   time.Time
	Name   string
}

func BlobPoolFlush() {
	for {
		select {
		case <-BlobPool:
		default:
			return
		}
	}
}

func NewBlob(owner, author *EncrPub, name string) (blob *Blob) {
	select {
	case blob = <-BlobPool:
	default:
		blob = &Blob{}
	}
	blob.Owner = *owner
	blob.Author = *author
	blob.Name = name
	blob.Time = time.Now()
	return
}

func NewBlobFrom(r io.Reader) (blob *Blob, err error) {
	select {
	case blob = <-BlobPool:
	default:
		blob = &Blob{}
	}
	if _, err = blob.ReadFrom(r); err != nil {
		blob.Free()
		blob = nil
	}
	return
}

// FN returns a formatted file name of its time and abbreviated sum.
func (blob *Blob) FN(sum string) string {
	return fmt.Sprintf("%016x_%s", blob.Time.UnixNano(), sum[:16])
}

// Free the Blob by pooling or release it to GC if pool is full.
func (blob *Blob) Free() {
	if blob != nil {
		select {
		case BlobPool <- blob:
		default:
		}
	}
}

// Blob{}.ReadFrom *after* Id{}.ReadFrom(r)
func (blob *Blob) ReadFrom(r io.Reader) (n int64, err error) {
	var (
		b [256]byte
		x N
	)
	defer func() {
		n = int64(x)
	}()
	if err = x.Plus(r.Read(b[:BlobMagicSz])); err != nil {
		return
	}
	if string(b[:x]) != BlobMagic {
		err = ErrNotMagic
		return
	}
	if err = x.Plus(r.Read(b[:BlobRandomSz])); err != nil {
		return
	}
	if err = x.Plus(r.Read(blob.Owner[:])); err != nil {
		return
	}
	if err = x.Plus(r.Read(blob.Author[:])); err != nil {
		return
	}
	if err = x.Plus((NBOReader{r}).ReadNBO(&blob.Time)); err != nil {
		return
	}
	if err = x.Plus(r.Read(b[:1])); err != nil {
		return
	}
	if l := int(b[0]); l > 0 {
		if err = x.Plus(r.Read(b[:l])); err != nil {
			return
		}
		blob.Name = string(b[:l])
	} else {
		blob.Name = ""
	}
	return
}

// RFC822Z returns formatted time.
func (blob *Blob) RFC822Z() string { return blob.Time.Format(time.RFC822Z) }

// SummingWriteContentsTo writes a blob with v contents and returns it's sum
// along with bytes written and any error.
func (blob *Blob) SummingWriteContentsTo(w io.Writer, v interface{}) (sum *Sum,
	n int64, err error) {
	var (
		b [BlobRandomSz]byte
		x N
	)
	h := sha512.New()
	m := io.MultiWriter(w, h)
	defer func() {
		if err == nil {
			sum = new(Sum)
			copy(sum[:], h.Sum([]byte{}))
		} else {
			Diag.Println(err)
		}
		h.Reset()
		h = nil
		n = int64(x)
	}()
	if err = x.Plus(Latest.WriteTo(m)); err != nil {
		return
	}
	if err = x.Plus(BlobId.Version(Latest).WriteTo(m)); err != nil {
		return
	}
	if err = x.Plus(m.Write([]byte(BlobMagic))); err != nil {
		return
	}
	rand.Reader.Read(b[:BlobRandomSz])
	if err = x.Plus(m.Write(b[:BlobRandomSz])); err != nil {
		return
	}
	if err = x.Plus(m.Write(blob.Owner[:])); err != nil {
		return
	}
	if err = x.Plus(m.Write(blob.Author[:])); err != nil {
		return
	}
	if err = x.Plus((NBOWriter{m}).WriteNBO(blob.Time)); err != nil {
		return
	}
	b[0] = byte(len(blob.Name))
	if err = x.Plus(m.Write(b[:1])); err != nil {
		return
	}
	if b[0] > 0 {
		if err = x.Plus(m.Write([]byte(blob.Name[:]))); err != nil {
			return
		}
	}
	switch t := v.(type) {
	case Mark:
		err = x.Plus(t.WriteTo(m))
	case Sums:
		err = x.Plus(t.WriteTo(m))
	case *bytes.Buffer:
		err = x.Plus(t.WriteTo(m))
	case []byte:
		err = x.Plus(m.Write(t))
	case string:
		err = x.Plus(m.Write([]byte(t)))
	case io.Reader:
		err = x.Plus(io.Copy(m, t))
	}
	return
}

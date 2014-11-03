// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

// SeekBlobContent moves the ReadSeeker past the ASN blob headers
func SeekBlobContent(r io.ReadSeeker) (n int64, err error) {
	var b [1]byte
	n, err = r.Seek(BlobNameLenOff, os.SEEK_SET)
	if err != nil {
		return
	}
	_, err = r.Read(b[:])
	if err != nil {
		return
	}
	n, err = r.Seek(int64(b[0]), os.SEEK_CUR)
	return
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

// File blob with v contents in repos returning file name, sum and any error.
func (blob *Blob) File(repos Reposer, v interface{}) (fn string, sum *Sum,
	err error) {
	f, err := ioutil.TempFile(repos.DN(), "temp_")
	if err != nil {
		return
	}
	if sum, _, err = blob.SummingWriteContentsTo(f, v); err == nil {
		fn = BlobFN(repos, sum)
		MkReposPath(fn)
		err = syscall.Link(f.Name(), fn)
	}
	tn := f.Name()
	f.Close()
	syscall.Unlink(tn)
	return
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

// Blobber links and redistributes blob files
func (blob *Blob) Proc(repos Reposer, sum *Sum, fn string,
	// send the named blob file to given or all users
	send func(string, ...*EncrPub)) {
	user := GetAsnUser(repos, &blob.Owner)
	switch {
	case blob.Name == "" ||
		blob.Name == "asn/messages/" ||
		blob.Name == "asn/messages":
		if user != "bridge" {
			var to []*EncrPub
			sendto := func(keys ...*EncrPub) {
				for _, k := range keys {
					if !KeysHasKey(to, k) {
						ln := UserPN(repos, k,
							"asn", "messages",
							sum.String()[:32])
						MkReposPath(ln)
						syscall.Link(fn, ln)
						to = append(to, k)
					}
				}
			}
			// First link to sender
			sendto(&blob.Author)
			if moderators := GetAsnModerators(repos,
				&blob.Owner); len(moderators) != 0 {
				sendto(moderators...)
				CleanKeys(moderators)
				moderators = nil
			} else if subscribers := GetAsnSubscribers(repos,
				&blob.Owner); len(subscribers) != 0 {
				sendto(subscribers...)
				CleanKeys(subscribers)
				subscribers = nil
			} else if blob.Owner != blob.Author {
				sendto(&blob.Owner)
			}
			send(fn, to...)
		}
		// FIXME bridge
	case blob.Name == "asn/mark":
		ln := UserPN(repos, &blob.Owner,
			"asn", "messages", sum.String()[:32])
		MkReposPath(ln)
		syscall.Link(fn, ln)
		send(fn)
	case strings.HasSuffix(blob.Name, "/"):
		ln := UserPN(repos, &blob.Owner,
			filepath.FromSlash(blob.Name[:len(blob.Name)-1]),
			sum.String()[:32])
		MkReposPath(ln)
		syscall.Link(fn, ln)
	case blob.Name == "asn/removals":
		// FIXME
	case blob.Name == "asn/approvals":
		// FIXME
	default:
		ln := UserPN(repos, &blob.Owner, filepath.FromSlash(blob.Name))
		if blob.Time.After(BlobTime(ln)) {
			FlagDeletion(ln)
			syscall.Unlink(ln)
			MkReposPath(ln)
			syscall.Link(fn, ln)
		} else { // older blob so flag it and don't link ref
			FlagDeletion(fn)
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
	case []byte:
		err = x.Plus(m.Write(t))
	case string:
		err = x.Plus(m.Write([]byte(t)))
	case io.Reader:
		err = x.Plus(io.Copy(m, t))
	}
	return
}

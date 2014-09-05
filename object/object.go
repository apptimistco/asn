// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package object

import (
	"crypto/rand"
	"github.com/apptimistco/datum"
	"github.com/apptimistco/encr"
	"github.com/apptimistco/nbo"
	"io"
	"time"
)

type Code uint8

const (
	_ Code = iota
	BlobCode
	ASNCode
	UserCode
	PackCode
)

func (c Code) IsBlob() bool { return c == BlobCode }
func (c Code) IsASN() bool  { return c == ASNCode }
func (c Code) IsUser() bool { return c == UserCode }
func (c Code) IsPack() bool { return c == PackCode }

// Code{}.ReadFrom *after* Magic{}.ReadFrom
func (c *Code) ReadFrom(r io.Reader) (n int64, err error) {
	ni, err := (nbo.Reader{r}).ReadNBO((*uint8)(c))
	if err == nil {
		n = int64(ni)
	}
	return
}

// Code{}.WriteTo *after* Magic{}.WriteTo
func (c Code) WriteTo(w io.Writer) (n int64, err error) {
	ni, err := (nbo.Writer{w}).WriteNBO(uint8(c))
	if err == nil {
		n = int64(ni)
	}
	return
}

type Header struct {
	Owner  encr.Pub
	Author encr.Pub
	Time   time.Time
}

// Header{}.ReadFrom *after* Code{}.ReadFrom
func (h *Header) ReadFrom(r io.Reader) (n int64, err error) {
	var unique [24]byte
	ni, err := r.Read(unique[:])
	if err != nil {
		return
	}
	n += int64(ni)
	ni, err = r.Read(h.Owner[:])
	if err != nil {
		return
	}
	n += int64(ni)
	ni, err = r.Read(h.Author[:])
	if err != nil {
		return
	}
	n += int64(ni)
	var nanoepoch uint64
	ni, err = (nbo.Reader{r}).ReadNBO(&nanoepoch)
	if err != nil {
		return
	}
	n += 8
	sec := int64(time.Second)
	i := int64(nanoepoch)
	h.Time = time.Unix(i/sec, i%sec)
	return
}

// Header{}.WriteTo *after* Code{}.WriteTo
//
// This only writes Owner and Author from Header; the unique random data and
// time stamp are generated w/in.
func (h *Header) WriteTo(w io.Writer) (n int64, err error) {
	var unique [24]byte
	ni, err := rand.Reader.Read(unique[:])
	if err != nil {
		return
	}
	ni, err = w.Write(unique[:])
	if err != nil {
		return
	}
	n += int64(ni)
	ni, err = w.Write(h.Owner[:])
	if err != nil {
		return
	}
	n += int64(ni)
	ni, err = w.Write(h.Author[:])
	if err != nil {
		return
	}
	n += int64(ni)
	ni, err = (nbo.Writer{w}).WriteNBO(uint64(time.Now().UnixNano()))
	if err == nil {
		n += int64(ni)
	}
	return
}

type Magic [7]uint8

var (
	MagicString = Magic{'a', 's', 'n', 'o', 'b', 'j', 0}
	secretMagic = MagicString
)

func (m *Magic) IsMagic() bool { return *m == secretMagic }

func (m *Magic) ReadFrom(r io.Reader) (n int64, err error) {
	ni, err := r.Read(m[:])
	if err != nil {
		return
	}
	n = int64(ni)
	return
}

// Use MagicString.WriteTo(w)
func (m *Magic) WriteTo(w io.Writer) (n int64, err error) {
	ni, err := w.Write(m[:])
	if err != nil {
		return
	}
	n = int64(ni)
	return
}

type Pack []*datum.Datum

func (p *Pack) Append(d *datum.Datum) { *p = append(*p, d) }

// Pack{}.ReadFrom *after* Header{}.ReadFrom
func (p *Pack) ReadFrom(r io.Reader) (n int64, err error) {
	var count uint32
	ni, err := (nbo.Reader{r}).ReadNBO(&count)
	if err != nil {
		return
	}
	*p = make(Pack, int(count))
	for i := 0; i < int(count); i++ {
		var l uint32
		ni, err = (nbo.Reader{r}).ReadNBO(&l)
		if err != nil {
			break
		}
		n += int64(ni)
		d := datum.Pull()
		d.Limit(int64(l))
		nd, rerr := d.ReadFrom(r)
		if rerr != nil {
			err = rerr
			break
		}
		(*p)[i] = d
		n += nd
	}
	return
}

// Pack{}.WriteTo *after* Header{}.WriteTo
func (p *Pack) WriteTo(w io.Writer) (n int64, err error) {
	ni, err := (nbo.Writer{w}).WriteNBO(uint32(len(*p)))
	if err != nil {
		return
	}
	for _, d := range *p {
		ni, err = (nbo.Writer{w}).WriteNBO(uint32(d.Len()))
		if err != nil {
			break
		}
		n += int64(ni)
		nd, werr := d.WriteTo(w)
		if werr != nil {
			err = werr
			break
		}
		n += int64(nd)
	}
	return
}

type Tree []struct {
	Sum  datum.Sum
	Name string
}

func (p *Tree) Append(sum datum.Sum, name string) {
	*p = append(*p, struct {
		Sum  datum.Sum
		Name string
	}{sum, name})
}

// Tree{}.ReadFrom *after* Header{}.ReadFrom
func (p *Tree) ReadFrom(r io.Reader) (n int64, err error) {
	var count uint32
	ni, err := (nbo.Reader{r}).ReadNBO(&count)
	if err != nil {
		return
	}
	n += int64(ni)
	*p = make(Tree, int(count))
	for i := 0; i < int(count); i++ {
		var b [256]byte
		var l uint8
		ni, err = r.Read((*p)[i].Sum[:])
		if err != nil {
			break
		}
		n += int64(ni)
		ni, err = (nbo.Reader{r}).ReadNBO(&l)
		if err != nil {
			break
		}
		n += int64(ni)
		ni, err = r.Read(b[:l])
		if err != nil {
			break
		}
		n += int64(ni)
		(*p)[i].Name = string(b[:ni])
	}
	return
}

// Tree{}.WriteTo *after* Header{}.WriteTo
func (p *Tree) WriteTo(w io.Writer) (n int64, err error) {
	ni, err := (nbo.Writer{w}).WriteNBO(uint32(len(*p)))
	if err != nil {
		return
	}
	for _, blob := range *p {
		ni, err = w.Write(blob.Sum[:])
		if err != nil {
			break
		}
		n += int64(ni)
		l := uint8(len(blob.Name))
		ni, err = (nbo.Writer{w}).WriteNBO(l)
		if err != nil {
			break
		}
		n += int64(ni)
		ni, err = w.Write([]byte(blob.Name))
		if err != nil {
			break
		}
		n += int64(ni)
	}
	return
}

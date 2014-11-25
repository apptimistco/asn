// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn

import (
	"bytes"
	"code.google.com/p/go.crypto/nacl/box"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
)

const (
	EncrPubSz = 32
	EncrSecSz = 32
)

type EncrPubList []EncrPub

func (keys EncrPubList) Has(x *EncrPub) bool {
	for _, k := range keys {
		if k == *x {
			return true
		}
	}
	return false
}

// EncrPubList.fromBlob panics on error so the calling function must recover.
func (lp *EncrPubList) fromBlob(fn string) {
	f, err := os.Open(fn)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		panic(err)
	}
	defer f.Close()
	pos := blobSeek(f)
	fi, err := f.Stat()
	if err != nil {
		panic(err)
	}
	n := int(fi.Size()-pos) / EncrPubSz
	keys := make([]EncrPub, n)
	for i := 0; i < n; i++ {
		f.Read(keys[i][:])
	}
	*lp = keys
}

// EncrPub[lic] key
type EncrPub [EncrPubSz]byte

// Decode the given hexadecimal character string into a new
// public encryption key.
func NewEncrPubString(s string) (*EncrPub, error) {
	return NewEncrPub(s)
}

// NewEncrPubReader reads a binary key from given reader.
func NewEncrPubReader(r io.Reader) (*EncrPub, error) {
	return NewEncrPub(r)
}

// NewEncrPub creates a binary key from given reader or string.
func NewEncrPub(v interface{}) (pub *EncrPub, err error) {
	defer func() {
		if perr := recover(); perr != nil {
			err = perr.(error)
		}
	}()
	pub = newEncrPub(v)
	return
}

// newEncrPub will panic on error so the calling function must recover.
func newEncrPub(v interface{}) *EncrPub {
	pub := &EncrPub{}
	switch t := v.(type) {
	case string:
		if b, err := DecodeStringExactly(t, EncrPubSz); err != nil {
			panic(err)
		} else {
			copy(pub[:], b[:])
			b = nil
		}
		return pub
	case io.Reader:
		if _, err := t.Read(pub[:]); err != nil {
			panic(err)
		}
		return pub
	default:
		panic(os.ErrInvalid)
	}
}

// New, random public and secret encryption keys.
func NewRandomEncrKeys() (*EncrPub, *EncrSec, error) {
	pub, sec, err := box.GenerateKey(rand.Reader)
	return (*EncrPub)(pub), (*EncrSec)(sec), err
}

// Return the public key as a byte slice.
func (pub *EncrPub) Bytes() (b []byte) {
	copy(b[:], pub[:])
	return
}

// Equal returns a boolean reporting whether another key is equivalent.
func (pub *EncrPub) Equal(other *EncrPub) bool {
	return bytes.Equal(pub[:], other[:])
}

// fromBlob will panic on error so the calling function must recover.
func (pub *EncrPub) fromBlob(fn string) int {
	f, err := os.Open(fn)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		panic(err)
	}
	defer f.Close()
	blobSeek(f)
	n, err := f.Read(pub[:])
	if err != nil {
		panic(err)
	}
	return n
}

func (pub *EncrPub) GetYAML() (string, interface{}) {
	if pub != nil {
		return "", pub.String()
	}
	return "", ""
}

// Recast the public key to its basic type.
func (pub *EncrPub) Recast() *[EncrPubSz]byte {
	return (*[EncrPubSz]byte)(pub)
}

func (pub *EncrPub) SetYAML(t string, v interface{}) bool {
	if s, ok := v.(string); ok && len(s) > 0 {
		if p, err := NewEncrPubString(s); err == nil {
			*pub = *p
			return true
		}
	}
	return false
}

// Encode the public key as a hexadecimal character string.
func (pub *EncrPub) String() string {
	return hex.EncodeToString([]byte(pub[:]))
}

// Secret key
type EncrSec [EncrSecSz]byte

// Decode the given hexadecimal character string into a new secret key.
func NewEncrSecString(s string) (*EncrSec, error) {
	b, err := DecodeStringExactly(s, EncrSecSz)
	if err != nil {
		return nil, err
	}
	sec := &EncrSec{}
	copy(sec[:], b[:])
	return sec, nil
}

// Return the secret key as a byte slice.
func (sec *EncrSec) Bytes() (b []byte) {
	copy(b[:], sec[:])
	return
}

func (sec *EncrSec) GetYAML() (string, interface{}) {
	if sec != nil {
		return "", sec.String()
	}
	return "", ""
}

// Recast the secret key to its basic type.
func (sec *EncrSec) Recast() *[EncrSecSz]byte {
	return (*[EncrSecSz]byte)(sec)
}

func (sec *EncrSec) SetYAML(t string, v interface{}) bool {
	if s, ok := v.(string); ok && len(s) > 0 {
		if p, err := NewEncrSecString(s); err == nil {
			*sec = *p
			return true
		}
	}
	return false
}

// Encode the secret key as a hexadecimal character string.
func (sec *EncrSec) String() string {
	return hex.EncodeToString([]byte(sec[:]))
}

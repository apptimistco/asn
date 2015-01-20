// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"golang.org/x/crypto/nacl/box"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

const (
	SharedSz    = 32
	NonceSz     = 24
	BoxOverhead = box.Overhead
)

var (
	ErrNonce = errors.New("invalid nonce")
	ErrSeal  = errors.New("can't seal box")
	ErrOpen  = errors.New("can't open box")
)

// New() creates a Box of given sequence length, nonce, peer and the subject
// encryption key pair.
//
// The sequence length is the number of trailing bytes of the Nonce pair used
// as BigEndian counters {0, 1, 2, 4, or 8}.
//
// The initial nonce is usually the self-signed Pub key of the service.  It's
// either compiled or otherwise configured into the App and server daemon.
// Note that this parameter is an interface. If the underlying type is: none,
// it's copied into the initial open and seal nonce; signature, the first
// NouncSz bytes are copied; oterwise, it's decoded from the hexadecimal
// string.
func NewBox(seqLen int, nonce interface{}, peer *EncrPub,
	pub *EncrPub, sec *EncrSec) *Box {
	x := &Box{Key: NewSharedKey(peer, sec)}
	x.OpenNonce, _ = Noncer(nonce)
	x.SealNonce, _ = Noncer(nonce)
	if x.SeqLen = seqLen; x.SeqLen > 0 {
		var o, s uint64
		i := NonceSz - x.SeqLen
		if bytes.Compare(pub[:], peer[:]) < 0 {
			o, s = 2, 1
		} else {
			o, s = 1, 2
		}
		switch x.SeqLen {
		case 1:
			x.OpenNonce[i] = byte(o)
			x.SealNonce[i] = byte(s)
		case 2:
			binary.BigEndian.PutUint16(x.OpenNonce[i:], uint16(o))
			binary.BigEndian.PutUint16(x.SealNonce[i:], uint16(s))
		case 4:
			binary.BigEndian.PutUint32(x.OpenNonce[i:], uint32(o))
			binary.BigEndian.PutUint32(x.SealNonce[i:], uint32(s))
		case 8:
			binary.BigEndian.PutUint64(x.OpenNonce[i:], o)
			binary.BigEndian.PutUint64(x.SealNonce[i:], s)
		}
	}
	return x
}

// Box provides parameters and methods to exchange encrypted info between
// endpoints.
type Box struct {
	OpenNonce *Nonce
	SealNonce *Nonce
	SeqLen    int
	Key       *Shared
}

// Decrypt a byte slice
func (x *Box) Open(out, in []byte) ([]byte, error) {
	black, ok := box.OpenAfterPrecomputation(out, in,
		x.OpenNonce.Recast(), x.Key.Recast())
	if !ok {
		black = black[:0]
		return black, ErrOpen
	}
	x.OpenNonce.Inc(x.SeqLen)
	return black, nil
}

// Encrypt a byte slice
func (x *Box) Seal(out, in []byte) ([]byte, error) {
	red := box.SealAfterPrecomputation(out, in,
		x.SealNonce.Recast(), x.Key.Recast())
	if len(red) == 0 {
		return red, ErrSeal
	}
	x.SealNonce.Inc(x.SeqLen)
	return red, nil
}

// Noncer() creates a Nonce from the given interface as follows:
//	*Nonce	copy
//	*Sig	copy the first NonceSz bytes
//	string	decode the hexadecimal string
func Noncer(v interface{}) (*Nonce, error) {
	switch t := v.(type) {
	case *Nonce:
		nonce := &Nonce{}
		copy(nonce[:], t[:NonceSz])
		return nonce, nil
	case *AuthSig:
		nonce := &Nonce{}
		copy(nonce[:], t[:NonceSz])
		return nonce, nil
	case string:
		return NewNonceString(t)
	}
	return nil, ErrNonce
}

type Nonce [NonceSz]byte

// Inc[rement] the Box Nounce by two.
func (x *Nonce) Inc(l int) {
	switch l {
	case binary.Size(uint8(0)):
		seq := x[NonceSz-l]
		seq += 2
		x[NonceSz-l] = seq
	case binary.Size(uint16(0)):
		seq := binary.BigEndian.Uint16(x[NonceSz-l:])
		seq += 2
		binary.BigEndian.PutUint16(x[NonceSz-l:], seq)
	case binary.Size(uint32(0)):
		seq := binary.BigEndian.Uint32(x[NonceSz-l:])
		seq += 2
		binary.BigEndian.PutUint32(x[NonceSz-l:], seq)
	case binary.Size(uint64(0)):
		seq := binary.BigEndian.Uint64(x[NonceSz-l:])
		seq += 2
		binary.BigEndian.PutUint64(x[NonceSz-l:], seq)
	}
}

// Decode the given hexadecimal character string into a new Nonce.
func NewNonceString(s string) (*Nonce, error) {
	b, err := DecodeStringExactly(s, NonceSz)
	if err != nil {
		return nil, err
	}
	nonce := &Nonce{}
	copy(nonce[:], b[:])
	return nonce, err
}

func (x *Nonce) GetYAML() (string, interface{}) {
	if x != nil {
		return "", x.String()
	}
	return "", ""
}

// Recast the Nonce to its basic type.
func (x *Nonce) Recast() *[NonceSz]byte { return (*[NonceSz]byte)(x) }

func (x *Nonce) SetYAML(t string, v interface{}) bool {
	if s, ok := v.(string); ok && len(s) > 0 {
		if p, err := NewNonceString(s); err == nil {
			*x = *p
			return true
		}
	}
	return false
}

// Encode the Nonce key as a hexadecimal character string.
func (x *Nonce) String() string {
	return hex.EncodeToString([]byte(x[:]))
}

// Precomputed, shared box key.
type Shared [SharedSz]byte

// Precompute a shared key from the peer and secret keys.
func NewSharedKey(peer *EncrPub, sec *EncrSec) (shared *Shared) {
	shared = &Shared{}
	box.Precompute(shared.Recast(), peer.Recast(), sec.Recast())
	return shared
}

// Decode the given hexadecimal character string into a new Shared key.
func NewSharedString(s string) (*Shared, error) {
	b, err := DecodeStringExactly(s, SharedSz)
	if err != nil {
		return nil, err
	}
	shared := &Shared{}
	copy(shared[:], b[:])
	return shared, err
}

// Recast the Shared key to its basic type.
func (shared *Shared) Recast() *[SharedSz]byte {
	return (*[SharedSz]byte)(shared)
}

// Encode the Shared key as a hexadecimal character string.
func (shared *Shared) String() string {
	return hex.EncodeToString([]byte(shared[:]))
}

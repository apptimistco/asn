// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn

import (
	"encoding/hex"
	"errors"
)

var ErrDecodeLen = errors.New("non-matching decode length")

// Decode a hexadecimal characer string of an expected length.
func DecodeStringExactly(s string, l int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err == nil {
		if len(b) != l {
			err = ErrDecodeLen
		}
	}
	return b, err
}

type Pub struct {
	Encr *EncrPub
	Auth *AuthPub
}

type Sec struct {
	Encr *EncrSec
	Auth *AuthSec
}

type Quad struct {
	Pub *Pub
	Sec *Sec `yaml:"sec,omitempty"`
}

func NewQuad() (q *Quad, err error) {
	q = &Quad{
		Pub: &Pub{},
		Sec: &Sec{},
	}
	if q.Pub.Encr, q.Sec.Encr, err = NewRandomEncrKeys(); err != nil {
		q = nil
		return
	}
	if q.Pub.Auth, q.Sec.Auth, err = NewRandomAuthKeys(); err != nil {
		q = nil
		return
	}
	return
}

type Keys struct {
	Admin  *Quad
	Server *Quad
	Nonce  *Nonce
}

func (pub *Pub) Clean() {
	pub.Encr = nil
	pub.Auth = nil
}

func (sec *Sec) Clean() {
	sec.Encr = nil
	sec.Auth = nil
}

func (q *Quad) Clean() {
	if q.Pub != nil {
		q.Pub.Clean()
		q.Pub = nil
	}
	if q.Sec != nil {
		q.Sec.Clean()
		q.Sec = nil
	}
}

// Clean empties the key.
func (k *Keys) Clean() {
	if k != nil {
		if k.Admin != nil {
			k.Admin.Clean()
			k.Admin = nil
		}
		if k.Server != nil {
			k.Server.Clean()
			k.Server = nil
		}
		k.Nonce = nil
	}
}

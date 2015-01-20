// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"errors"

	"gopkg.in/yaml.v1"
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

type Keys struct {
	Admin  *Quad
	Server *Quad
	Nonce  *Nonce
}

func NewKeys() (k *Keys, err error) {
	admq, err := NewQuad()
	if err != nil {
		return
	}
	srvq, err := NewQuad()
	if err != nil {
		return
	}
	k = &Keys{
		Admin:  admq,
		Server: srvq,
	}
	sig := k.Server.Sec.Auth.Sign(k.Server.Pub.Encr[:])
	k.Nonce, err = Noncer(sig)
	return
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

/*
String format key struct like this...
	keys:
	  admin:
	    pub:
	      encr: 811eaf27961cc841b0b84439c08b98a4c95c131acb0c972e6976d85f995b3961
	      auth: 36399341866db8e8fec67462c1fa62927455d2ec205502495343b00d25747ed1
	    sec:
	      encr: 8fd509f93117430d196fd4ad5c80953c6b93dbc6bd339b529171dc9cb865ac8f
	      auth: 0fa38aacffd74eca8a879967d04b105b2f2d4da88f4fcbb160ec1e423250174336399341866db8e8fec67462c1fa62927455d2ec205502495343b00d25747ed1
	  server:
	    pub:
	      encr: d3bf326c0a9ca1c36add21586ce5ae4128162947d3f19467a84f8720aec5bc04
	      auth: 702d9f65b6dbc7c7c51a8eb906aba6274bf6ecda48cc4c04006110ec98adc425
	    sec:
	      encr: 94885cfd5a782aca9f2bff0390194d3bafc9a215a1e8b03da50702773ccb6483
	      auth: 0f2118fcdcb65b48a05bca8354742119d2d2aa80d8fe5116beb52328690a7be2702d9f65b6dbc7c7c51a8eb906aba6274bf6ecda48cc4c04006110ec98adc425
	  nonce: 2a477eb95cee5dbc5c6de3d4368c314e7e49836f8b72ec5c
*/
func (k *Keys) String() string {
	m := struct{ Keys *Keys }{k}
	b, err := yaml.Marshal(m)
	if err != nil {
		return err.Error()
	}
	return string(b)
}

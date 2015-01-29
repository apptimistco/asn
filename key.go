// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"

	"github.com/agl/ed25519"
	"golang.org/x/crypto/nacl/box"
	"gopkg.in/yaml.v1"
)

const (
	NonceSz     = 24
	PubAuthSz   = ed25519.PublicKeySize
	PubEncrSz   = 32
	SecAuthSz   = ed25519.PrivateKeySize
	SecEncrSz   = 32
	SharedSz    = 32
	SignatureSz = ed25519.SignatureSize
)

type Nonce [NonceSz]byte
type PubAuth [PubAuthSz]byte
type PubEncr [PubEncrSz]byte
type SecAuth [SecAuthSz]byte
type SecEncr [SecEncrSz]byte
type Shared [SharedSz]byte
type Signature [SignatureSz]byte

type PubEncrList []PubEncr

type PubKeys struct {
	Encr *PubEncr
	Auth *PubAuth
}

type SecKeys struct {
	Encr *SecEncr
	Auth *SecAuth
}

type UserKeys struct {
	Pub *PubKeys
	Sec *SecKeys `yaml:"sec,omitempty"`
}

type ServiceKeys struct {
	Admin  *UserKeys
	Server *UserKeys
	Nonce  *Nonce
}

func (k *PubKeys) Free() {
	if k == nil {
		return
	}
	k.Encr = nil
	k.Auth = nil
}

func (k *SecKeys) Free() {
	if k == nil {
		return
	}
	k.Encr = nil
	k.Auth = nil
}

func (k *UserKeys) Free() {
	if k == nil {
		return
	}
	k.Pub.Free()
	k.Pub = nil
	k.Sec.Free()
	k.Sec = nil
}

func (k *ServiceKeys) Free() {
	if k == nil {
		return
	}
	k.Admin.Free()
	k.Admin = nil
	k.Server.Free()
	k.Server = nil
	k.Nonce = nil
}

func (x *Nonce) Bytes() []byte {
	// FIXME do we need this copy?
	// copy(b[:], k[:])
	return x[:]
}

func (x *PubAuth) Bytes() []byte {
	return x[:]
}

func (x *PubEncr) Bytes() []byte {
	return x[:]
}

func (x *SecAuth) Bytes() []byte {
	return x[:]
}

func (x *SecEncr) Bytes() []byte {
	return x[:]
}

func (x *Shared) Bytes() []byte {
	return x[:]
}

func (x *Signature) Bytes() []byte {
	return x[:]
}

func (x *PubEncr) Equal(other *PubEncr) bool {
	return bytes.Equal(x[:], other[:])
}

func (x *Nonce) GetYAML() (string, interface{}) { return GetYAML(x) }

func (x *PubAuth) GetYAML() (string, interface{}) { return GetYAML(x) }
func (x *PubEncr) GetYAML() (string, interface{}) { return GetYAML(x) }
func (x *SecAuth) GetYAML() (string, interface{}) { return GetYAML(x) }
func (x *SecEncr) GetYAML() (string, interface{}) { return GetYAML(x) }

func (keys PubEncrList) Has(x *PubEncr) bool {
	for _, k := range keys {
		if k.Equal(x) {
			return true
		}
	}
	return false
}

func (x *Nonce) Recast() *[NonceSz]byte { return (*[NonceSz]byte)(x) }

func (x *PubAuth) Recast() *[PubAuthSz]byte { return (*[PubAuthSz]byte)(x) }
func (x *PubEncr) Recast() *[PubEncrSz]byte { return (*[PubEncrSz]byte)(x) }
func (x *SecAuth) Recast() *[SecAuthSz]byte { return (*[SecAuthSz]byte)(x) }
func (x *SecEncr) Recast() *[SecEncrSz]byte { return (*[SecEncrSz]byte)(x) }

func (x *Shared) Recast() *[SharedSz]byte { return (*[SharedSz]byte)(x) }

func (x *Signature) Recast() *[SignatureSz]byte {
	return (*[SignatureSz]byte)(x)
}

func (x *Nonce) SetYAML(t string, v interface{}) bool {
	return SetYAML(x, t, v)
}

func (x *PubAuth) SetYAML(t string, v interface{}) bool {
	return SetYAML(x, t, v)
}

func (x *PubEncr) SetYAML(t string, v interface{}) bool {
	return SetYAML(x, t, v)
}

func (x *SecAuth) SetYAML(t string, v interface{}) bool {
	return SetYAML(x, t, v)
}

func (x *SecEncr) SetYAML(t string, v interface{}) bool {
	return SetYAML(x, t, v)
}

func (x *SecAuth) Sign(m []byte) *Signature {
	return (*Signature)(ed25519.Sign(x.Recast(), m))
}

func (x *Nonce) Size() int     { return len(*x) }
func (x *PubAuth) Size() int   { return len(*x) }
func (x *PubEncr) Size() int   { return len(*x) }
func (x *SecAuth) Size() int   { return len(*x) }
func (x *SecEncr) Size() int   { return len(*x) }
func (x *Shared) Size() int    { return len(*x) }
func (x *Signature) Size() int { return len(*x) }

func (x *Nonce) String() string     { return EncodeToString(x) }
func (x *PubAuth) String() string   { return EncodeToString(x) }
func (x *PubEncr) String() string   { return EncodeToString(x) }
func (x *SecAuth) String() string   { return EncodeToString(x) }
func (x *SecEncr) String() string   { return EncodeToString(x) }
func (x *Shared) String() string    { return EncodeToString(x) }
func (x *Signature) String() string { return EncodeToString(x) }

/*
String formats like this...
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
func (k *ServiceKeys) String() string {
	/* FIXME may want wrap so that output is indented like config
	m := struct{ Keys *ServiceKeys }{k}
	b, err := yaml.Marshal(m)
	*/
	b, err := yaml.Marshal(k)
	if err != nil {
		return err.Error()
	}
	return string(b)
}

func (sig *Signature) Verify(k *PubAuth, message []byte) bool {
	return ed25519.Verify(k.Recast(), message, sig.Recast())
}

func NewNonceString(s string) (x *Nonce, err error) {
	x = new(Nonce)
	err = DecodeFromString(x, s)
	return
}

func NewPubEncr(v interface{}) (pub *PubEncr, err error) {
	switch t := v.(type) {
	case string:
		pub, err = NewPubEncrString(t)
	case io.Reader:
		pub, err = NewPubEncrReader(t)
	default:
		err = os.ErrInvalid
	}
	return
}

func NewPubAuthString(s string) (x *PubAuth, err error) {
	x = new(PubAuth)
	err = DecodeFromString(x, s)
	return
}

func NewPubEncrString(s string) (x *PubEncr, err error) {
	x = new(PubEncr)
	err = DecodeFromString(x, s)
	return
}

func NewPubEncrReader(r io.Reader) (x *PubEncr, err error) {
	x = new(PubEncr)
	_, err = r.Read(x[:])
	return
}

func NewRandomAuthKeys() (*PubAuth, *SecAuth, error) {
	pub, sec, err := ed25519.GenerateKey(rand.Reader)
	return (*PubAuth)(pub), (*SecAuth)(sec), err
}

func NewRandomEncrKeys() (*PubEncr, *SecEncr, error) {
	pub, sec, err := box.GenerateKey(rand.Reader)
	return (*PubEncr)(pub), (*SecEncr)(sec), err
}

func NewRandomUserKeys() (u *UserKeys, err error) {
	u = &UserKeys{
		Pub: new(PubKeys),
		Sec: new(SecKeys),
	}
	defer func() {
		if err != nil {
			u.Free()
			u = nil
		}
	}()
	if u.Pub.Encr, u.Sec.Encr, err = NewRandomEncrKeys(); err != nil {
		return
	}
	if u.Pub.Auth, u.Sec.Auth, err = NewRandomAuthKeys(); err != nil {
		return
	}
	return
}

func NewRandomServiceKeys() (k *ServiceKeys, err error) {
	k = new(ServiceKeys)
	defer func() {
		if err != nil {
			k.Free()
			k = nil
		}
	}()
	if k.Admin, err = NewRandomUserKeys(); err != nil {
		return
	}
	if k.Server, err = NewRandomUserKeys(); err != nil {
		return
	}
	sig := k.Server.Sec.Auth.Sign(k.Server.Pub.Encr[:])
	k.Nonce, err = Noncer(sig)
	return
}

func NewSecAuthString(s string) (x *SecAuth, err error) {
	x = new(SecAuth)
	err = DecodeFromString(x, s)
	return
}

func NewSecEncrString(s string) (k *SecEncr, err error) {
	k = new(SecEncr)
	err = DecodeFromString(k, s)
	return
}

func NewSharedString(s string) (x *Shared, err error) {
	x = new(Shared)
	err = DecodeFromString(x, s)
	return
}

func NewSignatureString(s string) (x *Signature, err error) {
	x = new(Signature)
	err = DecodeFromString(x, s)
	return
}

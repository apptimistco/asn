// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/agl/ed25519"
	"github.com/apptimistco/asn/debug/accumulator"
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

var Mirrors = &PubEncr{} // empty key as flag for sending to mirrors

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

// FIXME do we need this copy?
// copy(b[:], k[:])
func (x *Nonce) Bytes() []byte {
	return x[:]
}
func (x *PubAuth) Bytes() []byte {
	return x[:]
}
func (x *PubEncr) Bytes() []byte {
	return x[:]
}
func (x *PubEncrList) Bytes() []byte {
	return []byte("FIXME")
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

func (x *Nonce) FullString() string {
	return hex.EncodeToString(x.Bytes())
}
func (x *PubAuth) FullString() string {
	return hex.EncodeToString(x.Bytes())
}
func (x *PubEncr) FullString() string {
	return hex.EncodeToString(x.Bytes())
}
func (x *SecAuth) FullString() string {
	return hex.EncodeToString(x.Bytes())
}
func (x *SecEncr) FullString() string {
	return hex.EncodeToString(x.Bytes())
}
func (x *Shared) FullString() string {
	return hex.EncodeToString(x.Bytes())
}
func (x *Signature) FullString() string {
	return hex.EncodeToString(x.Bytes())
}

func (x *Nonce) GetYAML() (string, interface{}) {
	return "", x.FullString()
}
func (x *PubAuth) GetYAML() (string, interface{}) {
	return "", x.FullString()
}
func (x *PubEncr) GetYAML() (string, interface{}) {
	return "", x.FullString()
}
func (x *SecAuth) GetYAML() (string, interface{}) {
	return "", x.FullString()
}
func (x *SecEncr) GetYAML() (string, interface{}) {
	return "", x.FullString()
}

func (x *PubAuth) Has(v interface{}) bool {
	if x == nil {
		return false
	}
	switch t := v.(type) {
	case PubAuth:
		return bytes.Equal(x.Bytes(), t.Bytes())
	case *PubAuth:
		return bytes.Equal(x.Bytes(), t.Bytes())
	}
	return false
}

func (x *PubEncr) Has(v interface{}) bool {
	if x == nil {
		return false
	}
	switch t := v.(type) {
	case *PubEncr:
		return bytes.Equal(x.Bytes(), t.Bytes())
	case PubEncr:
		return bytes.Equal(x.Bytes(), t.Bytes())
	}
	return false
}

func (x PubEncrList) Has(v interface{}) bool {
	if x == nil {
		return false
	}
	switch t := v.(type) {
	case *PubEncr:
		for _, k := range x {
			if bytes.Equal(k.Bytes(), t.Bytes()) {
				return true
			}
		}
	case PubEncr:
		for _, k := range x {
			if bytes.Equal(k.Bytes(), t.Bytes()) {
				return true
			}
		}
	}
	return false
}

func (x *PubAuth) ReadFrom(r io.Reader) (int64, error) {
	i, err := r.Read(x.Bytes())
	return int64(i), err
}

func (x *PubEncr) ReadFrom(r io.Reader) (int64, error) {
	i, err := r.Read(x.Bytes())
	return int64(i), err
}

func (x *PubEncrList) ReadFrom(r io.Reader) (int64, error) {
	if x == nil {
		x = new(PubEncrList)
	}
	for {
		var (
			k PubEncr
			n int64
		)
		i, err := r.Read(k.Bytes())
		n += int64(i)
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return n, err
		}
		*x = append(*x, k)
	}
}

func (x *PubAuth) Reset()     { *x = PubAuth{} }
func (x *PubEncr) Reset()     { *x = PubEncr{} }
func (x *PubEncrList) Reset() { *x = PubEncrList{} }

func (x *Nonce) Recast() *[NonceSz]byte { return (*[NonceSz]byte)(x) }

func (x *PubAuth) Recast() *[PubAuthSz]byte { return (*[PubAuthSz]byte)(x) }
func (x *PubEncr) Recast() *[PubEncrSz]byte { return (*[PubEncrSz]byte)(x) }

func (x *PubEncrList) Recast() *[]PubEncr { return (*[]PubEncr)(x) }

func (x *SecAuth) Recast() *[SecAuthSz]byte { return (*[SecAuthSz]byte)(x) }
func (x *SecEncr) Recast() *[SecEncrSz]byte { return (*[SecEncrSz]byte)(x) }

func (x *Shared) Recast() *[SharedSz]byte { return (*[SharedSz]byte)(x) }

func (x *Signature) Recast() *[SignatureSz]byte {
	return (*[SignatureSz]byte)(x)
}

func (x *PubAuth) Set(v interface{}) error {
	switch t := v.(type) {
	case *PubAuth:
		if x == nil {
			panic(os.ErrInvalid)
		}
		*x = *t
	case PubAuth:
		*x = t
	default:
		return os.ErrInvalid
	}
	return nil
}

func (x *PubEncr) Set(v interface{}) error {
	switch t := v.(type) {
	case *PubEncr:
		*x = *t
	case PubEncr:
		*x = t
	default:
		return os.ErrInvalid
	}
	return nil
}

func (x *PubEncrList) Set(v interface{}) error {
	switch t := v.(type) {
	case PubEncrList:
		*x = t
	default:
		return os.ErrInvalid
	}
	return nil
}

func SetKeyYAML(x ByteSizer, t string, v interface{}) bool {
	if s, ok := v.(string); ok && len(s) > 0 {
		if err := DecodeFromString(x, s); err != nil {
			return true
		}
	}
	return false
}

func (x *Nonce) SetYAML(t string, v interface{}) bool {
	return SetKeyYAML(x, t, v)
}

func (x *PubAuth) SetYAML(t string, v interface{}) bool {
	return SetKeyYAML(x, t, v)
}

func (x *PubEncr) SetYAML(t string, v interface{}) bool {
	return SetKeyYAML(x, t, v)
}

func (x *SecAuth) SetYAML(t string, v interface{}) bool {
	return SetKeyYAML(x, t, v)
}

func (x *SecEncr) SetYAML(t string, v interface{}) bool {
	return SetKeyYAML(x, t, v)
}

func (x *ServiceKeys) SetYAML(t string, v interface{}) (ret bool) {
	defer func() {
		if perr := recover(); perr != nil {
			err := perr.(error)
			io.WriteString(os.Stderr, err.Error())
			os.Stderr.Write(NL)
		} else {
			ret = true
		}
	}()
	if t == "!!str" {
		if b, ok := Builtin[v.(string)]; ok {
			if err := yaml.Unmarshal(b, x); err != nil {
				panic(err)
			}
			return
		}
		b, err := ioutil.ReadFile(v.(string))
		if err != nil {
			panic(err)
		}
		if err := yaml.Unmarshal(b, x); err != nil {
			panic(err)
		}
		return
	}
	if t != "!!map" {
		panic(&Error{t, "neither string nor map:"})
	}
	for mk, mv := range v.(map[interface{}]interface{}) {
		mks, ok := mk.(string)
		if !ok {
			panic(errors.New("service keyword isn't a string"))
		}
		switch mks {
		case "admin":
			mvm := mv.(map[interface{}]interface{})
			x.Admin = NewUserKeysMap(mvm)
		case "server":
			mvm := mv.(map[interface{}]interface{})
			x.Server = NewUserKeysMap(mvm)
		case "nonce":
			mvs := mv.(string)
			x.Nonce, _ = NewNonceString(mvs)
		default:
			panic(&Error{mks, "invalid keyword"})
		}
	}
	return
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

func (x *Nonce) String() string     { return x.ShortString() + "..." }
func (x *PubAuth) String() string   { return x.ShortString() + "..." }
func (x *PubEncr) String() string   { return x.ShortString() + "..." }
func (x *SecAuth) String() string   { return x.ShortString() + "..." }
func (x *SecEncr) String() string   { return x.ShortString() + "..." }
func (x *Shared) String() string    { return x.ShortString() + "..." }
func (x *Signature) String() string { return x.ShortString() + "..." }

func (x *PubEncrList) String() string {
	b := new(bytes.Buffer)
	for _, k := range *x {
		fmt.Fprintln(b, k)
	}
	return b.String()
}

func (x *Nonce) ShortString() string     { return x.FullString()[:8] }
func (x *PubAuth) ShortString() string   { return x.FullString()[:8] }
func (x *PubEncr) ShortString() string   { return x.FullString()[:8] }
func (x *SecAuth) ShortString() string   { return x.FullString()[:8] }
func (x *SecEncr) ShortString() string   { return x.FullString()[:8] }
func (x *Shared) ShortString() string    { return x.FullString()[:8] }
func (x *Signature) ShortString() string { return x.FullString()[:8] }

func (sig *Signature) Verify(k *PubAuth, message []byte) bool {
	return ed25519.Verify(k.Recast(), message, sig.Recast())
}

func (k *PubAuth) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(k.Bytes())
	return int64(n), err
}

func (k *PubEncr) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(k.Bytes())
	return int64(n), err
}

func (l *PubEncrList) WriteTo(w io.Writer) (n int64, err error) {
	var a accumulator.Int64
	defer func() {
		if r := recover(); r != nil {
			err, _ = r.(error)
		}
		n = int64(a)
	}()
	for _, k := range *l {
		a.Accumulate(w.Write(k.Bytes()))
	}
	return
}

func (sig *Signature) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(sig.Bytes())
	return int64(n), err
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

func NewPubEncrReader(r io.Reader) (x *PubEncr, err error) {
	x = new(PubEncr)
	_, err = r.Read(x[:])
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

func NewPubKeysMap(m map[interface{}]interface{}) *PubKeys {
	pub := new(PubKeys)
	for mk, mv := range m {
		mks, ok := mk.(string)
		if !ok {
			panic(errors.New("pub key keyword isn't a string"))
		}
		mvs, ok := mv.(string)
		if !ok {
			panic(&Error{mks, "value not a string"})
		}
		var err error
		switch mks {
		case "auth":
			pub.Auth, err = NewPubAuthString(mvs)
		case "encr":
			pub.Encr, err = NewPubEncrString(mvs)
		default:
			panic(&Error{mks, "invalid keyword"})
		}
		if err != nil {
			panic(&Error{mks, err.Error()})
		}
	}
	return pub
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

func NewSecKeysMap(m map[interface{}]interface{}) *SecKeys {
	sec := new(SecKeys)
	for mk, mv := range m {
		mks, ok := mk.(string)
		if !ok {
			panic(errors.New("sec key keyword isn't a string"))
		}
		mvs, ok := mv.(string)
		if !ok {
			panic(&Error{mks, "value not a string"})
		}
		var err error
		switch mks {
		case "auth":
			sec.Auth, err = NewSecAuthString(mvs)
		case "encr":
			sec.Encr, err = NewSecEncrString(mvs)
		default:
			panic(&Error{mks, "invalid keyword"})
		}
		if err != nil {
			panic(&Error{mks, err.Error()})
		}
	}
	return sec
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

func NewUserKeysMap(m map[interface{}]interface{}) *UserKeys {
	u := new(UserKeys)
	for mk, mv := range m {
		mks, ok := mk.(string)
		if !ok {
			panic(errors.New("user key's keyword not a string"))
		}
		switch mks {
		case "pub":
			xm, ok := mv.(map[interface{}]interface{})
			if !ok {
				panic(&Error{mks, "not a map"})
			}
			u.Pub = NewPubKeysMap(xm)
		case "sec":
			xm, ok := mv.(map[interface{}]interface{})
			if !ok {
				panic(&Error{mks, "not a map"})
			}
			u.Sec = NewSecKeysMap(xm)
		default:
			panic(&Error{mks, "invalid keyword"})
		}
	}
	return u
}

func DecodeFromString(x ByteSizer, s string) error {
	if x == nil {
		return errors.New("destination is nil")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(b) != x.Size() {
		return os.ErrInvalid
	}
	copy(x.Bytes()[:], b[:])
	return nil
}

// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/agl/ed25519"
	"os"
)

const (
	AuthPubSz = ed25519.PublicKeySize
	AuthSecSz = ed25519.PrivateKeySize
	AuthSigSz = ed25519.SignatureSize
)

// Pub[lic] key
type AuthPub [AuthPubSz]byte

// Decode the given hexadecimal character string into a new
// public authentication key.
func NewAuthPubString(s string) (*AuthPub, error) {
	b, err := DecodeStringExactly(s, AuthPubSz)
	if err != nil {
		return nil, err
	}
	pub := &AuthPub{}
	copy(pub[:], b[:])
	return pub, err
}

// New, random public and secret authentication keys.
func NewRandomAuthKeys() (*AuthPub, *AuthSec, error) {
	pub, sec, err := ed25519.GenerateKey(rand.Reader)
	return (*AuthPub)(pub), (*AuthSec)(sec), err
}

// Return the public key as a byte slice.
func (pub *AuthPub) Bytes() (b []byte) {
	copy(b[:], pub[:])
	return
}

// fromBlob will panic on error so the calling function must recover.
func (pub *AuthPub) fromBlob(fn string) int {
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

func (pub *AuthPub) GetYAML() (string, interface{}) {
	if pub != nil {
		return "", pub.String()
	}
	return "", ""
}

// Recast the public key to its basic type.
func (pub *AuthPub) Recast() *[AuthPubSz]byte {
	return (*[AuthPubSz]byte)(pub)
}

func (pub *AuthPub) SetYAML(t string, v interface{}) bool {
	if s, ok := v.(string); ok && len(s) > 0 {
		if p, err := NewAuthPubString(s); err == nil {
			*pub = *p
			return true
		}
	}
	return false
}

// Encode the public key as a hexadecimal character string.
func (pub *AuthPub) String() string {
	return hex.EncodeToString([]byte(pub[:]))
}

// Secret key
type AuthSec [AuthSecSz]byte

// Decode the given hexadecimal character string into a new secret key.
func NewAuthSecString(s string) (*AuthSec, error) {
	b, err := DecodeStringExactly(s, AuthSecSz)
	if err != nil {
		return nil, err
	}
	sec := &AuthSec{}
	copy(sec[:], b[:])
	return sec, err
}

// Return the secret key as a byte slice.
func (sec *AuthSec) Bytes() (b []byte) {
	copy(b[:], sec[:])
	return
}

func (sec *AuthSec) GetYAML() (string, interface{}) {
	if sec != nil {
		return "", sec.String()
	}
	return "", ""
}

// Recast the Sec[ret] key to its basic type.
func (sec *AuthSec) Recast() *[AuthSecSz]byte {
	return (*[AuthSecSz]byte)(sec)
}

func (sec *AuthSec) SetYAML(t string, v interface{}) bool {
	if s, ok := v.(string); ok && len(s) > 0 {
		if p, err := NewAuthSecString(s); err == nil {
			*sec = *p
			return true
		}
	}
	return false
}

// Sign a byte slice with the associated secret key.
func (sec *AuthSec) Sign(m []byte) *AuthSig {
	return (*AuthSig)(ed25519.Sign(sec.Recast(), m))
}

// Encode the secret key as a hexadecimal character string.
func (sec *AuthSec) String() string {
	return hex.EncodeToString([]byte(sec[:]))
}

// Signature
type AuthSig [AuthSigSz]byte

// Decode the given hexadecimal character string into a new signature.
func NewAuthSigString(s string) (*AuthSig, error) {
	b, err := DecodeStringExactly(s, AuthSigSz)
	if err != nil {
		return nil, err
	}
	sig := &AuthSig{}
	copy(sig[:], b[:])
	return sig, err
}

// Return the Signature as a byte slice.
func (sig *AuthSig) Bytes() (b []byte) {
	copy(b[:], sig[:])
	return
}

func (sig *AuthSig) GetYAML() (string, interface{}) {
	if sig != nil {
		return "", sig.String()
	}
	return "", ""
}

// Recast the signature to its basic type.
func (sig *AuthSig) Recast() *[AuthSigSz]byte {
	return (*[AuthSigSz]byte)(sig)
}

func (sig *AuthSig) SetYAML(t string, v interface{}) bool {
	if s, ok := v.(string); ok && len(s) > 0 {
		if p, err := NewAuthSigString(s); err == nil {
			*sig = *p
			return true
		}
	}
	return false
}

// Encode the signature as a hexadecimal character string.
func (sig *AuthSig) String() string {
	return hex.EncodeToString([]byte(sig[:]))
}

// Verify the signed message.
func (sig *AuthSig) Verify(pub *AuthPub, message []byte) bool {
	return ed25519.Verify(pub.Recast(), message, sig.Recast())
}

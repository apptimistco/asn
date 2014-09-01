// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package keys provides random server and admin keys for an ASN service.

	$ asnkeys
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
package keys

import (
	"github.com/apptimistco/auth"
	"github.com/apptimistco/box"
	"github.com/apptimistco/encr"
	"gopkg.in/yaml.v1"
	"io"
	"os"
)

const Usage = "Usage: asnkeys\n"

var Stdout io.Writer = os.Stdout

func Main(args ...string) (err error) {
	if help(args...) {
		return
	}
	m := struct{ Keys *Keys }{}
	m.Keys, err = New()
	if err != nil {
		return
	}
	b, err := yaml.Marshal(m)
	if err != nil {
		return
	}
	Stdout.Write(b)
	return
}

func help(args ...string) bool {
	if len(args) > 1 &&
		(args[1] == "help" ||
			args[1] == "-help" ||
			args[1] == "--help" ||
			args[1] == "-h") {
		Stdout.Write([]byte(Usage))
		return true
	}
	return false
}

type Pub struct {
	Encr *encr.Pub
	Auth *auth.Pub
}

type Sec struct {
	Encr *encr.Sec
	Auth *auth.Sec
}

type Quad struct {
	Pub *Pub
	Sec *Sec `yaml:"sec,omitempty"`
}

type Keys struct {
	Admin  *Quad
	Server *Quad
	Nonce  *box.Nonce
}

func New() (k *Keys, err error) {
	k = &Keys{
		Admin:  &Quad{&Pub{}, &Sec{}},
		Server: &Quad{&Pub{}, &Sec{}},
	}
	k.Admin.Pub.Encr, k.Admin.Sec.Encr, err = encr.NewRandomKeys()
	if err != nil {
		return
	}
	k.Admin.Pub.Auth, k.Admin.Sec.Auth, err = auth.NewRandomKeys()
	if err != nil {
		return
	}
	k.Server.Pub.Encr, k.Server.Sec.Encr, err = encr.NewRandomKeys()
	if err != nil {
		return
	}
	k.Server.Pub.Auth, k.Server.Sec.Auth, err = auth.NewRandomKeys()
	if err != nil {
		return
	}
	sig := k.Server.Sec.Auth.Sign(k.Server.Pub.Encr[:])
	k.Nonce, err = box.Noncer(sig)
	return
}

// Clean empties the key.
func (k *Keys) Clean() {
	if k != nil {
		if k.Admin != nil {
			if k.Admin.Pub != nil {
				k.Admin.Pub.Encr = nil
				k.Admin.Pub.Auth = nil
				k.Admin.Pub = nil
			}
			if k.Admin.Sec != nil {
				k.Admin.Sec.Encr = nil
				k.Admin.Sec.Auth = nil
				k.Admin.Sec = nil
			}
			k.Admin = nil
		}
		if k.Server != nil {
			if k.Server.Pub != nil {
				k.Server.Pub.Encr = nil
				k.Server.Pub.Auth = nil
				k.Server.Pub = nil
			}
			if k.Server.Sec != nil {
				k.Server.Sec.Encr = nil
				k.Server.Sec.Auth = nil
				k.Server.Sec = nil
			}
			k.Server = nil
		}
		k.Nonce = nil
	}
}

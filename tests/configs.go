// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tests

import (
	"bytes"
	"github.com/apptimistco/asn/adm"
	"github.com/apptimistco/asn/keys"
	"github.com/apptimistco/asn/srv"
	"text/template"
)

var (
	// common ASN test configurations
	admTmpl = template.Must(template.New("adm").Parse(adm.Inline + `
name: siren-adm
dir: siren-adm.asn
lat: 37.774929
lon: -122.419415
keys:
  admin:
    pub:
      encr: {{.Admin.Pub.Encr}}
      auth: {{.Admin.Pub.Auth}}
    sec:
      encr: {{.Admin.Sec.Encr}}
      auth: {{.Admin.Sec.Auth}}
  server:
    pub:
      encr: {{.Server.Pub.Encr}}
      auth: {{.Server.Pub.Auth}}
  nonce: {{.Nonce}}
server:
- name: Local
  url: unix:///siren-sf.sock
  lat: 181
  lon: 0
- name: San Francisco
  url: ws://localhost:6969/asn/siren.ws
  lat: 37.774929
  lon: -122.419415
- name: Los Angeles
  url: ws://la.siren.apptimist.co/ws/siren/
  lat: 34.052234
  lon: -118.243684
`))
	srvTmpl = template.Must(template.New("srv").Parse(srv.Inline + `
name: siren-sf
dir: siren-sf.asn
lat: 37.774929
lon: -122.419415
log: siren-sf.log
pid: siren-sf.pid
keys:
  admin:
    pub:
      encr: {{.Admin.Pub.Encr}}
      auth: {{.Admin.Pub.Auth}}
  server:
    pub:
      encr: {{.Server.Pub.Encr}}
      auth: {{.Server.Pub.Auth}}
    sec:
      encr: {{.Server.Sec.Encr}}
      auth: {{.Server.Sec.Auth}}
  nonce: {{.Nonce}}
listen:
- unix:///siren-sf.sock
- ws://localhost:6969/asn/siren.ws
`))
)

func Configs() (adm, srv string) {
	k, err := keys.New()
	if err != nil {
		return
	}
	admConfigBuffer := &bytes.Buffer{}
	srvConfigBuffer := &bytes.Buffer{}
	admTmpl.Execute(admConfigBuffer, k)
	srvTmpl.Execute(srvConfigBuffer, k)
	adm = string(admConfigBuffer.Bytes())
	srv = string(srvConfigBuffer.Bytes())
	k.Clean()
	return
}

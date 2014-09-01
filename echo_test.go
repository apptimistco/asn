// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn_test

import (
	"github.com/apptimistco/asn/adm"
	"github.com/apptimistco/asn/keys"
	"github.com/apptimistco/asn/srv"
	"github.com/apptimistco/yab"
	"os"
	"testing"
	"text/template"
)

const (
	asnadm = "asnadm"
	asnsrv = "asnsrv"
)

func TestEcho(t *testing.T) {
	admTmpl := template.Must(template.New("adm").Parse(`
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
	srvTmpl := template.Must(template.New("srv").Parse(`
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
	k, err := keys.New()
	if err != nil {
		t.Fatal(err)
	}
	defer k.Clean()
	admConfig := yab.Pull()
	defer yab.Push(&admConfig)
	srvConfig := yab.Pull()
	defer yab.Push(&srvConfig)
	admTmpl.Execute(admConfig, k)
	srvTmpl.Execute(srvConfig, k)
	go srv.Main(asnsrv, srv.Inline+string(srvConfig.Buf))
	err = adm.Main(asnadm, adm.Inline+string(admConfig.Buf), "0",
		"echo", "hello", "world")
	if err != nil {
		t.Error(err)
	}
	err = adm.Main(asnadm, adm.Inline+string(admConfig.Buf), "1",
		"echo", "hello", "world")
	if err != nil {
		t.Error(err)
	}
	srv.KillAll(os.Interrupt)
}

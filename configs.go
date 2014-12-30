// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn

import (
	"bytes"
	"io/ioutil"
	"os"
	"text/template"

	"github.com/apptimistco/asn/internal/keys"
)

var (
	// common ASN test configurations
	AdmConfigFN = "siren-adm.yaml"
	AdmTmpl     = template.Must(template.New("adm").Parse(`
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
- name: sf.sock
  url: unix:///siren-sf.sock
  lat: 181
  lon: 0
- name: sf.ws
  url: ws://localhost:6969/asn/siren.ws
  lat: 37.774929
  lon: -122.419415
- name: la.ws
  url: ws://la.siren.apptimist.co/ws/siren/
  lat: 34.052234
  lon: -118.243684
`))
	SrvConfigFN = "siren-sf.yaml"
	SrvTmpl     = template.Must(template.New("srv").Parse(`
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

func WriteConfigs() {
	if _, err := os.Stat(SrvConfigFN); os.IsExist(err) {
		return
	}
	if k, err := keys.New(); err == nil {
		admConfigBuffer := &bytes.Buffer{}
		srvConfigBuffer := &bytes.Buffer{}
		AdmTmpl.Execute(admConfigBuffer, k)
		SrvTmpl.Execute(srvConfigBuffer, k)
		ioutil.WriteFile(AdmConfigFN, admConfigBuffer.Bytes(), 0660)
		ioutil.WriteFile(SrvConfigFN, srvConfigBuffer.Bytes(), 0660)
		k.Clean()
	}
}

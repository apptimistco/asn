// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

var Builtin = map[string][]byte{
	`test-keys`: []byte(`
admin:
  pub:
    encr: 3dd19090c0cd240cd380a93ad46d94e4624ef9f435e8e4d5ad985d60ce8aca10
    auth: d9b123efc0c826ca4d92771e1b73235255bd035e3710b3f83f775f2f537ce02c
  sec:
    encr: 524df11157a2eea170487d9a421f3f5b593223ec2533c723d58b87d4b582afff
    auth: 2e3d3bb0fedeba0bf04f0c069ed5405b850d047c04457a5864dcab2718f2e896d9b123efc0c826ca4d92771e1b73235255bd035e3710b3f83f775f2f537ce02c
server:
  pub:
    encr: ee738f784c74ce0bd15ace0a1e6c7d05034ef961c18b2541d06d15b5a7ae5627
    auth: 47a2273cf166923ebb47e5c938916b78045bd5b801a3249d0f94efbdcc2a5027
  sec:
    encr: a9a97e6082a8f7fcd90c0cd351eeb08f1a8a6b6478dd2ac2c9d92239c0a78347
    auth: 65cae92d293d7e573088643786464b674bccf0409eaba4b811f6341037488f8f47a2273cf166923ebb47e5c938916b78045bd5b801a3249d0f94efbdcc2a5027
nonce: 94ece1e40821737fc5ee4e8c86d59762e9cd238ec932ad20
`),
	`test-adm`: []byte(`
lat: 37.7833
lon: -122.4167
server:
- name: sf
  url: unix:///test-sf.sock
  lat: 37.7833
  lon: -122.4167
- name: sf.ws
  url: ws://localhost:6080/asn/test-sf.ws
  lat: 37.7833
  lon: -122.4167
- name: la
  url: unix:///test-la.sock
  lat: 34.05
  lon: -118.25
- name: la.tcp
  url: tcp://localhost:6022
  lat: 34.05
  lon: -118.25
- name: gcloud.ws
  url: ws://104.154.68.215:8080/asn/test.ws
  lat: 37.7833
  lon: -122.4167
keys: test-keys
`),
	`test-sf`: []byte(`
lat: 37.7833
lon: -122.4167
listen:
- unix:///test-sf.sock
- ws://:6080/asn/test-sf.ws
keys: test-keys
`),
	`test-la`: []byte(`
lat: 34.05
lon: -118.25
listen:
- unix:///test-la.sock
- tcp://:6022
keys: test-keys
`),
	`test-gcloud`: []byte(`
lat: 37.7833
lon: -122.4167
listen:
- ws://:8080/asn/test.ws
keys: test-keys
`),
}

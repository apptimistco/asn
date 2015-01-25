// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"io/ioutil"
	"path/filepath"
	"strconv"

	"gopkg.in/yaml.v1"
)

const (
	DefaultConfigFN = "asn.yaml"
	ExampleConfigs  = `
Server CONFIG Format:
  name: STRING
  dir: PATH
  lat: FLOAT
  lon: FLOAT
  listen:
  - unix:///PATH.sock
  - tcp://:PORT
  - ws://[HOST][:PORT]/PATH.ws
  keys:
    admin:
      pub:
        encr: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        auth: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    server:
      pub:
        encr: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        auth: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      sec:
        encr: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        auth: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    nonce: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

Admin CONFIG Format:
  name: STRING
  dir: PATH
  lat: FLOAT
  lon: FLOAT
  keys:
    admin:
      pub:
        encr: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        auth: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      sec:
        encr: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        auth: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    server:
      pub:
        encr: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        auth: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    nonce: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
  server:
  - name: local
    url: unix:///PATH.sock
  - name: sf
    url: ws://HOST[:PORT]/PATH.ws
    lat: 37.774929
    lon: -122.419415
  - name: la
    url: ws://HOST[:PORT]/PATH.ws
    lat: 34.052234
    lon: -118.243684
`
)

var SystemConfigFN = filepath.FromSlash("/etc/asn.yaml")

type Config struct {
	Name string
	// (e.g. "siren")
	Dir string
	// Local repository directory (e.g. /srv/asn/siren or siren.asn)
	Lat float64 `yaml:"lat,omitempty"`
	Lon float64 `yaml:"lon,omitempty"`
	// Latitude and Longitude of this server or administrator.
	Listen []*URL `yaml:"listen,omitempty"`
	// List of listening URLs.  All servers should listen to WebSockets
	// (e.g. ws://). Servers should also listen on a Unix socket file for
	// test and administration (e.g.unix:///). If available, also listen on
	// a TCP socket (e.g. tcp://) for mirror activity.
	// Assume admin mode if empty or not present.
	Server []struct {
		Name     string `yaml:"name,omitempty"`
		Url      *URL
		Lat, Lon float64
	} `yaml:"server,omitempty"`
	// In daemon mode this lists the other servers to replicate blobs.
	// In admin mode this lists the servers that may get/put blobs.
	Keys *Keys `yaml:"keys,omitempty"`
	// Usually generated with -new-keys then edited to remove the
	// unnecessary secrete keys.
}

func ReadConfigFile(fn string) (b []byte, err error) {
	b, err = ioutil.ReadFile(fn)
	if err != nil && fn == DefaultConfigFN {
		b, err = ioutil.ReadFile(SystemConfigFN)
	}
	return
}

// Bytes marshals the Config for output to a file.
func (c *Config) Bytes() []byte {
	buf, err := yaml.Marshal(c)
	if err != nil {
		return []byte(err.Error())
	}
	return buf
}

func (c *Config) Check(m Mode) (err error) {
	switch {
	case len(c.Name) == 0:
		err = &Error{"config", "no name"}
	case len(c.Dir) == 0:
		err = &Error{c.Name, "no repos"}
	case c.Keys == nil:
		err = &Error{c.Name, "no keys"}
	case c.Keys.Admin == nil:
		err = &Error{c.Name, "no admin keys"}
	case c.Keys.Admin.Pub == nil:
		err = &Error{c.Name, "no admin public keys"}
	case c.Keys.Admin.Pub.Encr == nil:
		err = &Error{c.Name, "no admin public encr key"}
	case c.Keys.Admin.Pub.Auth == nil:
		err = &Error{c.Name, "no admin public auth key"}
	case c.Keys.Server == nil:
		err = &Error{c.Name, "no server keys"}
	case c.Keys.Server.Pub == nil:
		err = &Error{c.Name, "no server public keys"}
	case c.Keys.Server.Pub.Encr == nil:
		err = &Error{c.Name, "no server public encr key"}
	case c.Keys.Server.Pub.Auth == nil:
		err = &Error{c.Name, "no server public auth key"}
	case m.Admin() && len(c.Server) == 0:
		err = &Error{c.Name, "no servers"}
	case m.Server() && len(c.Listen) == 0:
		err = &Error{c.Name, "no listeners"}
	}
	return
}

func (c *Config) Parse(b []byte) error { return yaml.Unmarshal(b, c) }

// retrieve Server Index of named, url or numbered server.
func (c *Config) SI(s string) (i int, err error) {
	if s == "" {
		return
	}
	if i, err = strconv.Atoi(s); err == nil {
		if i < 0 || i >= len(c.Server) {
			err = &Error{s, strconv.ErrRange.Error()}
		}
		return
	}
	for x, se := range c.Server {
		if s == se.Name || s == se.Url.String() {
			i, err = x, nil
			return
		}
	}
	err = &Error{s, "no such server"}
	return
}

// String marshals the Config.
func (c *Config) String() string {
	buf, err := yaml.Marshal(c)
	if err != nil {
		return err.Error()
	}
	return string(buf)
}
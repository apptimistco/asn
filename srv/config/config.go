// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package config provides configuration of an ASN Server through YAML files.
// See: testdata/
package config

import (
	"errors"
	"github.com/apptimistco/asn/keys"
	"github.com/apptimistco/url"
	"gopkg.in/yaml.v1"
	"io/ioutil"
)

const Inline = "__inline_file__"

// Config describes ASN services provided by the Server.
type Config struct {
	Name string
	// (e.g. "siren")
	Dir string
	// Local repository directory (e.g. /var/lib/asn/siren or siren.asn)
	Tmp string
	// Temporary Datum directory (e.g. /tmp, /var/tmp, /var/lib/asn/tmp)
	Lat, Lon float64
	// Latitude and Longitude.
	Log string
	// Log file name (e.g. /var/log/asn/siren); defaults to syslog
	Pid string
	// Process ID filename (e.g. /var/run/asn/siren.pid); default to none
	Keys *keys.Keys
	// See, github.com/apptimistco/asn/keys
	// Usually generated with asnkeys and edited to remove Admin Sec keys
	Listen []*url.URL `yaml:"listen,omitempty"`
	// List of listening URLs.  Front-end servers always listen to
	// WebSockets (e.g. ws://); whereas some back-end and mirror servers
	// may also use a TCP (e.g. tcp://). All servers should be configured
	// to also listen on a Unix socket file for test and administration
	// (e.g.unix:///).
	Mirror []*url.URL `yaml:"mirror,omitempty"`
	// For back-end servers, this lists the other servers on which it
	// should replicate transactions
	Server []struct {
		Name     string `yaml:"name,omitempty"`
		Url      *url.URL
		Lat, Lon float64
	} `yaml:"server,omitempty"`
	// For front-end servers, this lists the servers on which it should
	// get/put objects and references.
	//
	// With a 'unix://' schemed socket URL, the Server searches the working
	// directory before root ('/')
	adm bool
}

// New Config from named file or Inline prefaced string.
// The file name may or may not have the ".yaml" extension.
func New(s string) (c *Config, err error) {
	var buf []byte
	if ni, ns := len(Inline), len(s); ni < ns && s[:ni] == Inline {
		buf = []byte(s[ni:])
	} else if buf, err = ioutil.ReadFile(s + ".yaml"); err != nil {
		if buf, err = ioutil.ReadFile(s); err != nil {
			return
		}
	}
	c = &Config{}
	if err = yaml.Unmarshal(buf, c); err != nil {
		return
	}
	preface := "config " + c.Name + ": "
	switch {
	case len(c.Name) == 0:
		err = errors.New("config: no name")
	case len(c.Dir) == 0:
		err = errors.New(preface + "no repos")
	case c.Keys == nil:
		err = errors.New(preface + "no keys")
	case c.Keys.Admin == nil:
		err = errors.New(preface + "no admin keys")
	case c.Keys.Admin.Pub == nil:
		err = errors.New(preface + "no admin public keys")
	case c.Keys.Admin.Pub.Encr == nil:
		err = errors.New(preface + "no admin public encr key")
	case c.Keys.Admin.Pub.Auth == nil:
		err = errors.New(preface + "no admin public auth key")
	case c.Keys.Server == nil:
		err = errors.New(preface + "no server keys")
	case c.Keys.Server.Pub == nil:
		err = errors.New(preface + "no server public keys")
	case c.Keys.Server.Pub.Encr == nil:
		err = errors.New(preface + "no server public encr key")
	case c.Keys.Server.Pub.Auth == nil:
		err = errors.New(preface + "no server public auth key")
	case c.Keys.Server.Sec == nil:
		err = errors.New(preface + "no server secrete keys")
	case c.Keys.Server.Sec.Encr == nil:
		err = errors.New(preface + "no server secrete encr key")
	case c.Keys.Server.Sec.Auth == nil:
		err = errors.New(preface + "no server secrete auth key")
	case c.Keys.Nonce == nil:
		err = errors.New(preface + "no nonce")
	case len(c.Listen) == 0:
		err = errors.New(preface + "not listening")
	}
	if c != nil && err != nil {
		c.Clean()
	}
	return
}

// Clean empties the configuration.
func (c *Config) Clean() {
	c.Name, c.Dir = "", ""
	c.Lat, c.Lon = 0, 0
	c.Log, c.Pid = "", ""
	c.Keys.Clean()
	c.Keys = nil
	c.Listen = nil
	c.Mirror = nil
	c.Server = nil
}

func (c *Config) String() string {
	buf, err := yaml.Marshal(c)
	if err != nil {
		return err.Error()
	}
	return string(buf)
}

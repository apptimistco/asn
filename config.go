// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn

import (
	"errors"
	"gopkg.in/yaml.v1"
	"io/ioutil"
)

const Inline = "__inline_file__"

type Config struct {
	Name string
	// (e.g. "siren")
	Dir string
	// Local repository directory (e.g. /var/lib/asn/siren or siren.asn)
	Lat float64 `yaml:"lat,omitempty"`
	Lon float64 `yaml:"lon,omitempty"`
	// Latitude and Longitude of this server or administrator.
	Log string `yaml:"log,omitempty"`
	// Log file name (e.g. /var/log/asn/siren); defaults to syslog
	// Not used with asnadm.
	Pid string `yaml:"pid,omitempty"`
	// Process ID filename (e.g. /var/run/asn/siren.pid); default to none
	Keys *Keys
	// Usually generated with asnkeys and edited to remove Admin Sec keys
	Listen []*URL `yaml:"listen,omitempty"`
	// List of listening URLs.  All servers should listen to WebSockets
	// (e.g. ws://). Servers should also listen on a Unix socket file for
	// test and administration (e.g.unix:///). If available, also listen on
	// a TCP socket (e.g. tcp://) for mirror activity.
	// Not used with asnadm.
	Server []struct {
		Name     string `yaml:"name,omitempty"`
		Url      *URL
		Lat, Lon float64
	}
	// With asnsrv, this lists the other servers to replicate blobs.
	// With asnadm, this lists the servers that may get/put blobs.
	//
	// With a 'unix://' schemed socket URL, the Server searches the working
	// directory before root ('/')
}

// NewConfig from named file or Inline prefaced string.
// The file name may or may not have the ".yaml" extension.
func NewConfig(s string) (c *Config, err error) {
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
		/*
			case len(c.Server) == 0:
				err = errors.New(preface + "no servers")
		*/
	}
	if err != nil {
		c.Clean()
	}
	return
}

// Clean configuration fields for GC.
func (c *Config) Clean() {
	if c != nil {
		c.Name, c.Dir = "", ""
		c.Lat, c.Lon = 0, 0
		c.Log, c.Pid = "", ""
		c.Keys.Clean()
		c.Keys = nil
		c.Listen = nil
		c.Server = nil
	}
}

// String marshals Config.
func (c *Config) String() string {
	buf, err := yaml.Marshal(c)
	if err != nil {
		return err.Error()
	}
	return string(buf)
}

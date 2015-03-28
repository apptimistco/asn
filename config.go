// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v1"
)

var (
	SystemConfigFN = filepath.Join("etc", DefaultConfigFN)
	SystemReposDN  = filepath.Join("srv", AsnStr)
)

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
	Keys *ServiceKeys `yaml:"keys,omitempty"`
	// Usually generated with -new-keys then edited to remove the
	// unnecessary secrete keys.
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

func (c *Config) Parse(fn string) (err error) {
	var b []byte
	var def struct{ name, dir string }
	var ok bool
	if b, ok = Builtin[fn]; ok {
		def.name = fn
		def.dir = fn + ReposExt
	} else if fn == DefaultConfigFN {
		b, err = ioutil.ReadFile(DefaultConfigFN)
		def.name = AsnStr
		if err != nil {
			b, err = ioutil.ReadFile(SystemConfigFN)
			if err != nil {
				return
			}
			def.dir = SystemReposDN
		} else {
			def.dir = DefaultReposDN
		}
	} else if b, err = ioutil.ReadFile(fn); err == nil {
		def.name = strings.TrimSuffix(fn, ConfigExt)
		def.dir = def.name + ReposExt
	} else if b, err = ioutil.ReadFile(fn + ConfigExt); err == nil {
		def.name = fn
		def.dir = def.name + ReposExt
	} else {
		return
	}
	if err := yaml.Unmarshal(b, c); err != nil {
		return err
	}
	if c.Name == "" {
		c.Name = def.name
	}
	if c.Dir == "" {
		c.Dir = def.dir
	}
	return nil
}

// ServerURL returns indexed or named server; or parsed url.
func (c *Config) ServerURL(s string) (*URL, error) {
	if s == "" {
		return c.Server[0].Url, nil
	}
	if i, err := strconv.Atoi(s); err == nil {
		if i < 0 || i >= len(c.Server) {
			return nil, &Error{s, strconv.ErrRange.Error()}
		}
		return c.Server[i].Url, nil
	}
	for i, se := range c.Server {
		if s == se.Name || s == se.Url.String() {
			return c.Server[i].Url, nil
		}
	}
	return NewURL(s)
}

// String marshals the Config.
func (c *Config) String() string {
	buf, err := yaml.Marshal(c)
	if err != nil {
		return err.Error()
	}
	return string(buf)
}

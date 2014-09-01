// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package config provides configuration of an ASN Admin through YAML files.
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

// Config describes ASN Admin.
type Config struct {
	Name string
	// (e.g. "siren")
	Lat, Lon float64
	// Latitude and Longitude
	Keys   *keys.Keys
	Server []struct {
		Name     string `yaml:"name,omitempty"`
		Url      *url.URL
		Lat, Lon float64
	}
	// This lists the servers on which the admin may get/put objects and
	// references.
	//
	// With a 'unix://' schemed socket URL, the Admin searches the working
	// directory before root ('/')
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
	case c.Keys.Admin.Sec == nil:
		err = errors.New(preface + "no server admin keys")
	case c.Keys.Admin.Sec.Encr == nil:
		err = errors.New(preface + "no server admin encr key")
	case c.Keys.Admin.Sec.Auth == nil:
		err = errors.New(preface + "no server admin auth key")
	case c.Keys.Server == nil:
		err = errors.New(preface + "no server keys")
	case c.Keys.Server.Pub == nil:
		err = errors.New(preface + "no server public keys")
	case c.Keys.Server.Pub.Encr == nil:
		err = errors.New(preface + "no server public encr key")
	case c.Keys.Server.Pub.Auth == nil:
		err = errors.New(preface + "no server public auth key")
	case c.Keys.Nonce == nil:
		err = errors.New(preface + "no nonce")
	case len(c.Server) == 0:
		err = errors.New(preface + "no servers")
	}
	if err != nil {
		c.Clean()
	}
	return
}

// Clean empties the configuration.
func (c *Config) Clean() {
	c.Name = ""
	c.Lat, c.Lon = 0, 0
	c.Keys.Clean()
	c.Keys = nil
	c.Server = nil
}

func (c *Config) String() string {
	buf, err := yaml.Marshal(c)
	if err != nil {
		return err.Error()
	}
	return string(buf)
}

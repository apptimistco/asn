// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

const (
	AsnApprovals   = "asn/approvals"
	AsnAuth        = "asn/auth"
	AsnAuthor      = "asn/author"
	AsnBridge      = "asn/bridge"
	AsnEditors     = "asn/editors"
	AsnInvites     = "asn/invites"
	AsnMark        = "asn/mark"
	AsnMessages    = "asn/messages"
	AsnModerators  = "asn/moderators"
	AsnRemovals    = "asn/removals"
	AsnSubscribers = "asn/subscribers"
	AsnUser        = "asn/user"
	AsnVouchers    = "asn/vouchers"
)

var AsnPubEncrLists = []string{
	AsnEditors,
	AsnInvites,
	AsnModerators,
	AsnSubscribers,
}

type Cache map[string]*CacheEntry

func (c Cache) Auth() *PubAuth {
	return c.PubAuth(AsnAuth)
}

func (c Cache) Author() *PubEncr {
	return c.PubEncr(AsnAuthor)
}

func (c Cache) Editors() *PubEncrList {
	return c.PubEncrList(AsnEditors)
}

func (c Cache) Invites() *PubEncrList {
	return c.PubEncrList(AsnInvites)
}

func (c Cache) Load(dn string) error {
	for fn, e := range c {
		pn := filepath.Join(dn, fn)
		fi, err := os.Stat(pn)
		if err != nil {
			if os.IsNotExist(err) {
				err = nil
				continue
			} else {
				return err
			}
		}
		if fi.IsDir() {
			dir, err := ioutil.ReadDir(pn)
			if err != nil {
				return &Error{pn, err.Error()}
			}
			for _, fi := range dir {
				keystr := fi.Name()
				key, err := NewPubEncr(keystr)
				if err != nil {
					return err
				}
				c.PubEncrList(fn).KeyAdd(key)
			}
			e.Time = time.Now()
		} else {
			f, err := os.Open(pn)
			if err != nil {
				return err
			}
			var fh FH
			if _, err = fh.ReadFrom(f); err != nil {
				f.Close()
				return &Error{pn, err.Error()}
			}
			e.Time = fh.Blob.Time
			_, err = e.ReadFrom(f)
			f.Close()
			if err != nil {
				return &Error{pn, err.Error()}
			}
		}
	}
	return nil
}

func (c Cache) Mark() *Mark {
	return c[AsnMark].Cacher.(*Mark)
}

func (c Cache) Moderators() *PubEncrList {
	return c.PubEncrList(AsnModerators)
}

func (c Cache) PubAuth(kw string) *PubAuth {
	l, _ := c[kw].Cacher.(*PubAuth)
	return l
}

func (c Cache) PubEncr(kw string) *PubEncr {
	l, _ := c[kw].Cacher.(*PubEncr)
	return l
}

func (c Cache) PubEncrList(kw string) *PubEncrList {
	l, _ := c[kw].Cacher.(*PubEncrList)
	return l
}

func (c Cache) Reset() {
	for _, e := range c {
		e.Reset()
	}
}

func (c Cache) Subscribers() *PubEncrList {
	return c.PubEncrList(AsnSubscribers)
}

type CacheEntry struct {
	time.Time
	Cacher
}

func (e *CacheEntry) Reset() {
	e.Time = Time0
	e.Cacher.Reset()
}

func (e *CacheEntry) Set(v interface{}) error {
	if t, ok := v.(time.Time); ok {
		e.Time = t
		return nil
	}
	return e.Cacher.Set(v)
}

func (e *CacheEntry) String() string {
	return e.Cacher.String()
}
